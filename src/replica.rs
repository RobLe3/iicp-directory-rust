// SPDX-License-Identifier: Apache-2.0
//! Replica-side federation: consume the Genesis Seed's signed event log and mirror
//! its state (ADR-013 / S.13 / #385). This module is the orchestration layer —
//! signature verification (via [`crate::federation`]), `seq` monotonicity (DIR-FED-02),
//! and dispatch of each verified event to the local repository.
//!
//! State mutation reuses the existing `register()` / `deregister()` repo methods, so
//! REGISTER (incl. `capabilities[]` per #438) + DEREGISTER replicate into discover with
//! no new persistence surface. REPUTATION_DECAY + CREDIT_AWARD + REPLICA_REGISTERED all
//! apply (#441 — full state fidelity: reputation_score / credit_balance / replicas registry).

// The HTTP sync loop (DID resolve + snapshot + poll /v1/events) is the consumer of
// FederatedEvent/verify_and_apply; allow until it lands so the build stays clean.
#![allow(dead_code)]

use crate::federation;
use crate::repo::{NodeRecord, NodeRepository};
use crate::types::Node;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// Replica-mode configuration, from env. `None` when the directory runs as a normal
/// (seed/standalone) instance.
pub struct ReplicaConfig {
    /// Genesis Seed root URL (e.g. `http://seed-directory:8080`); endpoints are
    /// `{seed_url}/api/v1/events` and `{seed_url}/.well-known/did.json`.
    pub seed_url: String,
    pub poll_interval_secs: u64,
    /// This replica's DID (e.g. `did:web:replica.example`), from `IICP_REPLICA_DID`.
    /// Required for the join handshake (DIR-FED-13); if absent the handshake is skipped.
    pub replica_did: Option<String>,
    /// This replica's public HTTPS endpoint, from `IICP_REPLICA_ENDPOINT`.
    /// Sent to the seed during the join handshake so the seed can record this replica.
    pub replica_endpoint: Option<String>,
}

impl ReplicaConfig {
    /// Active when `IICP_REPLICA_MODE` is `true`/`1` and `IICP_SEED_URL` is set.
    pub fn from_env() -> Option<Self> {
        let mode = std::env::var("IICP_REPLICA_MODE").ok()?;
        if mode != "true" && mode != "1" {
            return None;
        }
        let seed_url = std::env::var("IICP_SEED_URL").ok()?;
        let poll_interval_secs = std::env::var("IICP_REPLICA_POLL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        let replica_did = std::env::var("IICP_REPLICA_DID").ok();
        let replica_endpoint = std::env::var("IICP_REPLICA_ENDPOINT").ok();
        Some(ReplicaConfig {
            seed_url: seed_url.trim_end_matches('/').to_string(),
            poll_interval_secs,
            replica_did,
            replica_endpoint,
        })
    }
}

/// Resolve the seed's Ed25519 pubkey (hex) from its DID document — `None` if the seed
/// hasn't set its genesis key (unsigned network → events applied without sig check).
async fn resolve_seed_pubkey(client: &reqwest::Client, seed_url: &str) -> Option<String> {
    let url = format!("{seed_url}/.well-known/did.json");
    let did: Value = client.get(&url).send().await.ok()?.json().await.ok()?;
    seed_pubkey_hex_from_did(&did)
}

/// Fetch one page of the seed's event log: `GET /api/v1/events?since_seq=N` (public).
/// Returns (events, next_seq, has_more).
///
/// Path note: the PHP directory mounts the federation event log under the `/api/v1`
/// prefix (`routes/api_public.php` `require`d into `routes/api.php`), and production
/// `iicp.network` serves it at `/api/v1/events` too. There is no bare `/v1/events`
/// route — an earlier draft polled `/v1/events` and silently 404'd every tick.
async fn fetch_events(
    client: &reqwest::Client,
    seed_url: &str,
    since_seq: i64,
) -> Option<(Vec<FederatedEvent>, i64, bool)> {
    let url = events_url(seed_url, since_seq);
    let body: Value = client.get(&url).send().await.ok()?.json().await.ok()?;
    let events: Vec<FederatedEvent> = serde_json::from_value(body.get("events")?.clone()).ok()?;
    let next_seq = body
        .get("next_seq")
        .and_then(Value::as_i64)
        .unwrap_or(since_seq);
    let has_more = body
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some((events, next_seq, has_more))
}

/// Build the seed event-log poll URL. Extracted so the `/api/v1` prefix is unit-tested
/// (an earlier draft used a bare `/v1/events` that 404'd against both the PHP testbed
/// seed and production — the kind of silent path drift a string test catches).
fn events_url(seed_url: &str, since_seq: i64) -> String {
    format!("{seed_url}/api/v1/events?since_seq={since_seq}")
}

/// Build the snapshot bootstrap URL (`GET /api/v1/snapshot`).
/// Both PHP and Rust seeds mount this under `/api/v1`; the bare `/v1/snapshot` alias
/// exists on the Rust seed but not on the PHP testbed — always use the /api/v1 form.
fn snapshot_url(seed_url: &str) -> String {
    format!("{seed_url}/api/v1/snapshot")
}

/// Build the join-handshake URL (`POST /api/v1/replicas/register`).
fn handshake_url(seed_url: &str) -> String {
    format!("{seed_url}/api/v1/replicas/register")
}

/// Snapshot bootstrap (DIR-FED-13 §5.3): fetch the seed's current-state snapshot, apply
/// it to local state, and return `snapshot_seq` so the poll loop tails from there.
/// Returns `None` on any fetch/parse failure (replica falls back to tailing from seq=0).
async fn fetch_and_apply_snapshot(
    client: &reqwest::Client,
    seed_url: &str,
    repo: &dyn NodeRepository,
) -> Option<i64> {
    let url = snapshot_url(seed_url);
    let snapshot: Value = client.get(&url).send().await.ok()?.json().await.ok()?;
    let snapshot_seq = snapshot_seq_from(&snapshot);
    let applied = apply_snapshot(repo, &snapshot).await;
    eprintln!("[replica] snapshot applied: {applied} node(s) → since_seq={snapshot_seq}");
    Some(snapshot_seq)
}

/// Extract `snapshot_seq` from a snapshot response (falls back to 0 if missing).
/// Pure helper so the seq-extraction logic can be unit-tested independently of HTTP.
fn snapshot_seq_from(snapshot: &Value) -> i64 {
    snapshot
        .get("snapshot_seq")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// Join handshake (DIR-FED-13 §7): announce this replica to the seed with our DID +
/// endpoint. The seed records us in its replica registry and emits a REPLICA_REGISTERED
/// event so other replicas know about us. Returns the handshake `since_seq` on success
/// (`None` on any network/parse failure — skipping the handshake is non-fatal; the replica
/// still tails events, just without appearing in the seed's replica list).
async fn join_handshake(
    client: &reqwest::Client,
    seed_url: &str,
    did: &str,
    endpoint: &str,
) -> Option<i64> {
    let url = handshake_url(seed_url);
    let resp: Value = client
        .post(&url)
        .json(&serde_json::json!({ "did": did, "endpoint": endpoint }))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let since = resp.get("since_seq").and_then(Value::as_i64).unwrap_or(0);
    let rid = resp
        .get("replica_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    eprintln!("[replica] handshake ok: replica_id={rid} since_seq={since}");
    Some(since)
}

/// Replica sync loop (DIR-FED-01/02/13): resolve the seed's signing key, perform the
/// join handshake + snapshot bootstrap (#440), then poll the event log forever — verifying
/// + applying each new event to mirror the seed's state. The join handshake (§7) announces
/// this replica to the seed; the snapshot bootstrap (§5.3) primes local state and advances
/// `since_seq` so we only tail events newer than the snapshot.
pub async fn run_replica_sync(repo: Arc<dyn NodeRepository>, cfg: ReplicaConfig) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let pubkey = resolve_seed_pubkey(&client, &cfg.seed_url).await;
    eprintln!(
        "[replica] sync start: seed={} signing-key={}",
        cfg.seed_url,
        if pubkey.is_some() {
            "resolved (verifying)"
        } else {
            "pending (unsigned mode)"
        }
    );

    // JOIN HANDSHAKE (DIR-FED-13 §7): announce this replica to the seed.
    // Requires IICP_REPLICA_DID + IICP_REPLICA_ENDPOINT; skipped (non-fatal) if absent.
    if let (Some(did), Some(endpoint)) = (&cfg.replica_did, &cfg.replica_endpoint) {
        join_handshake(&client, &cfg.seed_url, did, endpoint).await;
    }

    // SNAPSHOT BOOTSTRAP (§5.3): fetch the seed's state snapshot, apply it, and
    // advance `since_seq` to `snapshot_seq` so the poll loop only tails new events.
    let mut since_seq: i64 = fetch_and_apply_snapshot(&client, &cfg.seed_url, repo.as_ref())
        .await
        .unwrap_or(0);

    let mut interval = tokio::time::interval(Duration::from_secs(cfg.poll_interval_secs));
    loop {
        interval.tick().await;
        // Drain the backlog (paginate until caught up), then idle until the next tick.
        // `prev_sig` tracks the signature of the last event we verified, so each next
        // event's prev_hash can be checked for hash-chain continuity (#458). It is unknown
        // at the start of a drain (we persist only `since_seq`), so the first event of a
        // cycle skips the continuity check; its own signature is still verified.
        let mut prev_sig: Option<String> = None;
        loop {
            let Some((events, _next_seq, has_more)) =
                fetch_events(&client, &cfg.seed_url, since_seq).await
            else {
                eprintln!("[replica] events fetch failed (seq={since_seq}); retry next tick");
                break;
            };
            if events.is_empty() {
                break;
            }
            let mut applied = 0u32;
            for ev in &events {
                let expected_prev = prev_sig
                    .as_deref()
                    .map(|s| federation::prev_hash_from(Some(s)));
                let (outcome, hw) = verify_and_apply(
                    repo.as_ref(),
                    ev,
                    pubkey.as_deref(),
                    since_seq,
                    expected_prev.as_deref(),
                )
                .await;
                if hw > since_seq {
                    since_seq = hw;
                }
                if outcome == ApplyOutcome::Applied {
                    applied += 1;
                    prev_sig = ev.sig.clone();
                }
            }
            if applied > 0 {
                eprintln!("[replica] applied {applied} event(s) → seq={since_seq}");
            }
            if !has_more {
                break;
            }
        }
    }
}

/// One entry from the seed's `GET /v1/events` stream (and snapshot deltas).
#[derive(Debug, Clone, Deserialize)]
pub struct FederatedEvent {
    pub event_id: String,
    pub event_type: String,
    /// Optional, signed service-origin metadata. Unknown values remain opaque and MUST
    /// NOT be interpreted as authorization or routing instructions.
    #[serde(default)]
    pub service_id: Option<String>,
    pub seq: i64,
    pub ts_ms: i64,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub payload: Value,
    /// Hash-chain link to the predecessor (#458) — bound into the signing input. Null for
    /// legacy pre-migration events; verifiers seed continuity from GENESIS_ROOT.
    #[serde(default)]
    pub prev_hash: Option<String>,
    /// Hex Ed25519 detached signature (null until the seed sets its genesis key).
    #[serde(default)]
    pub sig: Option<String>,
    #[serde(default)]
    pub signer_did: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    /// Valid but no state change (e.g. unknown node, unhandled event type).
    Skipped,
    /// Refused — signature invalid, seq non-monotonic, or malformed. State unchanged.
    Rejected(&'static str),
}

/// Intents the node serves, from the REGISTER event's `capabilities[]` (#438).
fn intents_from_payload(payload: &Value) -> Vec<String> {
    payload
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|caps| {
            caps.iter()
                .filter_map(|c| c.get("intent").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Build a replicated `Node` from a REGISTER event payload. Fields the event carries
/// are taken from it; the rest get federation-sensible defaults (score 0.5 so the node
/// is discoverable; reputation refines via later REPUTATION events).
fn node_from_register(node_id: &str, payload: &Value) -> Option<Node> {
    let endpoint = payload.get("endpoint").and_then(Value::as_str)?.to_string();
    let region = payload
        .get("region")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let cip_conformance_level = payload
        .get("cip_conformance_level")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| Some("CIP-None".to_string()));
    let credit_cost_multiplier = payload
        .get("pricing")
        .and_then(|p| p.get("credit_cost_multiplier"))
        .and_then(Value::as_f64)
        .unwrap_or(1.0);
    let pricing_model = payload
        .get("pricing")
        .and_then(|p| p.get("pricing_model"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| Some("per_token".to_string()));
    let models: Vec<String> = payload
        .get("capabilities")
        .and_then(Value::as_array)
        .map(|caps| {
            caps.iter()
                .filter_map(|c| c.get("models").and_then(Value::as_array))
                .flatten()
                .filter_map(|m| m.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // #439 — mirror reachability from the event so the replicated node carries the seed's
    // real exposure/reachability (was hardcoded). PHP discover filters on these; the Rust
    // discover filters on score, but the node detail + health scoring should still be faithful.
    let public_reachable = payload
        .get("public_reachable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let exposure_mode = payload
        .get("exposure_mode")
        .and_then(Value::as_str)
        .map(str::to_string);
    // Relay-reachable exposure set — parity with PHP NodeScorer::RELAY_REACHABLE_EXPOSURE_MODES.
    const RELAY_REACHABLE: &[&str] = &[
        "ipv4_public_direct",
        "ipv6_direct_pinhole_available",
        "ipv6_direct_firewall_required",
        "ipv4_cgnat_blocked",
        "relay_required",
        "tunnel_required",
        "dual_stack_available",
        "outbound_only",
    ];
    let reachability_signal = if public_reachable {
        1.0
    } else if exposure_mode
        .as_deref()
        .is_some_and(|m| RELAY_REACHABLE.contains(&m))
    {
        0.5
    } else {
        0.0
    };

    Some(Node {
        node_id: node_id.to_string(),
        endpoint,
        region,
        score: 0.5,
        available: true,
        load: 0.0,
        active_jobs: 0,
        max_concurrent: 4,
        reputation_score: 0.5,
        latency_estimate_ms: None,
        completed_tasks_count: 0,
        tasks_failed: 0,
        health_label: None,
        exposure_mode,
        reputation_tier: None,
        transport_endpoint: None,
        cip_conformance_level,
        models,
        pricing: payload.get("pricing").cloned(),
        nat_type: None,
        transport_method: None,
        relay_capable: None,
        sdk_language: None,
        sdk_version: None,
        consumer_cosignature_ready: payload
            .get("supported_receipt_profiles")
            .and_then(Value::as_array)
            .is_some_and(|profiles| {
                profiles
                    .iter()
                    .any(|p| p.as_str() == Some("consumer_cosignature_v1"))
            }),
        backend: payload
            .get("backend")
            .and_then(Value::as_str)
            .map(str::to_string),
        address_family: None,
        cip_policy: payload.get("cip_policy").cloned(),
        public_key: None,
        transport_metadata: None,
        quantization: vec![],
        inference_engine: vec![],
        credit_cost_multiplier,
        pricing_model,
        attested: payload
            .get("pricing")
            .and_then(|p| p.get("attested"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        transport: vec![],
        reachability_signal,
        // ADR-045 Phase A (#407) — operator binding rides on REGISTER event payload in a
        // later phase; replica reconstruction leaves it unverified until then.
        operator_pubkey: None,
        operator_display_name: None,
        operator_fingerprint: None,
        operator_verified: false,
        operator_trust_tier: None,
        // WQ-058 — public-listing opt-in rides on the REGISTER event payload in a later phase;
        // replica reconstruction defaults to not-listed until then.
        public_listing: false,
        operator_url: None,
        policy_manifest: payload.get("policy_manifest").cloned(),
        health_models: None, // #494 — populated by heartbeat events, not REGISTER
        routing_policy: crate::types::RoutingPolicyState::default(),
    })
}

/// Apply a single (already verified) event to local state. Pure state mutation —
/// callers do signature + seq checks first (see [`verify_and_apply`]).
pub async fn apply_event(repo: &dyn NodeRepository, ev: &FederatedEvent) -> ApplyOutcome {
    match ev.event_type.as_str() {
        "REGISTER" => apply_register(repo, ev).await,
        "DEREGISTER" => match ev.node_id.as_deref() {
            Some(id) if repo.deregister(id).await => ApplyOutcome::Applied,
            Some(_) => ApplyOutcome::Skipped, // unknown node
            None => ApplyOutcome::Rejected("DEREGISTER missing node_id"),
        },
        "HEALTH" => apply_health(repo, ev).await,
        "REPUTATION_DECAY" => apply_reputation_decay(repo, ev).await,
        "CREDIT_AWARD" => apply_credit_award(repo, ev).await,
        "REPLICA_REGISTERED" => apply_replica_registered(repo, ev).await,
        // Uptime tracking (#508): replicas self-maintain liveness via their own
        // expire_stale() loop, so EVICT/REACTIVATE don't mutate replica state.
        // Acknowledged (not unknown) to avoid noisy "unsupported event_type" logs.
        "EVICT" | "REACTIVATE" => ApplyOutcome::Skipped,
        _ => ApplyOutcome::Skipped,
    }
}

/// REGISTER → mirror the node row (+ capabilities, #438) into local discover.
async fn apply_register(repo: &dyn NodeRepository, ev: &FederatedEvent) -> ApplyOutcome {
    let Some(node_id) = ev.node_id.as_deref() else {
        return ApplyOutcome::Rejected("REGISTER missing node_id");
    };
    let Some(node) = node_from_register(node_id, &ev.payload) else {
        return ApplyOutcome::Rejected("REGISTER missing endpoint");
    };
    match repo
        .register(NodeRecord {
            node,
            intents: intents_from_payload(&ev.payload),
            availability: vec![],
            node_token: None, // replica never issues tokens; writes 307 to seed
            node_hmac_key: None,
            proxy_token: None,
        })
        .await
    {
        Ok(()) => ApplyOutcome::Applied,
        Err(_) => ApplyOutcome::Rejected("REGISTER persistence failed"),
    }
}

/// HEALTH (ADR-048 / #374) — store the per-(node, evaluator) snapshot so the
/// federation-wide mesh_health read can resolve each node by majority-vote across
/// evaluators. Record-only (never mutates the Node row); monotonic staleness is enforced
/// in the repo. Mirrors PHP ReplicaEventApplier::applyHealth.
async fn apply_health(repo: &dyn NodeRepository, ev: &FederatedEvent) -> ApplyOutcome {
    let Some(node_id) = ev.node_id.as_deref() else {
        return ApplyOutcome::Rejected("HEALTH missing node_id");
    };
    let p = &ev.payload;
    let Some(evaluator) = p.get("evaluator_did").and_then(Value::as_str) else {
        return ApplyOutcome::Rejected("HEALTH missing evaluator_did");
    };
    let Some(score) = p.get("score").and_then(Value::as_f64) else {
        return ApplyOutcome::Rejected("HEALTH missing score");
    };
    let evaluated_at_ms = health_evaluated_at_ms(p);
    // A stale replay (older than the stored snapshot) returns false → Skipped.
    if repo
        .upsert_health_observation(node_id, evaluator, score, evaluated_at_ms)
        .await
    {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::Skipped
    }
}

/// REPUTATION_DECAY (#441) — set the node's reputation_score (mirrors PHP applyReputationDecay).
async fn apply_reputation_decay(repo: &dyn NodeRepository, ev: &FederatedEvent) -> ApplyOutcome {
    let Some(node_id) = ev.node_id.as_deref() else {
        return ApplyOutcome::Rejected("REPUTATION_DECAY missing node_id");
    };
    let Some(score) = ev.payload.get("new_score").and_then(Value::as_f64) else {
        return ApplyOutcome::Rejected("REPUTATION_DECAY missing new_score");
    };
    if repo.set_reputation_score(node_id, score).await {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::Skipped // unknown node
    }
}

/// CREDIT_AWARD (#441) — set the node's credit_balance (mirrors PHP applyCreditAward).
async fn apply_credit_award(repo: &dyn NodeRepository, ev: &FederatedEvent) -> ApplyOutcome {
    let Some(node_id) = ev.node_id.as_deref() else {
        return ApplyOutcome::Rejected("CREDIT_AWARD missing node_id");
    };
    let Some(balance) = ev.payload.get("new_balance").and_then(Value::as_f64) else {
        return ApplyOutcome::Rejected("CREDIT_AWARD missing new_balance");
    };
    if repo.set_credit_balance(node_id, balance).await {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::Skipped // unknown node
    }
}

/// REPLICA_REGISTERED (#441) — record the trusted replica, upsert by DID; the event's
/// node_id carries replica_id. Mirrors PHP applyReplicaRegistered.
async fn apply_replica_registered(repo: &dyn NodeRepository, ev: &FederatedEvent) -> ApplyOutcome {
    let replica_id = ev.node_id.as_deref();
    let did = ev.payload.get("did").and_then(Value::as_str);
    let endpoint = ev.payload.get("endpoint").and_then(Value::as_str);
    let (Some(replica_id), Some(did), Some(endpoint)) = (replica_id, did, endpoint) else {
        return ApplyOutcome::Rejected("REPLICA_REGISTERED missing replica_id/did/endpoint");
    };
    let trust_tier = ev
        .payload
        .get("trust_tier")
        .and_then(Value::as_str)
        .unwrap_or("unverified");
    if repo
        .upsert_replica(replica_id, did, endpoint, trust_tier)
        .await
    {
        ApplyOutcome::Applied
    } else {
        ApplyOutcome::Skipped
    }
}

/// Normalize a HEALTH payload's evaluation time to unix ms. Prefers explicit
/// `evaluated_at_ms` (monotonic, no parse); falls back to an ISO-8601 `evaluated_at`
/// string (the ADR-044 forNode vector shape); else 0 (treated as oldest). Mirrors PHP
/// `ReplicaEventApplier::healthEvaluatedAtMs`.
fn health_evaluated_at_ms(payload: &Value) -> i64 {
    if let Some(ms) = payload.get("evaluated_at_ms").and_then(Value::as_i64) {
        return ms;
    }
    if let Some(iso) = payload.get("evaluated_at").and_then(Value::as_str) {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(iso) {
            return dt.timestamp_millis();
        }
    }
    0
}

/// Verify (DIR-FED-01) + enforce seq monotonicity (DIR-FED-02), then apply.
/// `seed_pubkey_hex` is the Genesis Seed's Ed25519 key from its DID document; when
/// `None`, signature checking is skipped (only safe on a trusted/dev network — the
/// seed currently emits unsigned events). Returns the outcome and the new high-water seq.
pub async fn verify_and_apply(
    repo: &dyn NodeRepository,
    ev: &FederatedEvent,
    seed_pubkey_hex: Option<&str>,
    last_applied_seq: i64,
    expected_prev_hash: Option<&str>,
) -> (ApplyOutcome, i64) {
    if ev
        .service_id
        .as_deref()
        .is_some_and(|service_id| !federation::valid_service_id(service_id))
    {
        return (
            ApplyOutcome::Rejected("invalid service_id"),
            last_applied_seq,
        );
    }
    // DIR-FED-02: reject non-monotonic / replayed seq (idempotency at the seq level).
    if ev.seq <= last_applied_seq {
        return (ApplyOutcome::Skipped, last_applied_seq);
    }
    // DIR-FED-01: verify the seed's signature before applying any state.
    if let Some(pk) = seed_pubkey_hex {
        let Some(sig) = ev.sig.as_deref() else {
            return (
                ApplyOutcome::Rejected("missing signature"),
                last_applied_seq,
            );
        };
        let prev_hash = ev.prev_hash.as_deref().unwrap_or(federation::GENESIS_ROOT);
        // #458: enforce hash-chain continuity against the predecessor we just applied —
        // a deleted/inserted/reordered event breaks this link even if its own sig is valid.
        if let Some(expected) = expected_prev_hash {
            if prev_hash != expected {
                return (
                    ApplyOutcome::Rejected("broken hash-chain"),
                    last_applied_seq,
                );
            }
        }
        let msg = match ev.service_id.as_deref() {
            Some(service_id) => match federation::event_message_with_service_id(
                service_id,
                &ev.event_id,
                &ev.event_type,
                ev.seq,
                ev.ts_ms,
                &ev.payload,
                prev_hash,
            ) {
                Some(message) => message,
                None => {
                    return (
                        ApplyOutcome::Rejected("invalid service_id"),
                        last_applied_seq,
                    )
                }
            },
            None => federation::event_message(
                &ev.event_id,
                &ev.event_type,
                ev.seq,
                ev.ts_ms,
                &ev.payload,
                prev_hash,
            ),
        };
        if !federation::verify_event(pk, sig, &msg) {
            return (ApplyOutcome::Rejected("bad signature"), last_applied_seq);
        }
    }
    let outcome = apply_event(repo, ev).await;
    // Advance the high-water mark only when the event was accepted (applied/skipped),
    // never on rejection.
    (outcome, ev.seq)
}

/// Extract the Genesis Seed's Ed25519 public key (hex) from its DID document
/// (`.well-known/did.json`, DIR-FED-03): the first `verificationMethod` whose
/// `publicKeyJwk` is `{kty:OKP, crv:Ed25519}`, base64url-decoding `x` to 32 raw bytes →
/// hex. Returns `None` if absent or a placeholder (prod's `"GENESIS_KEY_PENDING"`
/// decodes to the wrong length → unsigned network, no verification).
pub fn seed_pubkey_hex_from_did(did: &Value) -> Option<String> {
    use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
    let methods = did.get("verificationMethod")?.as_array()?;
    for m in methods {
        let Some(jwk) = m.get("publicKeyJwk") else {
            continue;
        };
        if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
            || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        {
            continue;
        }
        let Some(x) = jwk.get("x").and_then(Value::as_str) else {
            continue;
        };
        if let Ok(raw) = Base64UrlSafeNoPadding::decode_to_vec(x, None) {
            if raw.len() == 32 {
                return Some(hex::encode(raw));
            }
        }
    }
    None
}

/// Apply a `GET /v1/snapshot` body (S.13 §5.3/§5.5): register every node with its
/// capabilities' intents, mirroring the seed's full discoverable state. Returns the
/// number of nodes applied. This is the one-RTT bootstrap before tailing `/v1/events`.
pub async fn apply_snapshot(repo: &dyn NodeRepository, snapshot: &Value) -> usize {
    use std::collections::HashMap;
    // node_id → intents, from the capabilities[] array.
    let mut intents: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(caps) = snapshot.get("capabilities").and_then(Value::as_array) {
        for c in caps {
            if let (Some(nid), Some(intent)) = (
                c.get("node_id").and_then(Value::as_str),
                c.get("intent").and_then(Value::as_str),
            ) {
                intents
                    .entry(nid.to_string())
                    .or_default()
                    .push(intent.to_string());
            }
        }
    }
    let mut applied = 0;
    if let Some(nodes) = snapshot.get("nodes").and_then(Value::as_array) {
        for n in nodes {
            let Some(node_id) = n.get("node_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(mut node) = node_from_register(node_id, n) else {
                continue;
            };
            // Snapshot carries live availability + reputation from the seed.
            if let Some(av) = n.get("available").and_then(Value::as_bool) {
                node.available = av;
            }
            if let Some(rep) = n.get("reputation_score").and_then(Value::as_f64) {
                node.reputation_score = rep;
                node.score = rep;
            }
            applied += usize::from(
                repo.register(NodeRecord {
                    node,
                    intents: intents.get(node_id).cloned().unwrap_or_default(),
                    availability: vec![],
                    node_token: None,
                    node_hmac_key: None,
                    proxy_token: None,
                })
                .await
                .is_ok(),
            );
        }
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::{DiscoverQuery, InMemoryRepo};
    use serde_json::json;

    const CHAT: &str = "urn:iicp:intent:llm:chat:v1";

    // Regression guard for the federation event-log path. The PHP directory (testbed
    // seed AND production iicp.network) mounts the log under `/api/v1`; an earlier draft
    // polled a bare `/v1/events` and silently 404'd every tick, so a node registered on
    // the seed never propagated to the replica. This pins the prefix.
    #[test]
    fn events_url_uses_api_v1_prefix() {
        let url = events_url("http://seed-directory:8080", 7);
        assert_eq!(url, "http://seed-directory:8080/api/v1/events?since_seq=7");
        assert!(
            url.contains("/api/v1/events"),
            "must use the /api/v1 prefix: {url}"
        );
        // The bug was a bare `{seed}/v1/events` (no /api segment). Pin that it doesn't recur.
        assert!(
            !url.contains(":8080/v1/events"),
            "regressed to bare /v1/events: {url}"
        );
    }

    #[test]
    fn register_maps_reachability_from_payload() {
        // #439 — the mirrored node carries the seed's reachability so node detail/health
        // are faithful (public_reachable → 1.0, relay exposure → 0.5, else 0.0).
        let direct = node_from_register(
            "n1",
            &json!({"endpoint": "https://n1.test", "region": "eu",
                    "public_reachable": true, "exposure_mode": "ipv4_public_direct"}),
        )
        .unwrap();
        assert_eq!(direct.reachability_signal, 1.0);
        assert_eq!(direct.exposure_mode.as_deref(), Some("ipv4_public_direct"));

        let relay = node_from_register(
            "n2",
            &json!({"endpoint": "https://n2.test", "region": "eu",
                    "public_reachable": false, "exposure_mode": "relay_required"}),
        )
        .unwrap();
        assert_eq!(relay.reachability_signal, 0.5);

        let dark = node_from_register(
            "n3",
            &json!({"endpoint": "https://n3.test", "region": "eu", "public_reachable": false}),
        )
        .unwrap();
        assert_eq!(dark.reachability_signal, 0.0);
        assert_eq!(dark.exposure_mode, None);
    }

    fn register_event(node_id: &str, seq: i64) -> FederatedEvent {
        FederatedEvent {
            event_id: format!("evt-{node_id}-{seq}"),
            event_type: "REGISTER".into(),
            service_id: None,
            seq,
            ts_ms: 1_779_200_000_000,
            node_id: Some(node_id.into()),
            payload: json!({
                "endpoint": format!("https://{node_id}.test"),
                "region": "eu-central",
                "backend": "meshllm",
                "capabilities": [
                    {"intent": CHAT, "models": ["llama-3-8b"], "max_tokens": 4096, "input_modalities": ["text"]}
                ]
            }),
            prev_hash: None,
            sig: None,
            signer_did: Some("did:web:iicp.network".into()),
        }
    }

    async fn discoverable(repo: &InMemoryRepo, intent: &str) -> Vec<String> {
        repo.discover(&DiscoverQuery {
            intent: intent.into(),
            limit: 0,
            ..Default::default()
        })
        .await
        .into_iter()
        .map(|n| n.node_id)
        .collect()
    }

    #[tokio::test]
    async fn register_event_makes_node_discoverable() {
        let repo = InMemoryRepo::new(vec![]);
        let ev = register_event("n1", 1);
        assert_eq!(apply_event(&repo, &ev).await, ApplyOutcome::Applied);
        assert_eq!(discoverable(&repo, CHAT).await, vec!["n1".to_string()]);
        assert_eq!(
            repo.get("n1").await.unwrap().backend.as_deref(),
            Some("meshllm")
        );
    }

    #[tokio::test]
    async fn deregister_event_removes_node_from_discover() {
        let repo = InMemoryRepo::new(vec![]);
        apply_event(&repo, &register_event("n2", 1)).await;
        let dereg = FederatedEvent {
            event_id: "d1".into(),
            event_type: "DEREGISTER".into(),
            service_id: None,
            seq: 2,
            ts_ms: 1,
            node_id: Some("n2".into()),
            payload: json!({}),
            prev_hash: None,
            sig: None,
            signer_did: None,
        };
        assert_eq!(apply_event(&repo, &dereg).await, ApplyOutcome::Applied);
        assert!(discoverable(&repo, CHAT).await.is_empty());
    }

    #[tokio::test]
    async fn non_monotonic_seq_is_skipped() {
        let repo = InMemoryRepo::new(vec![]);
        // last_applied_seq=5; an event at seq 5 or below is a replay → skipped, no apply.
        let ev = register_event("n3", 5);
        let (outcome, hw) = verify_and_apply(&repo, &ev, None, 5, None).await;
        assert_eq!(outcome, ApplyOutcome::Skipped);
        assert_eq!(hw, 5);
        assert!(discoverable(&repo, CHAT).await.is_empty());
    }

    #[tokio::test]
    async fn bad_signature_is_rejected_and_seq_not_advanced() {
        let repo = InMemoryRepo::new(vec![]);
        let mut ev = register_event("n4", 10);
        ev.sig = Some("00".repeat(64)); // wrong sig
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let (outcome, hw) = verify_and_apply(&repo, &ev, Some(pubkey), 0, None).await;
        assert!(matches!(outcome, ApplyOutcome::Rejected(_)));
        assert_eq!(hw, 0, "rejected event must not advance the high-water seq");
        assert!(discoverable(&repo, CHAT).await.is_empty());
    }

    #[tokio::test]
    async fn signed_unknown_service_id_is_retained_but_not_authoritative() {
        let repo = InMemoryRepo::new(vec![]);
        let mut ev = register_event("service-node", 11);
        ev.service_id = Some("future-research-service".into());
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let secret = format!("{}{}", "11".repeat(32), pubkey);
        ev.sig = federation::sign_event_with_service_id(
            &secret,
            ev.service_id.as_deref().unwrap(),
            &ev.event_id,
            &ev.event_type,
            ev.seq,
            ev.ts_ms,
            &ev.payload,
            federation::GENESIS_ROOT,
        );

        let (outcome, high_water) = verify_and_apply(&repo, &ev, Some(pubkey), 0, None).await;
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert_eq!(high_water, 11);

        ev.service_id = Some("tampered-service".into());
        let (tampered, high_water) =
            verify_and_apply(&InMemoryRepo::new(vec![]), &ev, Some(pubkey), 0, None).await;
        assert_eq!(tampered, ApplyOutcome::Rejected("bad signature"));
        assert_eq!(high_water, 0);
    }

    #[tokio::test]
    async fn invalid_service_id_fails_closed() {
        let mut ev = register_event("service-node", 12);
        ev.service_id = Some("invalid:service".into());
        ev.sig = Some("00".repeat(64));
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let (outcome, high_water) =
            verify_and_apply(&InMemoryRepo::new(vec![]), &ev, Some(pubkey), 0, None).await;
        assert_eq!(outcome, ApplyOutcome::Rejected("invalid service_id"));
        assert_eq!(high_water, 0);
    }

    // ── ADR-048 (#374): HEALTH apply (parity with PHP HealthEventTest) ──

    fn health_event(node_id: &str, seq: i64, payload: Value) -> FederatedEvent {
        FederatedEvent {
            event_id: format!("evt-h-{node_id}-{seq}"),
            event_type: "HEALTH".into(),
            service_id: None,
            seq,
            ts_ms: 1_779_200_000_000,
            node_id: Some(node_id.into()),
            payload,
            prev_hash: None,
            sig: None,
            signer_did: Some("did:web:iicp.network".into()),
        }
    }

    #[tokio::test]
    async fn health_event_stores_per_evaluator_snapshot() {
        let repo = InMemoryRepo::new(vec![]);
        let ev = health_event(
            "node-a",
            1,
            json!({"score": 0.82, "evaluator_did": "did:web:seed", "evaluated_at_ms": 1_700_000_000_000i64}),
        );
        assert_eq!(apply_event(&repo, &ev).await, ApplyOutcome::Applied);
        let obs = repo.all_health_observations().await;
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].0, "node-a");
        assert_eq!(obs[0].1, "did:web:seed");
        assert!((obs[0].2 - 0.82).abs() < 1e-6);
    }

    #[tokio::test]
    async fn health_event_missing_evaluator_is_rejected() {
        let repo = InMemoryRepo::new(vec![]);
        let ev = health_event("node-a", 1, json!({"score": 0.5, "evaluated_at_ms": 1i64}));
        assert!(matches!(
            apply_event(&repo, &ev).await,
            ApplyOutcome::Rejected(_)
        ));
    }

    #[tokio::test]
    async fn older_health_snapshot_does_not_overwrite_newer() {
        let repo = InMemoryRepo::new(vec![]);
        let newer = health_event(
            "node-a",
            1,
            json!({"score": 0.90, "evaluator_did": "did:web:seed", "evaluated_at_ms": 2000i64}),
        );
        let older = health_event(
            "node-a",
            2,
            json!({"score": 0.10, "evaluator_did": "did:web:seed", "evaluated_at_ms": 1000i64}),
        );
        assert_eq!(apply_event(&repo, &newer).await, ApplyOutcome::Applied);
        // Out-of-order replay of the older snapshot is a no-op → Skipped.
        assert_eq!(apply_event(&repo, &older).await, ApplyOutcome::Skipped);
        let obs = repo.all_health_observations().await;
        assert_eq!(obs.len(), 1);
        assert!((obs[0].2 - 0.90).abs() < 1e-6);
    }

    // ── #441: replica full-state fidelity (REPUTATION_DECAY / CREDIT_AWARD) ──

    fn typed_event(event_type: &str, node_id: &str, seq: i64, payload: Value) -> FederatedEvent {
        FederatedEvent {
            event_id: format!("evt-{event_type}-{node_id}-{seq}"),
            event_type: event_type.into(),
            service_id: None,
            seq,
            ts_ms: 1_779_200_000_000,
            node_id: Some(node_id.into()),
            payload,
            prev_hash: None,
            sig: None,
            signer_did: Some("did:web:iicp.network".into()),
        }
    }

    #[tokio::test]
    async fn reputation_decay_updates_score() {
        let repo = InMemoryRepo::new(vec![]);
        apply_event(&repo, &register_event("n1", 1)).await; // node must exist
        let ev = typed_event("REPUTATION_DECAY", "n1", 2, json!({"new_score": 0.42}));
        assert_eq!(apply_event(&repo, &ev).await, ApplyOutcome::Applied);
        assert!((repo.get("n1").await.unwrap().reputation_score - 0.42).abs() < 1e-9);
    }

    #[tokio::test]
    async fn reputation_decay_unknown_node_skipped_and_missing_score_rejected() {
        let repo = InMemoryRepo::new(vec![]);
        // unknown node → Skipped (no-op, not an error)
        assert_eq!(
            apply_event(
                &repo,
                &typed_event("REPUTATION_DECAY", "ghost", 1, json!({"new_score": 0.5}))
            )
            .await,
            ApplyOutcome::Skipped
        );
        // missing new_score → Rejected
        apply_event(&repo, &register_event("n1", 2)).await;
        assert!(matches!(
            apply_event(&repo, &typed_event("REPUTATION_DECAY", "n1", 3, json!({}))).await,
            ApplyOutcome::Rejected(_)
        ));
    }

    #[tokio::test]
    async fn credit_award_applies_for_known_node() {
        let repo = InMemoryRepo::new(vec![]);
        apply_event(&repo, &register_event("n1", 1)).await;
        assert_eq!(
            apply_event(
                &repo,
                &typed_event("CREDIT_AWARD", "n1", 2, json!({"new_balance": 12.5}))
            )
            .await,
            ApplyOutcome::Applied
        );
        // unknown node → Skipped; missing new_balance → Rejected
        assert_eq!(
            apply_event(
                &repo,
                &typed_event("CREDIT_AWARD", "ghost", 3, json!({"new_balance": 1.0}))
            )
            .await,
            ApplyOutcome::Skipped
        );
        assert!(matches!(
            apply_event(&repo, &typed_event("CREDIT_AWARD", "n1", 4, json!({}))).await,
            ApplyOutcome::Rejected(_)
        ));
    }

    #[tokio::test]
    async fn replica_registered_records_and_upserts_by_did() {
        let repo = InMemoryRepo::new(vec![]);
        let ev = typed_event(
            "REPLICA_REGISTERED",
            "rep-uuid-1",
            1,
            json!({"did": "did:web:replica.example", "endpoint": "https://replica.example", "trust_tier": "low"}),
        );
        assert_eq!(apply_event(&repo, &ev).await, ApplyOutcome::Applied);
        let reps = repo.all_replicas().await;
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].1, "did:web:replica.example");
        assert_eq!(reps[0].2, "https://replica.example");

        // Re-register same DID with a new endpoint → upsert (no duplicate row).
        let ev2 = typed_event(
            "REPLICA_REGISTERED",
            "rep-uuid-1",
            2,
            json!({"did": "did:web:replica.example", "endpoint": "https://replica.example:8443"}),
        );
        assert_eq!(apply_event(&repo, &ev2).await, ApplyOutcome::Applied);
        let reps = repo.all_replicas().await;
        assert_eq!(reps.len(), 1, "same DID must upsert, not duplicate");
        assert_eq!(reps[0].2, "https://replica.example:8443");
        // default trust_tier when omitted
        assert_eq!(reps[0].3, "unverified");
    }

    #[tokio::test]
    async fn replica_registered_missing_did_or_endpoint_rejected() {
        let repo = InMemoryRepo::new(vec![]);
        assert!(matches!(
            apply_event(
                &repo,
                &typed_event(
                    "REPLICA_REGISTERED",
                    "rep-1",
                    1,
                    json!({"endpoint": "https://x"})
                )
            )
            .await,
            ApplyOutcome::Rejected(_)
        ));
        assert!(matches!(
            apply_event(
                &repo,
                &typed_event(
                    "REPLICA_REGISTERED",
                    "rep-1",
                    2,
                    json!({"did": "did:web:x"})
                )
            )
            .await,
            ApplyOutcome::Rejected(_)
        ));
    }

    #[test]
    fn extracts_ed25519_pubkey_from_did_doc() {
        // x = base64url(KAT pubkey 32 bytes); must decode back to the hex key (DIR-FED-03).
        let did = json!({
            "id": "did:web:iicp.network",
            "verificationMethod": [{
                "id": "did:web:iicp.network#key-1",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc"}
            }]
        });
        assert_eq!(
            seed_pubkey_hex_from_did(&did).as_deref(),
            Some("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")
        );
    }

    #[test]
    fn did_placeholder_key_yields_none() {
        // prod's unset key — decodes to the wrong length → None (unsigned network).
        let did = json!({"verificationMethod": [{"publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "GENESIS_KEY_PENDING"}}]});
        assert_eq!(seed_pubkey_hex_from_did(&did), None);
    }

    // ── #440: snapshot bootstrap + join handshake (FED-READY-3) ──────────────────

    #[test]
    fn snapshot_url_uses_api_v1_prefix() {
        // Both PHP and Rust seeds mount snapshots under /api/v1; the bare /v1/snapshot
        // only exists on the Rust seed — always use the /api/v1 form for PHP parity.
        let url = snapshot_url("http://seed:8080");
        assert_eq!(url, "http://seed:8080/api/v1/snapshot");
        assert!(
            !url.contains(":8080/v1/snapshot"),
            "regressed to bare /v1/snapshot: {url}"
        );
    }

    #[test]
    fn handshake_url_uses_api_v1_prefix() {
        let url = handshake_url("http://seed:8080");
        assert_eq!(url, "http://seed:8080/api/v1/replicas/register");
        assert!(
            !url.contains(":8080/v1/replicas"),
            "regressed to bare /v1/replicas: {url}"
        );
    }

    #[test]
    fn replica_config_reads_did_and_endpoint_from_env() {
        // The join handshake requires IICP_REPLICA_DID + IICP_REPLICA_ENDPOINT.
        // Pin that ReplicaConfig::from_env() reads both when present.
        std::env::set_var("IICP_REPLICA_MODE", "1");
        std::env::set_var("IICP_SEED_URL", "http://seed.test");
        std::env::set_var("IICP_REPLICA_DID", "did:web:replica.test");
        std::env::set_var("IICP_REPLICA_ENDPOINT", "https://replica.test");
        let cfg = ReplicaConfig::from_env().expect("config must parse");
        assert_eq!(cfg.replica_did.as_deref(), Some("did:web:replica.test"));
        assert_eq!(
            cfg.replica_endpoint.as_deref(),
            Some("https://replica.test")
        );
        std::env::remove_var("IICP_REPLICA_MODE");
        std::env::remove_var("IICP_SEED_URL");
        std::env::remove_var("IICP_REPLICA_DID");
        std::env::remove_var("IICP_REPLICA_ENDPOINT");
    }

    #[test]
    fn snapshot_seq_extraction_advances_cursor() {
        // The poll loop uses snapshot_seq_from() to advance since_seq past the snapshot.
        // Without this, it would start from 0 and re-apply every historical event.
        assert_eq!(snapshot_seq_from(&json!({"snapshot_seq": 42})), 42);
        assert_eq!(snapshot_seq_from(&json!({"snapshot_seq": 0})), 0);
        assert_eq!(snapshot_seq_from(&json!({})), 0, "missing key → 0 fallback");
    }

    #[tokio::test]
    async fn apply_snapshot_mirrors_nodes_into_discover() {
        let repo = InMemoryRepo::new(vec![]);
        let snapshot = json!({
            "snapshot_seq": 42,
            "nodes": [
                {"node_id": "s1", "endpoint": "https://s1.test", "region": "eu", "backend": "meshllm", "available": true, "reputation_score": 0.8},
                {"node_id": "s2", "endpoint": "https://s2.test", "region": "us", "available": false, "reputation_score": 0.7}
            ],
            "capabilities": [
                {"node_id": "s1", "intent": CHAT, "models": ["m"], "max_tokens": 1},
                {"node_id": "s2", "intent": CHAT, "models": ["m"], "max_tokens": 1}
            ]
        });
        assert_eq!(apply_snapshot(&repo, &snapshot).await, 2);
        // s1 available → discoverable; s2 unavailable → mirrored but not discoverable.
        assert_eq!(discoverable(&repo, CHAT).await, vec!["s1".to_string()]);
        assert_eq!(
            repo.get("s1").await.unwrap().backend.as_deref(),
            Some("meshllm")
        );
    }

    #[tokio::test]
    async fn unsigned_mode_applies_and_advances_seq() {
        // seed_pubkey=None (dev/unsigned network) → no sig check; monotonic seq applies.
        let repo = InMemoryRepo::new(vec![]);
        let (outcome, hw) = verify_and_apply(&repo, &register_event("n5", 7), None, 3, None).await;
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert_eq!(hw, 7);
        assert_eq!(discoverable(&repo, CHAT).await, vec!["n5".to_string()]);
    }
}

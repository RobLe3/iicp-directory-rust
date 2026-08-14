// SPDX-License-Identifier: Apache-2.0
//! IICP directory — Rust operator-preview implementation.
//!
//! This binary serves the shared directory contract, including registration,
//! discovery, operational, policy and federation-preview surfaces. PHP remains
//! the deployed Genesis authority until the documented parity, shadow-operation,
//! migration and rollback gates pass.

mod auth;
mod background;
mod behavior_contract;
mod cli;
mod config;
mod db;
mod delegation;
mod deployment_provenance;
mod directory_evidence;
mod discovery;
mod discovery_policy;
#[allow(dead_code)] // pure pre-normative matcher; no HTTP binding is authorized yet
mod effective_capability;
mod federation;
mod federation_handlers;
mod health;
#[cfg(test)]
mod jcs;
mod maintenance;
mod node_lifecycle;
mod observability;
mod operator;
mod peer_access;
mod policy;
mod policy_manifest;
mod probe;
mod public_surfaces;
mod recognition;
mod registration;
mod registration_store;
mod registry;
mod replica;
mod repo;
mod reputation;
mod router;
mod runtime;
mod schema;
mod service;
mod state;
mod token_issuance;
mod types;
mod updater;
mod validate;

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
#[cfg(test)]
use axum::extract::Request;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::{middleware, Json};
use clap::Parser;
use cli::Cli;
#[cfg(test)]
use cli::Command;
#[cfg(test)]
use config::DEFAULT_DIRECTORY_DID;
pub(crate) use directory_evidence::{
    compliance_attestation, deployment_record, did_document, directory_key, iicp_replicas,
    sign_domain_token, unix_now,
};
pub(crate) use discovery::{discover, dispatch_ticket_issue, node_detail, transport_methods};
#[cfg(test)]
pub(crate) use discovery::{
    profile_negotiation, DiscoverParams, DISPATCH_TICKET_AUDIENCE, PROFILE_FIXTURE_SHA256,
    SDK_BASELINE_VERSION,
};
pub(crate) use federation_handlers::{events, replicas_deregister, replicas_register, snapshot};
#[cfg(test)]
use observability::sdk_adoption_json;
pub(crate) use operator::{
    normalize_operator_display_name, operator_acceptance, operator_challenge,
    operator_display_name_for, operator_dsr_anonymize, operator_dsr_export, operator_dsr_restrict,
    operator_fingerprint_for, operator_key_revoke, operator_key_rotate, operator_rename,
    public_operator_fingerprint,
};
pub(crate) use peer_access::{me, peers};
pub(crate) use public_surfaces::{
    badge_svg, badges_list, conformance_submit, conformance_verify, metrics, root_info,
};
#[cfg(test)]
pub(crate) use repo::DiscoverQuery;
#[cfg(test)]
use repo::InMemoryRepo;
use repo::{AuditResult, ProbeResult, ProxyObservation};
use router::{app, replica_write_gate};
use serde::Deserialize;
use state::{new_register_rate, AppState};
pub(crate) use token_issuance::{consumer_token_issue, relay_ticket_issue};
pub(crate) use validate::validate_intent;
#[cfg(test)]
use validate::Env;

pub(crate) const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"), "-rs");
/// ADR-043 §9 exposure_mode vocabulary — enum parity with PHP RegisterController
/// validation (#401 / AL2). A register with any other value is rejected 422.
pub(crate) const EXPOSURE_MODES: [&str; 8] = [
    "outbound_only",
    "ipv4_public_direct",
    "ipv4_cgnat_blocked",
    "ipv6_direct_firewall_required",
    "ipv6_direct_pinhole_available",
    "relay_required",
    "tunnel_required",
    "dual_stack_available",
];

/// Emit + sign a federated event onto this directory's log if a signing key is configured
/// (#442). No-op when unsigned. Keeps the write-path handlers a single call (complexity-flat).
pub(crate) async fn emit_event(
    st: &AppState,
    event_type: &str,
    node_id: &str,
    payload: serde_json::Value,
) {
    if let Some(key) = st.signing_key.as_deref() {
        st.repo
            .append_signed_event(key, event_type, node_id, &payload)
            .await;
    }
}

// ── node lifecycle write handlers (iicp-dir §3.1/§3.2) ───────────────────────

pub(crate) use node_lifecycle::{heartbeat, leaderboard, register};
#[cfg(test)]
pub(crate) use node_lifecycle::{
    register_rate_step, valid_implementation_name, valid_version_axis, REGISTER_RATE_TTL_MS,
};

// ── credits (iicp-dir §6) ────────────────────────────────────────────

mod credits;
pub(crate) use credits::{credits_award, credits_balance, credits_summary, credits_transactions};
#[cfg(test)]
pub(crate) use credits::{verify_cip_receipt, CreditAwardRequest};

// ── audit-report (iicp-dir §7 / RT-05) ─────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct AuditReportRequest {
    node_id: String, // reporter (authenticated)
    target_node_id: String,
    finding: String, // must be in allowed set
}

/// `POST /v1/audit-report` (iicp-dir §7, RT-05 griefing cap).
/// Requires bearer auth. Applies -0.05 reputation delta to target (capped at 2
/// distinct reporters per target per 24h to prevent griefing).
async fn audit_report(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuditReportRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    const ALLOWED_FINDINGS: &[&str] = &["declaration_divergence", "liveness_failure"];

    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": { "code": "unauthorized", "message": "missing node_token" } }),
                ),
            )
        }
    };
    if !st.repo.verify_node_token(&req.node_id, &token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": { "code": "unauthorized", "message": "invalid node_token" } }),
            ),
        );
    }
    if req.node_id == req.target_node_id {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "validation_error", "message": "cannot report yourself" } }),
            ),
        );
    }
    if !ALLOWED_FINDINGS.contains(&req.finding.as_str()) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "validation_error", "message": "unknown finding type" } }),
            ),
        );
    }

    let AuditResult {
        applied, reason, ..
    } = st
        .repo
        .apply_audit_report(&req.target_node_id, &req.node_id, &req.finding)
        .await;

    // PHP returns 202 {accepted:true} always (when not rejected above).
    // Adapter checks for 202 (accepted) and 429 (rate-limited, reporter_cap_reached).
    // 404 when target not found — warns adapter without crashing.
    let status = match reason {
        "reporter_cap_reached" => StatusCode::TOO_MANY_REQUESTS,
        "target_not_found" => StatusCode::NOT_FOUND,
        _ => StatusCode::ACCEPTED, // 202 — accepted (applied or no-op)
    };
    (status, Json(serde_json::json!({ "accepted": applied })))
}

#[derive(Debug, Deserialize)]
struct DeregisterRequest {
    node_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct QuoteParams {
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    max_tokens: Option<u64>,
    #[serde(default)]
    min_reputation: Option<f64>,
}

/// Pure quote computation (WQ-057): derive the credit estimate from the candidate nodes'
/// `credit_cost_multiplier` list. `base_blocks = ceil(max_tokens / 1000)`; estimated uses the
/// average multiplier, min/max the cheapest/dearest. No candidates → base rate (×1.0), 0 nodes.
/// Extracted pure so the math is unit-tested in-process (PHP CreditsController::quote parity).
struct QuoteEstimate {
    estimated: f64,
    min: f64,
    max: f64,
    price_per_1000: f64,
    nodes_quoted: u32,
}

fn compute_quote(max_tokens: u64, multipliers: &[f64]) -> QuoteEstimate {
    let base_blocks = max_tokens.div_ceil(1000) as f64;
    let r4 = |x: f64| (x * 10000.0).round() / 10000.0;
    if multipliers.is_empty() {
        let c = r4(base_blocks);
        return QuoteEstimate {
            estimated: c,
            min: c,
            max: c,
            price_per_1000: 1.0,
            nodes_quoted: 0,
        };
    }
    let min_m = multipliers.iter().copied().fold(f64::INFINITY, f64::min);
    let max_m = multipliers
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max);
    let avg_m = multipliers.iter().sum::<f64>() / multipliers.len() as f64;
    QuoteEstimate {
        estimated: r4(base_blocks * avg_m),
        min: r4(base_blocks * min_m),
        max: r4(base_blocks * max_m),
        price_per_1000: r4(avg_m),
        nodes_quoted: multipliers.len() as u32,
    }
}

/// `GET /v1/credits/quote` (iicp-dir §6.4 / S.12 §2.1, PHP CreditsController::quote parity).
/// Node-token authenticated consumer pre-flight: estimates the credit cost for `max_tokens`
/// at `intent` across candidate nodes, and returns the consumer's balance +
/// `balance_sufficient` so the proxy can decide local-vs-remote before dispatch.
async fn credits_quote(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<QuoteParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Auth (mirror credits_summary): node_token bearer identifies the consumer.
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": { "code": "unauthorized", "message": "missing node_token" } }),
                ),
            )
        }
    };
    let node_id = match node_id_from_auth(&headers, &token) {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    serde_json::json!({ "error": { "code": "validation_error", "message": "X-Node-Id header required (or use JWT)" } }),
                ),
            )
        }
    };
    if !st.repo.verify_node_token(&node_id, &token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": { "code": "unauthorized", "message": "invalid node_token" } }),
            ),
        );
    }

    // §8.3: 422 if intent or max_tokens missing / max_tokens not positive.
    let intent = p.intent.as_deref().unwrap_or("");
    let max_tokens = p.max_tokens.unwrap_or(0);
    if intent.is_empty() || max_tokens == 0 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "validation_error", "message": "intent and max_tokens are required (max_tokens > 0)" } }),
            ),
        );
    }

    let min_rep = p.min_reputation.unwrap_or(0.0).clamp(0.0, 1.0);
    let multipliers = st.repo.quote_multipliers(intent, min_rep).await;
    let est = compute_quote(max_tokens, &multipliers);
    let effective =
        st.repo
            .effective_credit_balance(&node_id)
            .await
            .unwrap_or(repo::EffectiveCreditBalance {
                consumer_balance: 0.0,
                effective_balance: 0.0,
                balance_scope: "node",
                operator_wallet_balance: None,
            });
    let balance_sufficient = effective.effective_balance >= est.estimated;
    let quote_id = format!("q_{}", &uuid::Uuid::new_v4().to_string()[..12]);
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "quote_id": quote_id,
            "estimated_credits": est.estimated,
            "min_credits": est.min,
            "max_credits": est.max,
            "price_per_1000_tokens": est.price_per_1000,
            "nodes_quoted": est.nodes_quoted,
            "quote_expires_at": expires_at,
            "currency": "iicp_credits",
            // S.12 §2.1 pre-flight — proxy uses these to choose local vs remote.
            "consumer_balance": effective.consumer_balance,
            "effective_balance": effective.effective_balance,
            "balance_scope": effective.balance_scope,
            "operator_wallet_balance": effective.operator_wallet_balance,
            "balance_sufficient": balance_sufficient,
        })),
    )
}

// ── telemetry/probe (REACH integration) ──────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct TelemetryProbeRequest {
    probes: Vec<ProbeResult>,
    #[serde(default)]
    run_id: String,
}

/// `POST /v1/telemetry/probe` (ProbeTokenAuth — REACH daemon integration).
/// Verifies the probe token via SHA-256 hash lookup, bulk-inserts probe results.
async fn telemetry_probe(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<TelemetryProbeRequest>, JsonRejection>,
) -> (StatusCode, Json<serde_json::Value>) {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": { "code": "unauthorized", "message": "missing probe_token" } }),
                ),
            )
        }
    };

    let Json(req) = match request {
        Ok(request) => request,
        Err(_) => return reject("validation_error", "invalid telemetry probe request"),
    };

    // ProbeTokenAuth: SHA-256 hash the bearer token and look up in probe_tokens table.
    let token_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()));
    if !st.repo.verify_probe_token(&token_hash).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": { "code": "unauthorized", "message": "invalid probe_token" } }),
            ),
        );
    }

    if req.probes.is_empty() || req.probes.len() > 100 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "validation_error", "message": "probes must be 1–100 items" } }),
            ),
        );
    }

    // Stamp all probes with the request-level run_id if individual probes omit it.
    let mut stamped: Vec<ProbeResult> = req.probes;
    for p in &mut stamped {
        if p.run_id.is_empty() {
            p.run_id = req.run_id.clone();
        }
    }
    let stored = st.repo.record_probe_batch(&token_hash, &stamped).await;
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "ok": true, "stored": stored })),
    )
}

/// `POST /v1/telemetry` (ProxyTokenAuth — proxy latency/QoS report; iicp-telemetry §4).
/// Requires `Authorization: Bearer <proxy_token>`. Records the observation, applies the
/// EMA update to nodes.avg_latency_ms when Sybil quorum ≥3 (§4.3), and returns the
/// quorum count so the caller can observe the threshold.
async fn telemetry_proxy(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<ProxyObservation>, JsonRejection>,
) -> (StatusCode, Json<serde_json::Value>) {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": { "code": "unauthorized", "message": "missing proxy_token" } }),
                ),
            )
        }
    };
    let Json(obs) = match request {
        Ok(request) => request,
        Err(_) => return reject("validation_error", "invalid proxy telemetry request"),
    };
    if obs.proxy_node_id.is_empty() || obs.node_id.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "validation_error", "message": "node_id and proxy_node_id required" } }),
            ),
        );
    }
    if obs.node_id == obs.proxy_node_id {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "validation_error", "message": "proxy_node_id must differ from node_id (RT-03)" } }),
            ),
        );
    }
    if !st.repo.verify_proxy_token(&obs.proxy_node_id, &token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": { "code": "unauthorized", "message": "invalid proxy_token" } }),
            ),
        );
    }
    let (accepted, quorum) = st.repo.record_proxy_telemetry(&obs).await;
    if !accepted {
        // PHP returns 200 {accepted: false, reason: 'duplicate'} on duplicate (same bucket).
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "accepted": false, "reason": "duplicate" })),
        );
    }
    // PHP returns 202 {accepted: true} on success.
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "accepted": true,
            "proxy_quorum_count": quorum,   // extension: EMA quorum signal for callers
            "quorum_met": quorum >= 3
        })),
    )
}

/// Extract the real client IP from request headers (NodeAddressObserver parity with PHP).
/// Priority: CF-Connecting-IP (Cloudflare authoritative) → first token of X-Forwarded-For
/// (RFC 7239 §5.2 leftmost = original client) → X-Real-IP → "unknown".
pub(crate) fn get_client_ip(headers: &axum::http::HeaderMap) -> &str {
    if let Some(cf) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        let cf = cf.trim();
        if !cf.is_empty() {
            return cf;
        }
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let first = xff.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return first;
        }
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
}

pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Extract node_id from the request using JWT (preferred) or X-Node-Id header (interim).
/// JWT path: decode the bearer token as HS256 → extract `sub` as node_id.
/// Header path: read `X-Node-Id` header directly.
/// Returns None if neither is present or the JWT is invalid.
pub(crate) fn node_id_from_auth(headers: &axum::http::HeaderMap, token: &str) -> Option<String> {
    // Try JWT first — sub claim carries the node_id without a separate header.
    if let Some(node_id) = auth::verify_jwt(token) {
        return Some(node_id);
    }
    // Fallback: X-Node-Id header (Phase 4 interim, required when APP_KEY not set).
    headers
        .get("x-node-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

pub(crate) fn reject(code: &str, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    err_json(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

/// Canonical public-mesh policy refusal. The response deliberately includes only
/// taxonomy evidence, never submitted task content or the full identifier.
pub(crate) fn policy_reject(
    classification: &policy::IntentClassification,
) -> (StatusCode, Json<serde_json::Value>) {
    err_json(
        StatusCode::UNPROCESSABLE_ENTITY,
        policy::REFUSAL_CODE,
        &policy::refusal_message(classification),
    )
}

/// Structured error with an explicit status (PHP parity: `{error:{code,message}}`).
pub(crate) fn err_json(
    status: StatusCode,
    code: &str,
    message: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "error": { "code": code, "message": message } })),
    )
}

async fn bootstrap(State(st): State<AppState>) -> Json<serde_json::Value> {
    let raw = st.repo.bootstrap(5).await;
    let count = raw.len() as u32;
    // PHP BootstrapController returns {node_id, endpoint, region, last_seen} per peer.
    let peers: Vec<serde_json::Value> = raw
        .into_iter()
        .map(|n| {
            serde_json::json!({
                "node_id": n.node_id,
                "endpoint": n.endpoint,
                "region": n.region,
                "last_seen": serde_json::Value::Null,
            })
        })
        .collect();
    serde_json::json!({ "peers": peers, "count": count }).into()
}

/// `DELETE /v1/register` (iicp-dir §3.6). Requires `Authorization: Bearer <node_token>`.
/// Hard-deletes the node from the directory; capabilities removed via CASCADE.
async fn deregister(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeregisterRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": { "code": "unauthorized", "message": "missing node_token" } }),
                ),
            )
        }
    };
    if !st.repo.verify_node_token(&req.node_id, &token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": { "code": "unauthorized", "message": "invalid node_token" } }),
            ),
        );
    }
    if st.repo.deregister(&req.node_id).await {
        // #442 — emit a SIGNED DEREGISTER event (was an unsigned log_event) so replicas
        // mirror the removal over /v1/events. No-op when unsigned (no key configured).
        emit_event(&st, "DEREGISTER", &req.node_id, serde_json::json!({})).await;
        (
            StatusCode::OK,
            Json(serde_json::json!({ "deregistered": true })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": { "code": "IICP-E003", "message": "node not found" } }),
            ),
        )
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Some(command) = cli.command {
        let result = match command {
            cli::Command::Service { action } => service::run(action),
            cli::Command::Update { action } => updater::run(action).await,
            cli::Command::Healthcheck { ready, json, file } => {
                let code = runtime::run_healthcheck(file, ready, json).unwrap_or_else(|error| {
                    eprintln!("INDETERMINATE: {error}");
                    2
                });
                if code != 0 {
                    std::process::exit(code);
                }
                Ok(())
            }
            command => runtime::run_operational_command(command).await,
        };
        if let Err(error) = result {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        }
        return;
    }
    observability::mark_started();
    let addr = "0.0.0.0:8090";
    let env = config::environment();
    let signing_key = match config::signing_key(env) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        }
    };
    let runtime = runtime::initialize_repository(env, VERSION, signing_key.clone()).await;
    let repo = runtime.repo;
    // Local runtime health is implementation-level state, not a wire-protocol profile.
    // A scheduler checkpoint and the stale-node supervisor advance independently so a
    // notifier task cannot declare health merely because its own timer still runs.
    let runtime_health = iicp_directory_rs::runtime_health::RuntimeHealth::new(true);
    tokio::spawn(runtime::run_runtime_progress_loop(runtime_health.clone()));

    // Spawn background maintenance tasks before starting the HTTP server.
    tokio::spawn(background::run_expire_nodes_loop(
        Arc::clone(&repo),
        runtime_health.clone(),
    ));
    tokio::spawn(background::run_reputation_decay_loop(Arc::clone(&repo)));
    tokio::spawn(background::run_node_lifecycle_loop(Arc::clone(&repo)));
    tokio::spawn(background::run_prune_heartbeat_loop(Arc::clone(&repo)));
    if let Some(pool) = runtime.mysql_pool {
        tokio::spawn(background::run_prune_telemetry_loop(pool));
    }
    tokio::spawn(background::run_rotate_reputation_window_loop(Arc::clone(
        &repo,
    )));
    tokio::spawn(background::run_probe_nodes_loop(Arc::clone(&repo)));
    tokio::spawn(background::run_expire_credits_loop(Arc::clone(&repo))); // WQ-056: 90d TTL credit sink

    // #385/#437 — when IICP_REPLICA_MODE=true, federate: tail the Genesis Seed's
    // signed event log and mirror its state so this instance serves as a replica.
    // Capture the seed URL first: it both drives the sync loop and the write-gate
    // (DIR-FED-18) so the replica 307-redirects writes to the seed.
    let replica_config = replica::ReplicaConfig::from_env();
    let directory_identity = match config::directory_identity(replica_config.as_ref()) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        }
    };
    let replica_seed_url: Option<String> = match replica_config {
        Some(cfg) => {
            eprintln!(
                "[replica] IICP_REPLICA_MODE active — federating from seed {} (writes 307→seed)",
                cfg.seed_url
            );
            let seed = cfg.seed_url.clone();
            tokio::spawn(replica::run_replica_sync(Arc::clone(&repo), cfg));
            Some(seed)
        }
        None => None,
    };

    // #442: load this directory's Ed25519 signing key (libsodium 128-hex). When set, the
    // register/deregister write paths emit signed events onto /v1/events (become a seed).
    let state = AppState {
        repo,
        env,
        signing_key,
        directory_did: directory_identity.did,
        directory_service_endpoint: directory_identity.service_endpoint,
        register_rate: new_register_rate(),
        strict_e050_secured: config::strict_e050_secured(),
        allow_insecure_tls: config::allow_insecure_tls(env),
        skip_liveness_check: config::skip_liveness_check(env),
    };
    let router = match replica_seed_url {
        Some(seed) => app(state).layer(middleware::from_fn_with_state(seed, replica_write_gate)),
        None => app(state),
    };
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("iicp-directory-rs {VERSION} listening on {addr}");
    runtime_health.mark_running();
    #[cfg(all(target_os = "linux", feature = "systemd-notify"))]
    let systemd_notifier =
        iicp_directory_rs::systemd_notify::spawn_if_enabled(runtime_health.clone());

    let shutdown_health = runtime_health.clone();
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown_health.mark_stopping();
            #[cfg(all(target_os = "linux", feature = "systemd-notify"))]
            iicp_directory_rs::systemd_notify::notify_stopping();
        }
    });
    server.await.expect("serve");
    #[cfg(all(target_os = "linux", feature = "systemd-notify"))]
    if let Some(handle) = systemd_notifier {
        handle.abort();
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

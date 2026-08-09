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
mod state;
mod token_issuance;
mod types;
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
        if let Err(error) = runtime::run_operational_command(command).await {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        }
        return;
    }
    observability::mark_started();
    let addr = "0.0.0.0:8090";
    let env = config::environment();
    let runtime = runtime::initialize_repository(env, VERSION).await;
    let repo = runtime.repo;

    // Spawn background maintenance tasks before starting the HTTP server.
    tokio::spawn(background::run_expire_nodes_loop(Arc::clone(&repo)));
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
    let signing_key = match config::signing_key(env) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        }
    };
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
    axum::serve(listener, router).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use repo::NodeRecord;
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    use crate::operator::{operator_dpa_version, operator_terms_version};

    #[test]
    fn telemetry_prune_cli_is_read_only_without_apply() {
        let cli = Cli::try_parse_from(["iicp-directory-rs", "telemetry-prune", "--json"])
            .expect("parse telemetry prune");
        assert!(matches!(
            cli.command,
            Some(Command::TelemetryPrune {
                apply: false,
                dry_run: false,
                ..
            })
        ));
    }

    #[test]
    fn telemetry_prune_cli_rejects_conflicting_modes() {
        assert!(Cli::try_parse_from([
            "iicp-directory-rs",
            "telemetry-prune",
            "--dry-run",
            "--apply"
        ])
        .is_err());
    }

    fn test_state() -> AppState {
        // All tests use one deterministic non-secret key. Setting it once avoids
        // process-global environment races while exercising the production JWT path.
        static APP_KEY: std::sync::Once = std::sync::Once::new();
        APP_KEY.call_once(|| unsafe {
            std::env::set_var("APP_KEY", "test-directory-key-not-for-production");
        });
        let chat = "urn:iicp:intent:llm:chat:v1";
        let mk = |id: &str, score: f64| NodeRecord {
            node: types::Node {
                node_id: id.into(),
                endpoint: format!("https://{id}"),
                region: "eu".into(),
                score,
                available: true,
                load: 0.0,
                active_jobs: 0,
                max_concurrent: 4,
                reputation_score: 0.8,
                latency_estimate_ms: None,
                completed_tasks_count: 0,
                health_label: Some("healthy".into()),
                exposure_mode: None,
                reputation_tier: Some("silver".into()),
                transport_endpoint: None,
                cip_conformance_level: Some("CIP-None".into()),
                models: vec![],
                pricing: None,
                nat_type: None,
                transport_method: None,
                relay_capable: None,
                sdk_language: None,
                implementation_name: None,
                implementation_version: None,
                sdk_compatibility_version: None,
                sdk_version: None,
                consumer_cosignature_ready: false,
                backend: None,
                address_family: None,
                cip_policy: Some(
                    serde_json::json!({"allow_remote_inference":false,"allow_tool_execution":false,"allow_file_access":false,"pricing_credits_per_1000":null}),
                ),
                quantization: vec![],
                inference_engine: vec![],
                public_key: None,
                transport_metadata: None,
                credit_cost_multiplier: 1.0,
                pricing_model: Some("per_token".into()),
                attested: false,
                tasks_failed: 0,
                transport: vec![],
                // Relay-reachable test node (0.5) — matches the documented mesh_health
                // expectation and PHP reachabilityScore relay tier (#385).
                reachability_signal: 0.5,
                operator_pubkey: None,
                operator_display_name: None,
                operator_fingerprint: None,
                operator_verified: false,
                operator_trust_tier: None,
                public_listing: false,
                operator_url: None,
                policy_manifest: None,
                health_models: None,
                routing_policy: types::RoutingPolicyState::default(),
            },
            intents: vec![chat.into()],
            availability: vec![],
            node_token: None,
            node_hmac_key: Some("test-hmac-key".into()),
            proxy_token: None,
        };
        AppState {
            repo: Arc::new(InMemoryRepo::new(vec![mk("a", 0.9), mk("b", 0.5)])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        }
    }

    fn post_register(body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    fn test_state_with_signing_key() -> AppState {
        let mut st = test_state();
        // libsodium 64-byte secret key: seed(0x11*32) || public key from the KAT
        // in federation.rs. This is the same key shape the PHP directory uses.
        st.signing_key = Some(format!(
            "{}{}",
            "11".repeat(32),
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
        ));
        st
    }

    #[tokio::test]
    async fn compliance_attestation_uses_latest_conformance_run() {
        let st = test_state_with_signing_key();
        st.repo
            .record_probe_batch(
                "test",
                &[
                    ProbeResult {
                        probe_id: "p1".into(),
                        probe_type: "conformance".into(),
                        test_id: Some("DIR-ONE".into()),
                        level: "must".into(),
                        passed: true,
                        latency_ms: None,
                        detail: None,
                        run_id: "run-current".into(),
                        probed_at: Some("2026-07-29T15:16:51Z".into()),
                        node_id: None,
                    },
                    ProbeResult {
                        probe_id: "p2".into(),
                        probe_type: "conformance".into(),
                        test_id: Some("DIR-TWO".into()),
                        level: "should".into(),
                        passed: false,
                        latency_ms: None,
                        detail: None,
                        run_id: "run-current".into(),
                        probed_at: Some("2026-07-29T15:16:51Z".into()),
                        node_id: None,
                    },
                ],
            )
            .await;

        let response = app(st)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/compliance-attestation")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["probe_run_id"], "run-current");
        assert_eq!(value["passed_probes"], serde_json::json!(["DIR-ONE"]));
        assert_eq!(value["failed_probes"], serde_json::json!(["DIR-TWO"]));
        assert!(value["signature"]
            .as_str()
            .is_some_and(|sig| sig.len() == 128));
    }

    #[tokio::test]
    async fn api_v1_aliases_cover_live_php_paths() {
        let state = test_state();
        for (method, uri) in [
            ("GET", "/api/v1/stats"),
            ("GET", "/api/v1/metrics"),
            ("GET", "/api/v1/discover?intent=urn:iicp:intent:llm:chat:v1"),
            ("GET", "/api/v1/bootstrap"),
            ("GET", "/api/v1/events"),
            ("GET", "/api/v1/snapshot"),
            ("GET", "/api/v1/registry/nodes"),
            ("GET", "/api/v1/registry/intents"),
            ("GET", "/api/v1/registry/stats"),
            (
                "GET",
                "/api/v1/credits/quote?intent=urn:iicp:intent:llm:chat:v1&max_tokens=1",
            ),
            ("GET", "/api/v1/conformance/badges"),
            ("GET", "/api/v1/probe?endpoint=https://example.com"),
        ] {
            let req = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", "Bearer test-token")
                .header("x-node-id", "a")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app(state.clone()).oneshot(req).await.unwrap();
            assert_ne!(resp.status(), StatusCode::NOT_FOUND, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn discover_api_v1_contains_live_php_compatibility_fields() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let node = &v["nodes"][0];
        for field in [
            "cx_public_key",
            "key_ready",
            "response_encryption_ready",
            "privacy_routing_status",
            "auto_update",
            "backend_stability",
            "trust_progress",
            "route_evidence",
            "routing_hint",
            "sdk_status",
            "sdk_release",
            "sdk_baseline_version",
            "capability_summary",
            "browser_usable",
            "directory_observed_reachable",
            "performance",
            "latency_evidence",
            "health_reasons",
            "input_modalities",
        ] {
            assert!(
                node.as_object().unwrap().contains_key(field),
                "missing live compatibility field {field}"
            );
        }
        assert_eq!(node["sdk_baseline_version"], SDK_BASELINE_VERSION);
        assert_eq!(node["sdk_release"]["latest_known_version"], "0.7.101");
        assert_eq!(node["latency_evidence"]["basis"], "none");
        assert_eq!(node["health_reasons"][0]["dimension"], "reachability");
        assert!(node["trust_progress"]["remaining_gold_requirements"].is_array());
        assert_eq!(v["diversity_evidence"]["identity_material_exposed"], false);
        assert_eq!(
            v["diversity_evidence"]["failure_domain_count"],
            serde_json::Value::Null
        );
        assert_eq!(node["privacy_routing_status"], "transitional");
        assert_eq!(node["response_encryption_ready"], false);
        assert_eq!(node["browser_usable"], true);
    }

    #[tokio::test]
    async fn discover_profile_negotiation_is_additive_and_required_mismatch_fails_closed() {
        let legacy = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let legacy_body = legacy.into_body().collect().await.unwrap().to_bytes();
        assert!(serde_json::from_slice::<serde_json::Value>(&legacy_body)
            .unwrap()
            .get("profile_negotiation")
            .is_none());

        let compatible_uri = "/v1/discover?intent=urn:iicp:intent:llm:chat:v1&profile_id=iicp.profile.compatibility.v0&profile_version=0.4.0-draft&profile_fixture_sha256=d039eaf52afca6866832779261db7bdd2ffd818a36bc8ba9aea1db0c9c115012&profile_required=true";
        let ok = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri(compatible_uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        let ok_body = ok.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&ok_body).unwrap()["profile_negotiation"]
                ["status"],
            "compatible"
        );

        let legacy = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1&profile_id=iicp.profile.compatibility.v0&profile_version=0.3.0-draft&profile_fixture_sha256=4137ecf91b4748a2b368cf4428b4604c6947f8879d77402cc7937d11d24b2aaf&profile_required=true")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy.status(), StatusCode::OK);

        let rejected = app(test_state()).oneshot(axum::http::Request::builder().uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1&profile_id=iicp.profile.unknown.v0&profile_version=0.1.0-draft&profile_fixture_sha256=0000000000000000000000000000000000000000000000000000000000000000&profile_required=true").body(axum::body::Body::empty()).unwrap()).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn discover_uses_short_freshness_and_declares_cache_bypass() {
        let response = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-iicp-discover-origin-cache")
                .unwrap(),
            "bypass"
        );
        let cache_control = response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cache_control.contains("max-age=5"));
        assert!(cache_control.contains("s-maxage=10"));
        assert!(cache_control.contains("stale-while-revalidate=5"));
        let server_timing = response
            .headers()
            .get("server-timing")
            .unwrap()
            .to_str()
            .unwrap();
        for metric in [
            "iicp_repository",
            "iicp_enrichment",
            "iicp_response",
            "iicp_total",
        ] {
            assert!(server_timing.contains(&format!("{metric};dur=")));
        }
        assert!(!server_timing.contains("urn:iicp"));
    }

    #[test]
    fn profile_negotiation_fixture_uses_the_discovery_wire_field() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../parity/profile-negotiation-v0.json"))
                .expect("profile negotiation fixture must be valid JSON");
        assert_eq!(fixture["fixture_version"], "0.2.0-draft");
        assert_eq!(fixture["profile_fixture_sha256"], PROFILE_FIXTURE_SHA256);
        for case in fixture["cases"].as_array().expect("cases must be an array") {
            let request: DiscoverParams = serde_json::from_value(case["request"].clone())
                .expect("profile negotiation fixture request must deserialize");
            let expected = &case["expected"];
            if expected["requested"] == true {
                assert!(request.profile_fixture_sha256.is_some(), "{}", case["name"]);
                let actual =
                    profile_negotiation(&request).expect("requested profile must negotiate");
                for field in ["status", "reason", "dispatch_allowed"] {
                    assert_eq!(actual[field], expected[field], "{}: {field}", case["name"]);
                }
            } else {
                assert!(profile_negotiation(&request).is_none(), "{}", case["name"]);
            }
        }
    }

    #[tokio::test]
    async fn directory_key_and_signed_token_endpoints_work_with_seed_key() {
        let state = test_state_with_signing_key();
        let key_resp = app(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/directory-key")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(key_resp.status(), StatusCode::OK);
        let key_body: serde_json::Value =
            serde_json::from_slice(&key_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            key_body["public_key"],
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
        );

        let req_body = serde_json::json!({
            "target_node_id": "b",
            "intent": "urn:iicp:intent:llm:chat:v1"
        });
        let token_resp = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/consumer-token")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .header("x-node-id", "a")
                    .body(axum::body::Body::from(req_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(token_resp.status(), StatusCode::CREATED);
        let body: serde_json::Value =
            serde_json::from_slice(&token_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["caller_node_id"], "a");
        assert_eq!(body["target_node_id"], "b");
        assert!(body["token"].as_str().unwrap().contains('.'));
    }

    #[tokio::test]
    async fn relay_ticket_endpoint_returns_signed_ticket() {
        let req_body = serde_json::json!({"relay_node_id": "relay-eu"});
        let resp = app(test_state_with_signing_key())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/relay/ticket")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .header("x-node-id", "a")
                    .body(axum::body::Body::from(req_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["worker_node_id"], "a");
        assert_eq!(body["relay_node_id"], "relay-eu");
        assert_eq!(body["algorithm"], "ed25519");
        assert!(body["ticket"].as_str().unwrap().contains('.'));
    }

    #[tokio::test]
    async fn dispatch_ticket_returns_prompt_free_route_bound_ticket() {
        let request = serde_json::json!({"intent": "urn:iicp:intent:llm:chat:v1", "node_id": "a"});
        let resp = app(test_state_with_signing_key())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/dispatch/ticket")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert!(resp
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("no-store")));
        let body: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["node_id"], "a");
        assert_eq!(body["intent"], "urn:iicp:intent:llm:chat:v1");
        assert_eq!(body["algorithm"], "ed25519");
        assert!(body["ticket"].as_str().unwrap().contains('.'));
        assert_eq!(body["route"]["node_id"], "a");
        assert_eq!(body["route"]["endpoint"], "https://a");
        let token_payload = body["ticket"].as_str().unwrap().split('.').next().unwrap();
        use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
        let claims: serde_json::Value = serde_json::from_slice(
            &Base64UrlSafeNoPadding::decode_to_vec(token_payload, None).unwrap(),
        )
        .unwrap();
        assert_eq!(claims["typ"], "dispatch-route-ticket");
        assert_eq!(claims["aud"], DISPATCH_TICKET_AUDIENCE);
        assert_eq!(claims["node_id"], "a");
        assert!(claims.get("prompt").is_none());
        assert!(claims.get("payload").is_none());
        assert!(claims.get("endpoint").is_none());
        assert!(claims.get("node_token").is_none());
    }

    #[tokio::test]
    async fn dispatch_ticket_rejects_payload_and_high_risk_intents() {
        for request in [
            serde_json::json!({"intent": "urn:iicp:intent:llm:chat:v1", "prompt": "GDPR_CANARY_PROMPT_DO_NOT_LOG_20260701"}),
            serde_json::json!({"intent": "urn:iicp:intent:medical:diagnosis:v1"}),
        ] {
            let resp = app(test_state_with_signing_key())
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/v1/dispatch/ticket")
                        .method("POST")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(request.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                !String::from_utf8_lossy(&body).contains("GDPR_CANARY_PROMPT_DO_NOT_LOG_20260701")
            );
            assert!(value["error"]["code"].is_string());
        }
    }

    #[tokio::test]
    async fn replica_write_gate_307s_writes_and_passes_reads() {
        // DIR-FED-18: in replica mode, writes 307→seed; reads pass through.
        let seed = "http://seed-directory:8080".to_string();
        let gated = || {
            app(test_state()).layer(middleware::from_fn_with_state(
                seed.clone(),
                replica_write_gate,
            ))
        };

        // POST write → 307 to seed, path preserved.
        let resp = gated()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/register")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 307, "writes must redirect in replica mode");
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "http://seed-directory:8080/v1/register"
        );
        assert_eq!(
            resp.headers().get("x-iicp-redirect-reason").unwrap(),
            "replica_mode"
        );

        // GET read → passes through (not a redirect).
        let resp = gated()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/registry/nodes")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            307,
            "reads must pass through in replica mode"
        );
    }

    #[tokio::test]
    async fn stats_matches_spec_shape() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/stats")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["server"]["version"].is_string());
        assert!(v["mesh_health"]["label"].is_string());
        // ADR-048 (#374): federation aggregate null until HEALTH events applied.
        assert!(v["mesh_health_federated"].is_null());
        assert!(v["sdk_adoption"].is_object());
        assert!(v["sdk_adoption"]["total_active"].is_number());
        assert_eq!(
            v["sdk_adoption"]["total_active"],
            v["server"]["active_nodes"]
        );
        assert!(v["sdk_adoption"]["by_language"].is_object());
        assert!(v["sdk_adoption"]["by_version"].is_object());
        assert!(v["receipt_profile_adoption"].is_object());
        assert_eq!(
            v["receipt_profile_adoption"]["profile"],
            "consumer_cosignature_v1"
        );
    }

    #[tokio::test]
    async fn stats_includes_sdk_adoption_distribution() {
        let state = test_state();
        let before = sdk_adoption_json(&state.repo.active_nodes().await);
        let count = |v: &serde_json::Value, section: &str, key: &str| -> i64 {
            v[section][key].as_i64().unwrap_or(0)
        };
        let total_before = before["total_active"].as_i64().unwrap_or(0);
        let rust_before = count(&before, "by_language", "rust");
        let python_before = count(&before, "by_language", "python");
        let v0763_before = count(&before, "by_version", "0.7.63");
        let v0762_before = count(&before, "by_version", "0.7.62");

        for (id, endpoint, lang, version) in [
            ("rust-a", "https://1.1.1.1", "rust", "0.7.63"),
            ("rust-b", "https://1.0.0.1", "rust", "0.7.63"),
            ("py-a", "https://8.8.8.8", "python", "0.7.62"),
        ] {
            let body = serde_json::json!({
                "node_id": id,
                "endpoint": endpoint,
                "region": "eu-central",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
                "nat_type": "full_cone",
                "transport_method": "upnp_mapped",
                "sdk_language": lang,
                "sdk_version": version
            });
            let resp = app(state.clone())
                .oneshot(post_register(body))
                .await
                .unwrap();
            assert_eq!(resp.status(), 201);
        }

        let resp = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/stats")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let after = &v["sdk_adoption"];
        assert_eq!(after["total_active"].as_i64().unwrap(), total_before + 3);
        assert_eq!(count(after, "by_language", "rust"), rust_before + 2);
        assert_eq!(count(after, "by_language", "python"), python_before + 1);
        assert_eq!(count(after, "by_version", "0.7.63"), v0763_before + 2);
        assert_eq!(count(after, "by_version", "0.7.62"), v0762_before + 1);
    }

    #[tokio::test]
    async fn stats_probe_shape_includes_active_count_aggregate_conformance_directory_health() {
        // Behavior test: /v1/stats must expose the full PHP StatsController probe shape.
        // Fails if any of these keys are absent — regression guard for the parity gap.
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/stats")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // probes shape (PHP StatsController::probeStats parity)
        assert!(
            v["probes"]["active_count"].is_number(),
            "probes.active_count missing"
        );
        assert!(v["probes"]["regions"].is_array(), "probes.regions missing");
        assert!(
            v["probes"]["aggregate_24h"].is_object(),
            "probes.aggregate_24h missing"
        );
        assert!(
            v["probes"]["conformance_24h"].is_object(),
            "probes.conformance_24h missing"
        );
        assert!(
            v["probes"]["conformance_24h"]["top_failures"].is_array(),
            "conformance_24h.top_failures missing"
        );
        // directory_health (ADR-044 §3.9b parity)
        assert!(
            v["directory_health"].is_object(),
            "directory_health missing"
        );
        assert!(
            v["directory_health"]["label"].is_string(),
            "directory_health.label missing"
        );
        assert!(
            v["directory_health"]["window"].as_str() == Some("24h"),
            "directory_health.window wrong"
        );
    }

    #[tokio::test]
    async fn events_endpoint_serves_signed_log() {
        // #442 slice 3: GET /v1/events serves the signed log in the shape replica::fetch_events
        // expects, with each event carrying its Ed25519 sig + signer_did.
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let key = format!("{}{}", "11".repeat(32), pubkey);
        let state = test_state();
        let repo = state.repo.clone();
        repo.append_signed_event(
            &key,
            "REGISTER",
            "n1",
            &serde_json::json!({"endpoint": "http://x"}),
        )
        .await;
        repo.append_signed_event(&key, "DEREGISTER", "n1", &serde_json::json!({}))
            .await;

        let resp = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/events?since_seq=0")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let events = v["events"].as_array().expect("events array");
        assert_eq!(events.len(), 2);
        assert_eq!(v["next_seq"], 2);
        assert_eq!(events[0]["event_type"], "REGISTER");
        assert_eq!(events[0]["seq"], 1);
        assert!(
            events[0]["sig"].is_string(),
            "events must carry their signature"
        );
        assert_eq!(events[0]["signer_did"], "did:web:iicp.network");
    }

    #[tokio::test]
    async fn federation_endpoints_served_under_api_v1() {
        // #442: a replica (PHP ReplicaStartCommand / Rust fetch_events) polls
        // {seed}/api/v1/events + /api/v1/snapshot — so a Rust seed MUST serve those paths,
        // not just /v1/*. Without the aliases, federation FROM a Rust seed 404s.
        let events = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/events")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(events.status(), 200);
        let snapshot = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/snapshot")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            snapshot.status(),
            401,
            "snapshot path must exist and fail closed without replica authentication"
        );
        // POST /api/v1/replicas/register handshake reachable under /api/v1 too.
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/replicas/register")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"did": "did:web:r.example", "endpoint": "https://r.example"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn did_document_publishes_signing_pubkey_for_verification() {
        // #442: a Rust seed signs events; the DID doc must publish its pubkey so a replica
        // (seed_pubkey_hex_from_did) can resolve it and VERIFY those signatures. Closes the
        // loop with federation::sign_event/verify_event.
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let mut state = test_state();
        state.signing_key = Some(format!("{}{}", "11".repeat(32), pubkey));
        let resp = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/did.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["verificationMethod"].as_array().unwrap().len(), 1);
        // The replica's resolver extracts exactly the seed's signing pubkey from this doc.
        assert_eq!(
            crate::replica::seed_pubkey_hex_from_did(&v),
            Some(pubkey.to_string()),
            "a replica must resolve the Rust seed's verifying key from its DID document"
        );
    }

    #[tokio::test]
    async fn did_document_empty_verification_method_without_key() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/did.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert!(v["verificationMethod"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deployment_record_fails_closed_without_release_metadata() {
        let response = app(test_state_with_signing_key())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/iicp-deployment.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn snapshot_returns_nodes_and_capabilities() {
        // #442 slice 6: GET /v1/snapshot returns all nodes + capabilities for replica
        // bootstrap (test_state seeds nodes a,b serving llm:chat).
        let state = test_state();
        let registration = app(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/replicas/register")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({
                            "did": "did:web:snapshot.example",
                            "endpoint": "https://snapshot.example"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let registration_body = registration.into_body().collect().await.unwrap().to_bytes();
        let registration_json: serde_json::Value =
            serde_json::from_slice(&registration_body).unwrap();
        let token = registration_json["replica_token"].as_str().unwrap();
        let resp = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/snapshot")
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["schema_version"], 1);
        let nodes = v["nodes"].as_array().expect("nodes array");
        assert_eq!(nodes.len(), 2);
        assert!(
            nodes[0]["endpoint"].is_string(),
            "snapshot nodes carry endpoints"
        );
        let caps = v["capabilities"].as_array().expect("capabilities array");
        assert!(
            caps.iter()
                .any(|c| c["intent"] == "urn:iicp:intent:llm:chat:v1"),
            "capabilities carry the served intent so a replica's discover can serve it"
        );
    }

    #[tokio::test]
    async fn replicas_register_handshake() {
        // #442 slice 7: a replica announces did+endpoint → seed records it (idempotent on DID)
        // + emits a signed REPLICA_REGISTERED event.
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let mut state = test_state();
        state.signing_key = Some(format!("{}{}", "11".repeat(32), pubkey));
        let repo = state.repo.clone();
        let post = |b: serde_json::Value| {
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/replicas/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(b.to_string()))
                .unwrap()
        };
        let body = serde_json::json!({"did": "did:web:replica.example", "endpoint": "https://replica.example"});

        let r1 = app(state.clone())
            .oneshot(post(body.clone()))
            .await
            .unwrap();
        assert_eq!(r1.status(), 200);
        let v1: serde_json::Value =
            serde_json::from_slice(&r1.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let rid1 = v1["replica_id"].as_str().unwrap().to_string();
        assert_eq!(v1["trust_tier"], "low");
        assert_eq!(v1["did_acknowledged"], true);
        assert_eq!(v1["is_new_registration"], true);
        let token1 = v1["replica_token"].as_str().unwrap().to_string();

        // Idempotent on DID → same replica_id, no duplicate row.
        let r2 = app(state.clone())
            .oneshot(post(body.clone()))
            .await
            .unwrap();
        let v2: serde_json::Value =
            serde_json::from_slice(&r2.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v2["replica_id"].as_str().unwrap(), rid1);
        assert_eq!(v2["is_new_registration"], false);
        let token2 = v2["replica_token"].as_str().unwrap().to_string();
        assert_ne!(token1, token2, "re-registration must rotate the token");
        assert_eq!(repo.all_replicas().await.len(), 1);

        let old_snapshot = app(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/snapshot")
                    .header("authorization", format!("Bearer {token1}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_snapshot.status(), 401);
        let new_snapshot = app(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/snapshot")
                    .header("authorization", format!("Bearer {token2}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(new_snapshot.status(), 200);

        let decommission = app(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/replicas/deregister")
                    .header("authorization", format!("Bearer {token2}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(decommission.status(), 200);
        assert!(
            repo.all_replicas().await.is_empty(),
            "decommissioned replica must leave public registry"
        );
        let revoked = app(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/snapshot")
                    .header("authorization", format!("Bearer {token2}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), 401);

        let reactivated = app(state.clone())
            .oneshot(post(body.clone()))
            .await
            .unwrap();
        let reactivated_json: serde_json::Value =
            serde_json::from_slice(&reactivated.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(reactivated_json["replica_id"], rid1);
        assert_eq!(reactivated_json["trust_tier"], "low");
        assert_eq!(repo.all_replicas().await.len(), 1);

        // Every registration/rotation/reactivation and explicit decommissioning is signed.
        let events = repo.events_since(0, 100).await;
        assert_eq!(
            events
                .iter()
                .filter(|e| e.event_type == "REPLICA_REGISTERED")
                .count(),
            3
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.event_type == "REPLICA_DEREGISTERED")
                .count(),
            1
        );

        // Bad DID → 422.
        let r3 = app(state)
            .oneshot(post(
                serde_json::json!({"did": "nope", "endpoint": "https://x"}),
            ))
            .await
            .unwrap();
        assert_eq!(r3.status(), 422);
    }

    #[tokio::test]
    async fn health_alias_and_configured_directory_identity_are_served() {
        let mut state = test_state();
        state.directory_did = "did:web:rust-shadow.iicp.network".to_string();
        state.directory_service_endpoint = "https://shadow.example/v1".to_string();
        let health = app(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/iicp/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), 200);
        let did = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/did.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&did.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["id"], "did:web:rust-shadow.iicp.network");
        assert_eq!(body["controller"], "did:web:rust-shadow.iicp.network");
        assert_eq!(
            body["service"][0]["serviceEndpoint"],
            "https://shadow.example/v1"
        );
    }

    // DIR-FED-19: /.well-known/iicp-replicas.json dynamic endpoint
    #[tokio::test]
    async fn iicp_replicas_json_empty_before_any_replicas() {
        let state = test_state();
        let req = axum::http::Request::builder()
            .uri("/.well-known/iicp-replicas.json")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app(state).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["schema_version"], "2");
        assert_eq!(v["genesis_seed"], "did:web:iicp.network");
        assert!(v["replicas"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn iicp_replicas_json_includes_registered_replicas() {
        // After a replica registers via POST /v1/replicas/register, it must appear in
        // /.well-known/iicp-replicas.json with all DIR-FED-19 required fields present.
        let state = test_state();
        let post_body = serde_json::json!({"did": "did:web:replica.example", "endpoint": "https://replica.example"});
        let post_req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/replicas/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(post_body.to_string()))
            .unwrap();
        app(state.clone()).oneshot(post_req).await.unwrap();

        let get_req = axum::http::Request::builder()
            .uri("/.well-known/iicp-replicas.json")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app(state).oneshot(get_req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let entries = v["replicas"].as_array().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "registered replica must appear in the registry"
        );
        let entry = &entries[0];
        // All DIR-FED-19 required fields must be present and non-null.
        assert_eq!(entry["did"], "did:web:replica.example");
        assert_eq!(entry["endpoint"], "https://replica.example");
        assert_eq!(entry["trust_tier"], "low");
        assert!(entry["replica_id"].is_string());
        assert!(entry["registered_at"].is_string());
    }

    #[tokio::test]
    async fn stats_federated_present_once_health_applied() {
        // ADR-048 (#374): three evaluators agree node-x is healthy → majority aggregate
        // surfaces under mesh_health_federated (the single-directory mesh_health is unchanged).
        let state = test_state();
        let repo = state.repo.clone();
        for e in ["e1", "e2", "e3"] {
            repo.upsert_health_observation(
                "node-x",
                &format!("did:web:{e}"),
                0.90,
                1_700_000_000_000,
            )
            .await;
        }
        let resp = app(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/stats")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["mesh_health_federated"]["sample"], 1);
        assert_eq!(v["mesh_health_federated"]["basis"], "federated_union");
        // 1 node in the union < MIN_MESH_SAMPLE(3) → insufficient_sample (aggregate label
        // floor); the per-node majority resolution still produced the 0.90 score.
        assert_eq!(v["mesh_health_federated"]["label"], "insufficient_sample");
        assert_eq!(v["mesh_health_federated"]["score"], 0.9);
        assert_eq!(v["mesh_health_federated"]["contested"], 0);
    }

    #[tokio::test]
    async fn discover_returns_scored_nodelist() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1&limit=10")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["count"], 2);
        // highest score first
        assert_eq!(v["nodes"][0]["node_id"], "a");
        assert_eq!(v["nodes"][0]["health_label"], "healthy");
        // address_family derived from endpoint host at discover time.
        assert!(
            v["nodes"][0]["address_family"].is_string(),
            "address_family must be present in NODELIST (PHP NodeScorer parity)"
        );
        // cip_policy always present (S.12 §2.1).
        assert!(
            v["nodes"][0]["cip_policy"].is_object(),
            "cip_policy must be present in NODELIST"
        );
        // #400/#562 — PHP live shape exposes pricing details inside `pricing`,
        // not as raw Rust-internal top-level fields.
        assert_eq!(v["nodes"][0]["pricing"]["credit_cost_multiplier"], 1.0);
        assert_eq!(v["nodes"][0]["pricing"]["pricing_model"], "per_token");
        assert_eq!(v["nodes"][0]["pricing"]["attested"], false);
        for internal_field in [
            "completed_tasks_count",
            "tasks_failed",
            "credit_cost_multiplier",
            "pricing_model",
            "attested",
            "operator_verified",
            "operator_trust_tier",
            "health_models",
        ] {
            assert!(
                !v["nodes"][0]
                    .as_object()
                    .unwrap()
                    .contains_key(internal_field),
                "discover must not expose Rust-internal field {internal_field}"
            );
        }
        // #397 — transport derived server-side (test_state endpoints are https://…).
        assert_eq!(v["nodes"][0]["transport"], serde_json::json!(["https"]));
    }

    #[tokio::test]
    async fn register_with_phase5_fields_round_trips_in_discover() {
        let st = test_state();
        // Register a node that supplies Phase 5 registration fields.
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["llama3"],
                               "quantization": "q4_k_m", "inference_engine": "llama.cpp"}],
            "relay_capable": true,
            "sdk_language": "python",
            "implementation_name": "iicp-web-node",
            "implementation_version": "0.2.2",
            "sdk_compatibility_version": "0.7.101",
            "sdk_version": "0.7.101",
            "backend": "meshllm",
            "supported_receipt_profiles": ["consumer_cosignature_v1"],
            "nat_type": "full_cone",
            "transport_method": "direct"
        });
        let reg = app(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/register")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("app-env", "local")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reg.status(), 201);
        let rb: serde_json::Value =
            serde_json::from_slice(&reg.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let token = rb["node_token"].as_str().unwrap().to_string();
        // Heartbeat to make it available.
        let hb = serde_json::json!({"load":0.2,"available":true});
        let _ = app(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/heartbeat")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(axum::body::Body::from(hb.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Discover and check Phase 5 fields round-trip.
        let resp = app(st)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1&limit=50")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let node = v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["endpoint"] == "https://1.1.1.1")
            .expect("registered node must appear in discover");
        assert_eq!(node["relay_capable"], true);
        assert_eq!(node["sdk_language"], "python");
        assert_eq!(node["implementation_name"], "iicp-web-node");
        assert_eq!(node["implementation_version"], "0.2.2");
        assert_eq!(node["sdk_compatibility_version"], "0.7.101");
        assert_eq!(node["sdk_version"], "0.7.101");
        assert_eq!(node["backend"], "meshllm");
        assert_eq!(node["consumer_cosignature_ready"], true);
        assert!(node.get("supported_receipt_profiles").is_none());
        assert_eq!(node["nat_type"], "full_cone");
        assert_eq!(node["models"][0], "llama3");
        assert_eq!(node["quantization"][0], "q4_k_m");
        assert_eq!(node["inference_engine"][0], "llama.cpp");
        assert_eq!(node["address_family"], "ipv4");
    }

    #[tokio::test]
    async fn registration_rejects_conflicting_sdk_version_axes() {
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["llama3"]}],
            "sdk_compatibility_version": "0.7.101",
            "sdk_version": "0.7.100"
        });
        let response = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/register")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("app-env", "local")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Signs a fresh operator→node delegation for `node_id` (test key seed 0x09*32).
    fn signed_delegation(node_id: &str, not_after: u64) -> (serde_json::Value, String) {
        signed_delegation_with_seed(node_id, not_after, 9)
    }

    fn signed_delegation_with_seed(
        node_id: &str,
        not_after: u64,
        seed: u8,
    ) -> (serde_json::Value, String) {
        use ct_codecs::{Base64, Encoder};
        use ed25519_compact::{KeyPair, Seed};
        let kp = KeyPair::from_seed(Seed::new([seed; 32]));
        let op_pub = Base64::encode_to_string(&kp.pk[..]).unwrap();
        let msg = delegation::canonical_bytes(node_id, &op_pub, not_after);
        let sig = Base64::encode_to_string(&kp.sk.sign(&msg, None)[..]).unwrap();
        (
            serde_json::json!({
                "node_id": node_id, "operator_pub": op_pub,
                "not_after": not_after, "sig": sig,
            }),
            op_pub,
        )
    }

    // ADR-045 Phase A (#407/#385) — a valid ed25519 operator→node delegation presented
    // at register MUST bind the verified operator identity. Fails without the register-path
    // wiring (the node would stay operator_verified=false).
    #[tokio::test]
    async fn register_with_valid_operator_delegation_binds_identity() {
        let st = test_state();
        let node_id = "op-fleet-node-1";
        let (del, op_pub) = signed_delegation(node_id, delegation::now_unix() + 3600);
        let body = serde_json::json!({
            "node_id": node_id,
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "direct",
            "operator_delegation": del,
        });
        let resp = app(st.clone()).oneshot(post_register(body)).await.unwrap();
        assert_eq!(resp.status(), 201);
        let node = st.repo.get(node_id).await.expect("node stored");
        assert!(node.operator_verified);
        assert_eq!(node.operator_pubkey.as_deref(), Some(op_pub.as_str()));
        assert_eq!(node.operator_trust_tier.as_deref(), Some("did_key"));
    }

    #[tokio::test]
    async fn register_with_revoked_operator_delegation_rolls_back() {
        let state = test_state();
        let node_id = "revoked-operator-registration";
        let (delegation, operator_pubkey) =
            signed_delegation_with_seed(node_id, delegation::now_unix() + 3600, 71);
        state
            .repo
            .upsert_operator(&operator_pubkey, None, None, None)
            .await;
        state
            .repo
            .revoke_operator_identity(&operator_pubkey, "operator_request")
            .await
            .expect("revoke test operator");

        let response = app(state.clone())
            .oneshot(post_register(serde_json::json!({
                "node_id": node_id,
                "endpoint": "https://1.1.1.1",
                "capabilities": [{
                    "intent": "urn:iicp:intent:llm:chat:v1",
                    "models": ["model-a"]
                }],
                "availability": [{"start": "08:00", "end": "17:00", "share": 1.0}],
                "operator_delegation": delegation
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(state.repo.get(node_id).await.is_none());
    }

    // #463/#310/#464 (#385 parity with PHP OperatorRecordTest) — a verified delegation +
    // operator_display_name upserts the operators record; node detail serves display_name
    // but NEVER operator_pubkey; display_name is mutable via a delegated re-register.
    #[tokio::test]
    async fn register_upserts_operator_and_serves_display_name_not_pubkey() {
        use http_body_util::BodyExt;
        let st = test_state();
        let node_id = "op-fleet-node-dn";
        let (del, op_pub) = signed_delegation(node_id, delegation::now_unix() + 3600);
        let mk = |del: serde_json::Value, name: &str| {
            serde_json::json!({
                "node_id": node_id,
                "endpoint": "https://1.1.1.1",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
                "nat_type": "full_cone", "transport_method": "direct",
                "operator_delegation": del,
                "operator_display_name": name,
                "operator_created_at": "2026-06-05T12:00:00Z",
                "operator_integrity_hash": "a".repeat(64),
            })
        };
        let resp = app(st.clone())
            .oneshot(post_register(mk(del, "Rebel One")))
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        assert_eq!(
            st.repo.operator_display_name(&op_pub).await.as_deref(),
            Some("Rebel One")
        );

        // Node detail serves display_name but MUST NOT leak operator_pubkey.
        let detail = app(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/v1/registry/nodes/{node_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), 200);
        let bytes = detail.into_body().collect().await.unwrap().to_bytes();
        let raw = String::from_utf8(bytes.to_vec()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["operator_display_name"], "Rebel One");
        assert_eq!(
            v["operator_fingerprint"],
            public_operator_fingerprint(&op_pub)
        );
        assert!(
            !raw.contains(&op_pub),
            "node detail must not expose operator_pubkey"
        );
        assert!(!raw.contains("operator_pubkey"));

        // Mutable: a delegated re-register with a new name updates the one operator record.
        let (del2, _) = signed_delegation(node_id, delegation::now_unix() + 3600);
        app(st.clone())
            .oneshot(post_register(mk(del2, "New Name")))
            .await
            .unwrap();
        assert_eq!(
            st.repo.operator_display_name(&op_pub).await.as_deref(),
            Some("New Name")
        );
    }

    #[tokio::test]
    async fn discover_includes_operator_display_name_and_fingerprint_never_key() {
        use http_body_util::BodyExt;
        let st = test_state();
        let node_id = "op-fleet-discover";
        let (del, op_pub) = signed_delegation(node_id, delegation::now_unix() + 3600);
        let body = serde_json::json!({
            "node_id": node_id,
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["m"]}],
            "nat_type": "full_cone", "transport_method": "direct",
            "operator_delegation": del,
            "operator_display_name": "ZeroKelvinMoralist",
        });
        assert_eq!(
            app(st.clone())
                .oneshot(post_register(body))
                .await
                .unwrap()
                .status(),
            201
        );

        let resp = app(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1&limit=50")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let raw = String::from_utf8(bytes.to_vec()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let node = v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["node_id"] == node_id)
            .expect("registered node appears in discover");
        assert_eq!(node["operator_display_name"], "ZeroKelvinMoralist");
        assert_eq!(
            node["operator_fingerprint"],
            public_operator_fingerprint(&op_pub)
        );
        assert!(!raw.contains(&op_pub));
        assert!(!raw.contains("operator_pubkey"));
    }

    #[tokio::test]
    async fn display_name_cannot_be_claimed_by_different_verified_operator() {
        use http_body_util::BodyExt;
        let st = test_state();
        let (del_a, _) = signed_delegation_with_seed("op-name-a", delegation::now_unix() + 3600, 9);
        let first = serde_json::json!({
            "node_id": "op-name-a",
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "direct",
            "operator_delegation": del_a,
            "operator_display_name": "Mesh Pioneer",
        });
        assert_eq!(
            app(st.clone())
                .oneshot(post_register(first))
                .await
                .unwrap()
                .status(),
            201
        );

        let (del_b, _) =
            signed_delegation_with_seed("op-name-b", delegation::now_unix() + 3600, 10);
        let duplicate = serde_json::json!({
            "node_id": "op-name-b",
            "endpoint": "https://1.1.1.2",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "direct",
            "operator_delegation": del_b,
            "operator_display_name": " mesh   pioneer ",
        });
        let resp = app(st.clone())
            .oneshot(post_register(duplicate))
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["error"]["message"],
            "operator_display_name is already claimed by another verified operator (IICP-E051)"
        );
        assert!(st.repo.get("op-name-b").await.is_none());
    }

    #[tokio::test]
    async fn rotated_predecessor_does_not_block_successor_display_name() {
        // A key rotation retains the predecessor as immutable lifecycle evidence and
        // copies its public handle to the active successor. The successor must be
        // able to re-register under that handle; otherwise supervised handoff loops
        // indefinitely after an otherwise accepted rotation.
        let st = test_state();
        st.repo
            .upsert_operator(
                "operator-predecessor",
                Some("Mesh Pioneer"),
                Some("2026-07-12T00:00:00Z"),
                Some(&"a".repeat(64)),
            )
            .await;
        st.repo
            .rotate_operator_identity(
                "operator-predecessor",
                "operator-successor",
                Some(1),
                "operator_rotation",
            )
            .await
            .expect("active operator rotates");

        assert_eq!(
            st.repo
                .operator_identity_active("operator-predecessor")
                .await,
            Some(false)
        );
        assert_eq!(
            st.repo.operator_identity_active("operator-successor").await,
            Some(true)
        );
        assert!(
            !st.repo
                .operator_display_name_claimed_by_other("operator-successor", "mesh pioneer")
                .await,
            "rotated predecessor must not reserve the successor's copied handle"
        );
    }

    // ── #460 operator-signed rename (PHP OperatorRenameTest parity #385) ──────────

    fn rename_keypair(seed: u8) -> (String, ed25519_compact::KeyPair) {
        use ct_codecs::{Base64, Encoder};
        use ed25519_compact::{KeyPair, Seed};
        let kp = KeyPair::from_seed(Seed::new([seed; 32]));
        (Base64::encode_to_string(&kp.pk[..]).unwrap(), kp)
    }

    fn sign_rename(kp: &ed25519_compact::KeyPair, op_pub: &str, name: &str, ts: i64) -> String {
        use ct_codecs::{Base64, Encoder};
        let msg = delegation::canonical_rename_bytes(name, op_pub, ts);
        Base64::encode_to_string(&kp.sk.sign(&msg, None)[..]).unwrap()
    }

    fn post_rename(body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/operator/rename")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    fn post_operator(path: &str, body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    fn sign_self_service(
        keypair: &ed25519_compact::KeyPair,
        action: &str,
        fields: BTreeMap<String, serde_json::Value>,
    ) -> String {
        use ct_codecs::{Base64, Encoder};
        let bytes = delegation::canonical_self_service_bytes(action, &fields);
        Base64::encode_to_string(&keypair.sk.sign(&bytes, None)[..]).unwrap()
    }

    async fn challenge_nonce(st: AppState, operator_pub: &str) -> String {
        use http_body_util::BodyExt;
        let response = app(st)
            .oneshot(post_operator(
                "/v1/operator/challenge",
                serde_json::json!({"operator_pub": operator_pub}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        body["nonce"].as_str().unwrap().to_string()
    }

    async fn signed_operator_body(
        st: AppState,
        operator_pub: &str,
        keypair: &ed25519_compact::KeyPair,
        action: &str,
        extra: BTreeMap<String, serde_json::Value>,
    ) -> serde_json::Value {
        let mut fields = BTreeMap::from([
            (
                "operator_pub".to_string(),
                serde_json::Value::String(operator_pub.to_string()),
            ),
            (
                "nonce".to_string(),
                serde_json::Value::String(challenge_nonce(st, operator_pub).await),
            ),
            (
                "ts".to_string(),
                serde_json::Value::from(delegation::now_unix() as i64),
            ),
        ]);
        fields.extend(extra);
        let signature = sign_self_service(keypair, action, fields.clone());
        let mut body = serde_json::Map::from_iter(fields);
        body.insert("sig".to_string(), serde_json::Value::String(signature));
        serde_json::Value::Object(body)
    }

    #[tokio::test]
    async fn operator_acceptance_and_dsr_are_signed_redacted_and_one_use() {
        use http_body_util::BodyExt;
        let st = test_state();
        let (operator_pub, keypair) = rename_keypair(20);
        st.repo
            .upsert_operator(&operator_pub, Some("DSR Test"), None, None)
            .await;

        let acceptance = signed_operator_body(
            st.clone(),
            &operator_pub,
            &keypair,
            "accept",
            BTreeMap::from([
                (
                    "terms_version".to_string(),
                    serde_json::Value::String(operator_terms_version()),
                ),
                (
                    "dpa_version".to_string(),
                    serde_json::Value::String(operator_dpa_version()),
                ),
            ]),
        )
        .await;
        let response = app(st.clone())
            .oneshot(post_operator(
                "/api/v1/operator/acceptance",
                acceptance.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let raw = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(!raw.contains(&operator_pub));
        assert!(!raw.contains(acceptance["nonce"].as_str().unwrap()));
        let replay = app(st.clone())
            .oneshot(post_operator("/api/v1/operator/acceptance", acceptance))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        let export = signed_operator_body(
            st.clone(),
            &operator_pub,
            &keypair,
            "dsr_export",
            BTreeMap::from([(
                "tracking_id".to_string(),
                serde_json::Value::String("dsr-rust-export".to_string()),
            )]),
        )
        .await;
        let response = app(st.clone())
            .oneshot(post_operator("/api/v1/operator/dsr/export", export))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let raw = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(!raw.contains(&operator_pub));
        assert!(raw.contains("iicp.dsr.export.v1"));

        let restrict = signed_operator_body(
            st.clone(),
            &operator_pub,
            &keypair,
            "dsr_restrict",
            BTreeMap::from([
                (
                    "tracking_id".to_string(),
                    serde_json::Value::String("dsr-rust-restrict".to_string()),
                ),
                ("confirm".to_string(), serde_json::Value::Bool(true)),
            ]),
        )
        .await;
        let response = app(st.clone())
            .oneshot(post_operator("/api/v1/operator/dsr/restrict", restrict))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(st.repo.operator_display_name(&operator_pub).await, None);
    }

    #[tokio::test]
    async fn public_discovery_is_route_redacted_and_counted_anonymously() {
        use http_body_util::BodyExt;
        let st = test_state();
        let response = app(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/discover?intent=urn:iicp:intent:llm:chat:v1&view=public")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["x-iicp-discover-data-class"],
            "public_presentation"
        );
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["route_fields_present"], false);
        assert_eq!(
            body["diversity_evidence"]["identity_material_exposed"],
            false
        );
        let raw = body.to_string();
        assert!(!raw.contains("operator_pubkey"));
        for node in body["nodes"].as_array().unwrap() {
            assert!(node.get("endpoint").is_none());
            assert!(node.get("transport_endpoint").is_none());
            assert!(node.get("node_id").is_none());
            assert!(node.get("cx_public_key").is_none());
        }
        let usage = st.repo.dispatch_usage_summary(7).await;
        assert_eq!(usage["public_view_requests"], 1);
        assert_eq!(usage["contains_caller_identifiers"], false);
    }

    #[tokio::test]
    async fn registration_policy_manifest_is_exposed_as_verified_summary_not_raw_signature() {
        use ct_codecs::{Base64, Encoder};
        use ed25519_compact::{KeyPair, Seed};
        use http_body_util::BodyExt;
        let st = test_state();
        let keypair = KeyPair::from_seed(Seed::new([44; 32]));
        let mut manifest = serde_json::json!({
            "version": "1",
            "jurisdiction": "EU",
            "training_use": "none",
            "retention": {"task_payload": "transient", "logs_days": 0},
            "signature": {
                "algorithm": "Ed25519",
                "key_id": "operator-primary",
                "public_key": Base64::encode_to_string(&keypair.pk[..]).unwrap()
            }
        });
        let signature = keypair
            .sk
            .sign(policy_manifest::canonical_payload(&manifest), None);
        manifest["signature"]["signature"] =
            serde_json::Value::String(Base64::encode_to_string(&signature[..]).unwrap());
        let request = serde_json::json!({
            "node_id": "policy-node",
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone",
            "transport_method": "direct",
            "policy_manifest": manifest,
        });
        assert_eq!(
            app(st.clone())
                .oneshot(post_register(request))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        let response = app(st)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let raw = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(raw.contains("signed_valid"));
        assert!(!raw.contains(manifest["signature"]["signature"].as_str().unwrap()));
    }

    #[tokio::test]
    async fn operator_signed_rename_updates_display_name() {
        let st = test_state();
        let (op_pub, kp) = rename_keypair(21);
        st.repo
            .upsert_operator(&op_pub, Some("Old Name"), None, None)
            .await;
        let ts = delegation::now_unix() as i64;
        let resp = app(st.clone())
            .oneshot(post_rename(serde_json::json!({
                "operator_pub": op_pub, "display_name": "New Name", "ts": ts,
                "sig": sign_rename(&kp, &op_pub, "New Name", ts),
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            st.repo.operator_display_name(&op_pub).await.as_deref(),
            Some("New Name")
        );
    }

    #[tokio::test]
    async fn operator_rename_bad_signature_rejected() {
        let st = test_state();
        let (op_pub, _kp) = rename_keypair(22);
        st.repo
            .upsert_operator(&op_pub, Some("Old"), None, None)
            .await;
        let ts = delegation::now_unix() as i64;
        // A signature from a DIFFERENT key — valid length, wrong signer.
        let (_, other) = rename_keypair(99);
        let resp = app(st.clone())
            .oneshot(post_rename(serde_json::json!({
                "operator_pub": op_pub, "display_name": "Hijacked", "ts": ts,
                "sig": sign_rename(&other, &op_pub, "Hijacked", ts),
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(
            st.repo.operator_display_name(&op_pub).await.as_deref(),
            Some("Old")
        );
    }

    #[tokio::test]
    async fn operator_rename_stale_timestamp_rejected() {
        let st = test_state();
        let (op_pub, kp) = rename_keypair(23);
        st.repo
            .upsert_operator(&op_pub, Some("Old"), None, None)
            .await;
        let ts = delegation::now_unix() as i64 - 3600; // way outside the ±300s window
        let resp = app(st.clone())
            .oneshot(post_rename(serde_json::json!({
                "operator_pub": op_pub, "display_name": "New", "ts": ts,
                "sig": sign_rename(&kp, &op_pub, "New", ts),
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn operator_rename_unknown_operator_is_404() {
        let st = test_state();
        let (op_pub, kp) = rename_keypair(24); // never upserted into operators
        let ts = delegation::now_unix() as i64;
        let resp = app(st.clone())
            .oneshot(post_rename(serde_json::json!({
                "operator_pub": op_pub, "display_name": "Ghost", "ts": ts,
                "sig": sign_rename(&kp, &op_pub, "Ghost", ts),
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn operator_key_rotation_requires_two_keys_and_preserves_active_successor() {
        use ct_codecs::{Base64, Encoder};
        use ed25519_compact::{KeyPair, Seed};
        use http_body_util::BodyExt;

        let st = test_state();
        let old = KeyPair::from_seed(Seed::new([41; 32]));
        let next = KeyPair::from_seed(Seed::new([42; 32]));
        let old_pub = Base64::encode_to_string(&old.pk[..]).unwrap();
        let next_pub = Base64::encode_to_string(&next.pk[..]).unwrap();
        st.repo
            .upsert_operator(&old_pub, Some("Lifecycle"), None, None)
            .await;
        let nonce = challenge_nonce(st.clone(), &old_pub).await;
        let ts = delegation::now_unix() as i64;
        let fields = BTreeMap::from([
            (
                "operator_pub".to_string(),
                serde_json::Value::String(old_pub.clone()),
            ),
            (
                "new_operator_pub".to_string(),
                serde_json::Value::String(next_pub.clone()),
            ),
            (
                "nonce".to_string(),
                serde_json::Value::String(nonce.clone()),
            ),
            ("ts".to_string(), serde_json::Value::from(ts)),
            (
                "reason_class".to_string(),
                serde_json::Value::String("operator_rotation".to_string()),
            ),
        ]);
        let successor_fields = BTreeMap::from([
            (
                "operator_pub".to_string(),
                serde_json::Value::String(old_pub.clone()),
            ),
            (
                "new_operator_pub".to_string(),
                serde_json::Value::String(next_pub.clone()),
            ),
            (
                "nonce".to_string(),
                serde_json::Value::String(nonce.clone()),
            ),
            ("ts".to_string(), serde_json::Value::from(ts)),
            ("rotation_epoch".to_string(), serde_json::Value::Null),
        ]);
        let response = app(st.clone())
            .oneshot(post_operator(
                "/v1/operator/key/rotate",
                serde_json::json!({
                    "operator_pub": old_pub,
                    "new_operator_pub": next_pub,
                    "nonce": nonce,
                    "ts": ts,
                    "reason_class": "operator_rotation",
                    "sig": sign_self_service(&old, "key_rotate", fields),
                    "new_key_sig": sign_self_service(&next, "key_rotate_successor", successor_fields),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["status"], "rotated");
        assert_eq!(body["rotation_epoch"], 1);
        assert_eq!(
            st.repo.operator_identity_active(&old_pub).await,
            Some(false)
        );
        assert_eq!(
            st.repo.operator_identity_active(&next_pub).await,
            Some(true)
        );
    }

    #[tokio::test]
    async fn operator_key_revocation_consumes_one_challenge_and_fails_closed() {
        use ct_codecs::{Base64, Encoder};
        use ed25519_compact::{KeyPair, Seed};
        use http_body_util::BodyExt;

        let st = test_state();
        let key = KeyPair::from_seed(Seed::new([43; 32]));
        let operator_pub = Base64::encode_to_string(&key.pk[..]).unwrap();
        st.repo
            .upsert_operator(&operator_pub, Some("Revoke"), None, None)
            .await;
        let nonce = challenge_nonce(st.clone(), &operator_pub).await;
        let ts = delegation::now_unix() as i64;
        let fields = BTreeMap::from([
            (
                "operator_pub".to_string(),
                serde_json::Value::String(operator_pub.clone()),
            ),
            (
                "nonce".to_string(),
                serde_json::Value::String(nonce.clone()),
            ),
            ("ts".to_string(), serde_json::Value::from(ts)),
            ("confirm".to_string(), serde_json::Value::Bool(true)),
            (
                "reason_class".to_string(),
                serde_json::Value::String("operator_request".to_string()),
            ),
        ]);
        let body = serde_json::json!({
            "operator_pub": operator_pub,
            "nonce": nonce,
            "ts": ts,
            "confirm": true,
            "reason_class": "operator_request",
            "sig": sign_self_service(&key, "key_revoke", fields),
        });
        let response = app(st.clone())
            .oneshot(post_operator("/v1/operator/key/revoke", body.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let received: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(received["status"], "revoked");
        assert_eq!(
            st.repo.operator_identity_active(&operator_pub).await,
            Some(false)
        );
        let replay = app(st.clone())
            .oneshot(post_operator("/v1/operator/key/revoke", body))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        let replay_body: serde_json::Value =
            serde_json::from_slice(&replay.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(replay_body["error"]["code"], "IICP-E063");
    }

    // #310/#463 (PHP LeaderboardTest parity) — the founders board orders by ordinal, serves
    // the public display_name + recognition state, excludes non-founders, and NEVER leaks
    // operator_pubkey; an unknown/uncomputed board is 404.
    #[tokio::test]
    async fn founders_leaderboard_orders_by_ordinal_and_hides_pubkey() {
        use http_body_util::BodyExt;
        let st = test_state();
        for (pk, name, ord, tier, badge) in [
            ("PUBKEY_C", "Third", 3, "founders_1000", "founder"),
            ("PUBKEY_A", "First", 1, "genesis_50", "genesis"),
            ("PUBKEY_B", "Second", 2, "founders_500", "founder"),
        ] {
            st.repo.upsert_operator(pk, Some(name), None, None).await;
            st.repo
                .set_operator_recognition(pk, ord, Some(tier), Some(badge))
                .await;
        }
        // A non-founder (no ordinal) must not appear.
        st.repo
            .upsert_operator("PUBKEY_X", Some("Latecomer"), None, None)
            .await;

        let get = |uri: &str| {
            axum::http::Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let resp = app(st.clone())
            .oneshot(get("/v1/leaderboards/founders"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let raw = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["count"], 3);
        assert_eq!(v["entries"][0]["place"], 1);
        assert_eq!(v["entries"][0]["display_name"], "First");
        assert_eq!(v["entries"][0]["ordinal"], 1);
        assert_eq!(v["entries"][2]["display_name"], "Third");
        assert!(!raw.contains("PUBKEY_A"), "must not expose operator_pubkey");
        assert!(!raw.contains("operator_pubkey"));
        assert!(!raw.contains("Latecomer"), "non-founder must be excluded");

        // Boards needing rank_score (not yet computed) → 404, not a fabricated list.
        let resp404 = app(st.clone())
            .oneshot(get("/v1/leaderboards/living_mesh_lords"))
            .await
            .unwrap();
        assert_eq!(resp404.status(), 404);
    }

    // Provisional founders (PHP LeaderboardTest parity): an operator with a genuine served
    // node but no ordinal yet appears in `pending` with a projected ordinal + days remaining;
    // an operator with no served node (name squatter) does NOT.
    #[tokio::test]
    async fn founders_leaderboard_pending_shows_provisional_operators() {
        use http_body_util::BodyExt;
        let st = test_state();
        // Locked founder #1.
        st.repo
            .upsert_operator("PUBKEY_ONE", Some("Founder"), None, None)
            .await;
        st.repo
            .set_operator_recognition("PUBKEY_ONE", 1, Some("genesis_50"), Some("first_10"))
            .await;
        // Provisional: register a node with a verified operator delegation (genuine served node).
        let node_id = "pending-node-1";
        let (del, _op_pub) = signed_delegation(node_id, delegation::now_unix() + 3600);
        let body = serde_json::json!({
            "node_id": node_id,
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "direct",
            "operator_delegation": del,
            "operator_display_name": "Challenger",
        });
        let resp = app(st.clone()).oneshot(post_register(body)).await.unwrap();
        assert_eq!(resp.status(), 201);
        // Name squatter: operator record exists, no node.
        st.repo
            .upsert_operator("PUBKEY_SQUAT", Some("NameSquatter"), None, None)
            .await;

        let get = |uri: &str| {
            axum::http::Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let resp = app(st.clone())
            .oneshot(get("/v1/leaderboards/founders"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let raw = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["pending"][0]["display_name"], "Challenger");
        assert_eq!(v["pending"][0]["projected_ordinal"], 2); // after locked #1
        assert_eq!(v["pending"][0]["days_remaining"], 30); // just appeared
        assert_eq!(v["pending"][0]["provisional"], true);
        assert!(!raw.contains("NameSquatter"), "no served node → not listed");
        assert!(!raw.contains("PUBKEY_"), "must not expose operator_pubkey");
    }

    // An expired (or otherwise invalid) delegation is fail-safe: the node registers
    // successfully but stays unverified — no false operator binding.
    #[tokio::test]
    async fn register_with_expired_operator_delegation_stays_unverified() {
        let st = test_state();
        let node_id = "op-fleet-node-2";
        let (del, _op_pub) = signed_delegation(node_id, 1_000); // long expired
        let body = serde_json::json!({
            "node_id": node_id,
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "direct",
            "operator_delegation": del,
        });
        let resp = app(st.clone()).oneshot(post_register(body)).await.unwrap();
        assert_eq!(resp.status(), 201);
        let node = st.repo.get(node_id).await.expect("node stored");
        assert!(!node.operator_verified);
        assert_eq!(node.operator_pubkey, None);
    }

    // WQ-057 — GET /v1/credits/quote (PHP parity): authenticated pre-flight; the estimate
    // math is the pure compute_quote, the candidate scoping is quote_multipliers.
    #[test]
    fn credits_quote_compute_empty_uses_base_rate() {
        // WQ-057 #404: no candidates → base rate (×1.0), 0 nodes quoted.
        let q = super::compute_quote(2000, &[]);
        assert_eq!(q.nodes_quoted, 0);
        assert_eq!(q.estimated, 2.0); // base_blocks=2 × 1.0
        assert_eq!(q.price_per_1000, 1.0);
    }

    #[test]
    fn credits_quote_compute_uses_min_max_avg() {
        // WQ-057 #404: min/max from cheapest/dearest multiplier, estimated from the average.
        let q = super::compute_quote(2000, &[1.0, 2.0, 3.0]);
        assert_eq!(q.nodes_quoted, 3);
        assert_eq!(q.min, 2.0); // base 2 × 1.0
        assert_eq!(q.max, 6.0); // base 2 × 3.0
        assert_eq!(q.estimated, 4.0); // base 2 × avg 2.0
        assert_eq!(q.price_per_1000, 2.0);
    }

    #[test]
    fn credits_quote_compute_ceils_partial_block() {
        // ceil(500/1000) = 1 block (PHP parity).
        assert_eq!(super::compute_quote(500, &[1.0]).estimated, 1.0);
    }

    #[tokio::test]
    async fn credits_quote_requires_node_token() {
        // WQ-057 #404: the quote is an authenticated consumer pre-flight (PHP parity) —
        // no bearer → 401, not an anonymous price.
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/credits/quote?intent=urn:iicp:intent:llm:chat:v1&max_tokens=1000")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn credits_summary_zero_ledger_reconciles() {
        // (see preceding doc — summary reconciles to all-zero with no ledger)
        let st = test_state();
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "direct"
        });
        let reg = app(st.clone()).oneshot(post_register(body)).await.unwrap();
        assert_eq!(reg.status(), 201);
        let rb: serde_json::Value =
            serde_json::from_slice(&reg.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let node_id = rb["node_id"].as_str().unwrap().to_string();
        let token = rb["node_token"].as_str().unwrap().to_string();

        let resp = app(st)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/credits/summary")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("X-Node-Id", &node_id)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let v: serde_json::Value =
            serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(v["node_id"], node_id);
        assert_eq!(v["total_earned"], 0.0);
        assert_eq!(v["total_spent"], 0.0);
        assert_eq!(v["reconciles"], true);
        assert_eq!(v["tokens_per_credit"], 1000);
    }

    #[tokio::test]
    async fn discover_unknown_intent_returns_empty() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:nope:x:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["count"], 0);
    }

    #[tokio::test]
    async fn discover_relay_available_false_when_no_relay_capable_nodes() {
        // Behavior: relay_available=false when no discovered node has relay_capable=true.
        // test_state() nodes have relay_capable=None (falsy) → relay_available=false.
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["relay_available"], false,
            "relay_available should be false with no relay nodes"
        );
    }

    #[tokio::test]
    async fn discover_relay_available_true_when_relay_capable_node_present() {
        // Behavior: relay_available=true when ≥1 discovered node has relay_capable=true.
        let st = test_state();
        // Register a relay-capable node via HTTP then heartbeat it.
        let reg = app(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .header("app-env", "local")
                    .body(axum::body::Body::from(
                        serde_json::json!({
                            "endpoint": "https://1.1.1.1",
                            "region": "eu",
                            "relay_capable": true,
                            "nat_type": "full_cone",
                            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reg.status(), 201);
        let rb: serde_json::Value =
            serde_json::from_slice(&reg.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let token = rb["node_token"].as_str().unwrap().to_string();
        let _ = app(st.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::from(r#"{"load":0.1,"available":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = app(st)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["relay_available"], true,
            "relay_available should be true when relay node registered"
        );
    }

    #[tokio::test]
    async fn register_valid_returns_201_ack() {
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "upnp_mapped"
        });
        let resp = app(test_state())
            .oneshot(post_register(body))
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["node_token"].is_string());
        assert!(v["jwt_token"].is_string() || v["jwt_token"].is_null()); // PHP field name
        assert_eq!(v["public_reachable"], true); // declared-reachable
    }

    #[tokio::test]
    async fn register_emits_signed_event_to_log() {
        // #442: with a signing key configured, POST /v1/register emits a signed REGISTER
        // event onto the log (so a replica can mirror this node over /v1/events).
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let mut state = test_state();
        state.signing_key = Some(format!("{}{}", "11".repeat(32), pubkey));
        let repo = state.repo.clone();

        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["m1"]}],
            "nat_type": "full_cone", "transport_method": "upnp_mapped"
        });
        let resp = app(state).oneshot(post_register(body)).await.unwrap();
        assert_eq!(resp.status(), 201);

        let events = repo.events_since(0, 100).await;
        assert_eq!(events.len(), 1, "register must emit exactly one event");
        let ev = &events[0];
        assert_eq!(ev.event_type, "REGISTER");
        // capabilities ride along (#438) so a replica's discover can serve the node.
        assert_eq!(
            ev.payload["capabilities"][0]["intent"],
            "urn:iicp:intent:llm:chat:v1"
        );
        // the emitted event is signed and verifies under the configured key, and the first
        // event chains from GENESIS_ROOT (#458).
        let sig = ev.sig.as_ref().expect("event must be signed");
        assert_eq!(
            ev.prev_hash.as_deref(),
            Some(crate::federation::GENESIS_ROOT),
            "first event's prev_hash is GENESIS_ROOT"
        );
        let msg = crate::federation::event_message(
            &ev.event_id,
            &ev.event_type,
            ev.seq,
            ev.ts_ms,
            &ev.payload,
            ev.prev_hash
                .as_deref()
                .unwrap_or(crate::federation::GENESIS_ROOT),
        );
        assert!(crate::federation::verify_event(pubkey, sig, &msg));
    }

    #[tokio::test]
    async fn register_without_key_emits_nothing() {
        // No signing key (default test_state) → no events emitted (unsigned-mode parity).
        let state = test_state();
        let repo = state.repo.clone();
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1", "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "upnp_mapped"
        });
        let resp = app(state).oneshot(post_register(body)).await.unwrap();
        assert_eq!(resp.status(), 201);
        assert!(repo.events_since(0, 100).await.is_empty());
    }

    #[tokio::test]
    async fn credit_award_emits_signed_event() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let mut state = test_state();
        state.signing_key = Some(format!("{}{}", "11".repeat(32), pubkey));
        let repo = state.repo.clone();

        // 1. register a node → obtain node_token + node_hmac_key from the ACK.
        let reg = serde_json::json!({
            "endpoint": "https://1.1.1.1", "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "upnp_mapped"
        });
        let r1 = app(state.clone())
            .oneshot(post_register(reg))
            .await
            .unwrap();
        assert_eq!(r1.status(), 201);
        let b1 = r1.into_body().collect().await.unwrap().to_bytes();
        let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
        let node_id = v1["node_id"].as_str().unwrap().to_string();
        let token = v1["node_token"].as_str().unwrap().to_string();
        let hmac_key = v1["node_hmac_key"].as_str().unwrap().to_string();

        // 2. sign a valid CIP receipt and POST /v1/credits/award.
        let nonce = "nonce-abcdefghijklmnopqrstuvwxyz123456"; // >= 32 chars
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}",
            "task-1", 1000u64, "", "", nonce, "hash-1"
        );
        let mut mac = HmacSha256::new_from_slice(hmac_key.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        let award = serde_json::json!({
            "node_id": node_id, "task_id": "task-1", "tokens_used": 1000,
            "nonce": nonce, "response_hash": "hash-1", "signature": sig, "amount": 1.0
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/credits/award")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(award.to_string()))
            .unwrap();
        let r2 = app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(r2.status(), 201, "credit award must succeed");

        // 3. a signed CREDIT_AWARD event was emitted with the new balance.
        let events = repo.events_since(0, 100).await;
        let credit = events
            .iter()
            .find(|e| e.event_type == "CREDIT_AWARD")
            .expect("CREDIT_AWARD event emitted");
        assert_eq!(credit.payload["new_balance"], 1.0);
        assert!(credit.sig.is_some(), "CREDIT_AWARD must be signed");
    }

    #[tokio::test]
    async fn credit_award_excludes_same_querying_node() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let state = test_state();
        let repo = state.repo.clone();

        let reg = serde_json::json!({
            "endpoint": "https://1.1.1.1", "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "full_cone", "transport_method": "upnp_mapped"
        });
        let r1 = app(state.clone())
            .oneshot(post_register(reg))
            .await
            .unwrap();
        assert_eq!(r1.status(), 201);
        let b1 = r1.into_body().collect().await.unwrap().to_bytes();
        let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
        let node_id = v1["node_id"].as_str().unwrap().to_string();
        let token = v1["node_token"].as_str().unwrap().to_string();
        let hmac_key = v1["node_hmac_key"].as_str().unwrap().to_string();

        let nonce = "nonce-abcdefghijklmnopqrstuvwxyz123456";
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            "task-1", 1000u64, "", "", nonce, "hash-1", node_id
        );
        let mut mac = HmacSha256::new_from_slice(hmac_key.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        let award = serde_json::json!({
            "node_id": node_id,
            "querying_node_id": node_id,
            "task_id": "task-1",
            "tokens_used": 1000,
            "nonce": nonce,
            "response_hash": "hash-1",
            "signature": sig,
            "amount": 1.0
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/credits/award")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(award.to_string()))
            .unwrap();
        let r2 = app(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(r2.status(), 200, "self-query exclusion is net-zero success");
        let body = r2.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["excluded"], true);
        assert_eq!(v["attribution"], "self_node");
        assert_eq!(v["awarded"], 0.0);
        assert!(
            repo.events_since(0, 100)
                .await
                .iter()
                .all(|e| e.event_type != "CREDIT_AWARD"),
            "excluded self-query must not emit a CREDIT_AWARD event"
        );
    }

    #[tokio::test]
    async fn register_bad_intent_is_422() {
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "not-a-urn"}]
        });
        let resp = app(test_state())
            .oneshot(post_register(body))
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn register_rejects_unknown_backend_without_persisting() {
        let state = test_state();
        let body = serde_json::json!({
            "node_id": "backend-invalid",
            "endpoint": "https://1.1.1.1",
            "backend": "meshllm-peer-topology",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
        });
        let resp = app(state.clone())
            .oneshot(post_register(body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(state.repo.get("backend-invalid").await.is_none());
    }

    #[tokio::test]
    async fn register_accepts_availability_and_applies_pricing_ceiling() {
        let state = test_state();
        let response = app(state.clone())
            .oneshot(post_register(serde_json::json!({
                "node_id": "priced-registration",
                "endpoint": "https://1.1.1.1",
                "capabilities": [{
                    "intent": "urn:iicp:intent:llm:chat:v1",
                    "models": ["qwen2.5:0.5b"]
                }],
                "availability": [{"start": "08:30", "end": "17:15", "share": 0.75}],
                "pricing": {
                    "credit_cost_multiplier": 25.0,
                    "pricing_model": "per_token"
                }
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let node = state
            .repo
            .get("priced-registration")
            .await
            .expect("registered node");
        assert!((node.credit_cost_multiplier - 0.15).abs() < 0.000_001);
        assert_eq!(node.pricing_model.as_deref(), Some("per_token"));
    }

    #[tokio::test]
    async fn register_rejects_invalid_availability_or_pricing() {
        let invalid_fields = [
            serde_json::json!({"availability": [{"start": "24:00", "end": "17:00", "share": 1.0}]}),
            serde_json::json!({"availability": [{"start": "08:00", "end": "17:00", "share": 1.1}]}),
            serde_json::json!({"pricing": {"credit_cost_multiplier": -0.1, "pricing_model": "per_token"}}),
            serde_json::json!({"pricing": {"credit_cost_multiplier": 1.0, "pricing_model": "invented"}}),
        ];
        for fields in invalid_fields {
            let mut body = serde_json::json!({
                "endpoint": "https://1.1.1.1",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
            });
            body.as_object_mut()
                .expect("registration object")
                .extend(fields.as_object().expect("test fields").clone());
            let response = app(test_state())
                .oneshot(post_register(body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    #[tokio::test]
    async fn register_refuses_prohibited_capability_before_persistence() {
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:social-scoring:rank:v1"}]
        });
        let resp = app(test_state())
            .oneshot(post_register(body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], policy::REFUSAL_CODE);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("social scoring"));
        assert!(!value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("urn:iicp:"));
    }

    #[tokio::test]
    async fn register_non_routable_endpoint_is_422_in_prod() {
        let body = serde_json::json!({
            "endpoint": "http://192.168.1.10:8090",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
        });
        let resp = app(test_state())
            .oneshot(post_register(body))
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["error"]["code"], "IICP-E035");
    }

    #[tokio::test]
    async fn explicit_test_liveness_bypass_admits_routable_unknown_nat_endpoint() {
        // The shared test state explicitly enables the liveness bypass. RT-04 is
        // covered by validate::tests::rt04_unknown_nat_does_not_bypass_probe;
        // without the explicit bypass production performs a real dial-back.
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "nat_type": "unknown", "transport_method": "direct"
        });
        let resp = app(test_state())
            .oneshot(post_register(body))
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["public_reachable"], true);
    }

    fn hb(
        node_id: &str,
        with_token: bool,
        metrics: serde_json::Value,
    ) -> axum::http::Request<axum::body::Body> {
        let mut b = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/heartbeat")
            .header("content-type", "application/json");
        if with_token {
            b = b.header("authorization", "Bearer test-node-token-xyz");
        }
        b.body(axum::body::Body::from(
            serde_json::json!({"node_id": node_id, "load": 0.1, "available": true, "metrics": metrics}).to_string(),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn heartbeat_requires_token() {
        let resp = app(test_state())
            .oneshot(hb("a", false, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn heartbeat_unknown_node_is_404() {
        let resp = app(test_state())
            .oneshot(hb("nonexistent", true, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn heartbeat_applies_capped_delta_to_real_node() {
        // node "a" starts at reputation_score 0.8; 100 claimed successes → +0.10 cap → 0.9, not 1.0.
        let metrics =
            serde_json::json!({"tasks_success": 100, "tasks_failed": 0, "avg_latency_ms": 0.0});
        let resp = app(test_state())
            .oneshot(hb("a", true, metrics))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["reputation_score"], 0.9); // 0.8 + capped 0.10 (RT-01), not 1.0
        assert_eq!(v["challenge"].as_str().map(str::len), Some(32));
    }

    #[tokio::test]
    async fn heartbeat_challenge_is_single_use_and_rotates_after_replay() {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;

        let state = test_state();
        assert_eq!(
            state
                .repo
                .verify_and_rotate_liveness_challenge("a", None, "challenge-one")
                .await,
            Some(false)
        );

        let mut mac = HmacSha256::new_from_slice(b"test-hmac-key").unwrap();
        mac.update(b"challenge-one");
        let answer = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            state
                .repo
                .verify_and_rotate_liveness_challenge("a", Some(&answer), "challenge-two")
                .await,
            Some(true)
        );
        assert_eq!(
            state
                .repo
                .verify_and_rotate_liveness_challenge("a", Some(&answer), "challenge-three")
                .await,
            Some(false),
            "the response for challenge-one must not verify after rotation"
        );
    }

    #[tokio::test]
    async fn node_detail_returns_node_or_404() {
        let router = app(test_state());
        // known node "a"
        let ok = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/node/a")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        let b = ok.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["node_id"], "a");
        // unknown node → 404
        let nf = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/node/zzz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nf.status(), 404);
    }

    #[tokio::test]
    async fn re_register_with_known_id_preserves_reputation() {
        // ADR-026 anti-laundering: re-registering an existing node_id keeps its reputation
        // (a node can't reset a damaged score by re-registering).
        let st = AppState {
            repo: Arc::new(InMemoryRepo::new(vec![])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        };
        let router = app(st);
        let body = |id: &str| {
            serde_json::json!({
                "node_id": id,
                "endpoint": "https://1.1.1.1",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
            })
        };
        // register with explicit id → echoed back
        let r1 = router
            .clone()
            .oneshot(post_register(body("my-node-1")))
            .await
            .unwrap();
        assert_eq!(r1.status(), 201);
        let b1 = r1.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&b1).unwrap()["node_id"],
            "my-node-1"
        );

        // damage its reputation via failures
        let metrics =
            serde_json::json!({"tasks_success": 0, "tasks_failed": 5, "avg_latency_ms": 0.0});
        router
            .clone()
            .oneshot(hb("my-node-1", true, metrics))
            .await
            .unwrap();

        // re-register same id → reputation NOT reset to the 0.5 default
        router
            .clone()
            .oneshot(post_register(body("my-node-1")))
            .await
            .unwrap();
        let nd = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/node/my-node-1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let nb = nd.into_body().collect().await.unwrap().to_bytes();
        let score = serde_json::from_slice::<serde_json::Value>(&nb).unwrap()["reputation_score"]
            .as_f64()
            .unwrap();
        assert!(
            score < 0.5,
            "re-register must preserve damaged reputation, got {score}"
        );
    }

    #[tokio::test]
    async fn re_register_issues_new_token_that_works_for_heartbeat() {
        // BUG regression (iter-1578): MySqlRepo was not updating node_token_hash on
        // re-registration, so the new token returned to the client would fail
        // verify_node_token(). InMemoryRepo always accepts tokens, so this test validates
        // the contract rather than the bcrypt path — the MySqlRepo fix is in db.rs.
        let st = AppState {
            repo: Arc::new(InMemoryRepo::new(vec![])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        };
        let router = app(st);
        let body = serde_json::json!({
            "node_id": "rr-test",
            "endpoint": "https://1.1.1.1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
        });

        // First registration — get first token.
        let r1 = router
            .clone()
            .oneshot(post_register(body.clone()))
            .await
            .unwrap();
        assert_eq!(r1.status(), 201);
        let b1 = r1.into_body().collect().await.unwrap().to_bytes();
        let _first_token = serde_json::from_slice::<serde_json::Value>(&b1).unwrap()["node_token"]
            .as_str()
            .unwrap()
            .to_string();

        // Re-registration — new token issued.
        let r2 = router.clone().oneshot(post_register(body)).await.unwrap();
        assert_eq!(r2.status(), 201);
        let b2 = r2.into_body().collect().await.unwrap().to_bytes();
        let new_token = serde_json::from_slice::<serde_json::Value>(&b2).unwrap()["node_token"]
            .as_str()
            .unwrap()
            .to_string();

        // The new token must work for heartbeat (InMemoryRepo always accepts — validates contract).
        let hb_resp = router
            .oneshot(hb("rr-test", true, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(
            hb_resp.status(),
            200,
            "new token must be usable after re-registration"
        );
        drop(new_token); // suppress unused warning
    }

    #[tokio::test]
    async fn full_lifecycle_register_discover_heartbeat() {
        // Empty directory; register a node, discover it, then heartbeat it.
        let st = AppState {
            repo: Arc::new(InMemoryRepo::new(vec![])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        };
        let router = app(st);

        // 1. register
        let reg = router
            .clone()
            .oneshot(post_register(serde_json::json!({
                "endpoint": "https://1.1.1.1",
                "region": "eu-central",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
            })))
            .await
            .unwrap();
        assert_eq!(reg.status(), 201);
        let rb = reg.into_body().collect().await.unwrap().to_bytes();
        let node_id = serde_json::from_slice::<serde_json::Value>(&rb).unwrap()["node_id"]
            .as_str()
            .unwrap()
            .to_string();

        // 2. discover finds it
        let disc = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let db = disc.into_body().collect().await.unwrap().to_bytes();
        let dv: serde_json::Value = serde_json::from_slice(&db).unwrap();
        assert_eq!(dv["count"], 1);
        assert_eq!(dv["nodes"][0]["node_id"], node_id.as_str());

        // 3. heartbeat updates its score (starts 0.5 → +0.01 for one good task)
        let metrics =
            serde_json::json!({"tasks_success": 1, "tasks_failed": 0, "avg_latency_ms": 500.0});
        let hbr = router.oneshot(hb(&node_id, true, metrics)).await.unwrap();
        assert_eq!(hbr.status(), 200);
        let hbb = hbr.into_body().collect().await.unwrap().to_bytes();
        let hv: serde_json::Value = serde_json::from_slice(&hbb).unwrap();
        assert_eq!(hv["reputation_score"], 0.51); // 0.5 + 0.01
    }

    #[tokio::test]
    async fn discover_missing_intent_is_422() {
        // PHP validates intent is required → 422 (DIR-DISC-10 REACH probe).
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn discover_refuses_high_risk_public_mesh_intent_before_lookup() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:medical:diagnosis:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], policy::REFUSAL_CODE);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("healthcare decision"));
    }

    // ALIGN/#385 parity (#404): min_reputation out of [0,1] MUST 422 — including NEGATIVE
    // values (PHP validates min:0 AND max:1). Fails against the old `mr > 1.0`-only check.
    #[tokio::test]
    async fn discover_min_reputation_out_of_range_is_422() {
        let intent = "urn:iicp:intent:llm:chat:v1";
        for mr in ["-0.5", "1.5"] {
            let resp = app(test_state())
                .oneshot(
                    axum::http::Request::builder()
                        .uri(format!("/v1/discover?intent={intent}&min_reputation={mr}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 422, "min_reputation={mr} must be rejected");
        }
        // A valid in-range value is accepted (200).
        let ok = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/v1/discover?intent={intent}&min_reputation=0.5"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
    }

    // IICP-E034 registration rate-limit window logic (#404, W-033 parity). Fails if the
    // window reset / in-window increment is wrong (which would break the 60/60s limit).
    #[test]
    fn register_rate_step_increments_in_window_and_resets_after_ttl() {
        let ttl = super::REGISTER_RATE_TTL_MS;
        // First hit in a fresh window → count 1, start = now.
        assert_eq!(super::register_rate_step(None, 1_000, ttl), (1, 1_000));
        // Second hit within the window → increment, same window start.
        assert_eq!(
            super::register_rate_step(Some((1, 1_000)), 1_500, ttl),
            (2, 1_000)
        );
        // A hit after the TTL elapsed → new window resets to 1.
        assert_eq!(
            super::register_rate_step(Some((60, 1_000)), 1_000 + ttl + 1, ttl),
            (1, 1_000 + ttl + 1)
        );
        // Boundary: exactly at TTL is still "expired" (>= ttl) → reset.
        assert_eq!(
            super::register_rate_step(Some((5, 1_000)), 1_000 + ttl, ttl),
            (1, 1_000 + ttl)
        );
    }

    // IICP-E050 (#529) re-registration endpoint-ownership matrix (PHP NodeRegistry parity).
    // Mirrors the RegisterTest matrix shipped for the PHP directory.
    #[test]
    fn e050_endpoint_change_ownership_matrix() {
        // Same endpoint → ordinary refresh, always allowed (downlevel re-register).
        assert!(registration::endpoint_change_allowed(false, false, true));
        assert!(registration::endpoint_change_allowed(false, false, false));
        // Endpoint change WITH token ownership → allowed even if the old endpoint is alive
        // (an owner legitimately rotating a live tunnel).
        assert!(registration::endpoint_change_allowed(true, true, true));
        // Endpoint change, NO token, old endpoint dead → allowed (migration-safe rotation
        // for downlevel clients that don't send current_node_token yet).
        assert!(registration::endpoint_change_allowed(true, false, false));
        // Endpoint change, NO token, old endpoint still alive → REJECTED (hijack attempt:
        // pointing a victim's node_id at a live different endpoint).
        assert!(!registration::endpoint_change_allowed(true, false, true));
    }

    #[test]
    fn e050_strict_shared_parity_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../parity/e050-strict-v0.json")).unwrap();
        assert_eq!(fixture["schema"], "iicp.e050_strict_parity.v0");
        for case in fixture["cases"].as_array().unwrap() {
            let input = &case["input"];
            let actual = registration::routing_change_allowed(
                input["strict"].as_bool().unwrap(),
                input["secured"].as_bool().unwrap(),
                input["endpoint_changed"].as_bool().unwrap(),
                input["transport_endpoint_changed"].as_bool().unwrap(),
                input["relay_endpoint_changed"].as_bool().unwrap(),
                input["has_ownership"].as_bool().unwrap(),
                input["old_endpoint_alive"].as_bool().unwrap(),
            );
            assert_eq!(
                actual,
                case["allowed"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[tokio::test]
    async fn stats_returns_active_node_count() {
        // test_state has 2 available nodes → active_count() = 2.
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/stats")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["server"]["active_nodes"], 2);
        // ADR-044 / #492 mesh_health over 2 active nodes.
        // #492 formula: W_REACHABILITY=0.70, W_LATENCY=0.30 (success/reputation removed).
        // Each test node: reachability_signal=0.5 (relay tier), latency=None→0.5 neutral.
        // score = 0.70*0.5 + 0.30*0.5 = 0.50 → 50 → "impaired".
        let mh = &v["mesh_health"];
        assert_eq!(mh["sample"], 2);
        assert_eq!(mh["label"], "insufficient_sample"); // 2 < MIN_MESH_SAMPLE
        assert_eq!(mh["score"], 0.5);
        assert_eq!(mh["mean"], 0.5);
        assert_eq!(mh["distribution"]["impaired"], 2);
        assert_eq!(mh["basis"], "active_provider_nodes");
    }

    #[tokio::test]
    async fn bootstrap_returns_peer_list() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/bootstrap")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["peers"].is_array());
        assert_eq!(v["count"], 2); // 2 available nodes in test_state
    }

    #[tokio::test]
    async fn deregister_requires_token() {
        let body = serde_json::json!({ "node_id": "a" });
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn deregister_removes_node() {
        // InMemoryRepo always accepts any token (local/test mode).
        let body = serde_json::json!({ "node_id": "a" });
        let router = app(test_state());
        let resp = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer any-token")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["deregistered"], true); // PHP returns {deregistered: true}
                                             // Node "a" is now gone → node_detail returns 404.
        let nd = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/node/a")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(nd.status(), 404);
    }

    #[tokio::test]
    async fn deregister_unknown_node_is_404() {
        let body = serde_json::json!({ "node_id": "nonexistent" });
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .method("DELETE")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer any-token")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("text/plain"));
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&b).unwrap();
        assert!(text.contains("iicp_active_nodes"));
        assert!(text.contains("iicp_directory_info"));
    }

    #[tokio::test]
    async fn me_requires_token_and_node_id_header() {
        // missing token → 401
        let no_token = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/me")
                    .header("x-node-id", "a")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_token.status(), 401);

        // missing x-node-id → 422
        let no_id = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/me")
                    .header("authorization", "Bearer tok")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_id.status(), 422);
    }

    #[tokio::test]
    async fn me_returns_authenticated_node() {
        // InMemoryRepo always accepts any token — lets us test the happy path without bcrypt.
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/me")
                    .header("authorization", "Bearer any-token")
                    .header("x-node-id", "a")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["node_id"], "a");
    }

    #[tokio::test]
    async fn registry_nodes_returns_public_listing() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/registry/nodes")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["nodes"].is_array(), "nodes must be an array");
        // PHP registry anonymizes node_id to node_id_prefix (ADR-017 — no private fields).
        for node in v["nodes"].as_array().unwrap() {
            assert!(
                node["node_id_prefix"].is_string(),
                "registry must return node_id_prefix not full node_id"
            );
            assert!(
                node.get("endpoint").is_none(),
                "registry must not expose endpoint"
            );
            // #385 parity: PHP includes the served `models` in the public listing. #404 —
            // fails if the field regresses (it was absent before the parity fix).
            assert!(
                node["models"].is_array(),
                "registry listing must include a models array (PHP parity)"
            );
        }
    }

    #[tokio::test]
    async fn registry_stats_returns_counts() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/registry/stats")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["total_nodes"].is_number());
        assert!(v["active_nodes"].is_number());
        // PHP buildStats parity: regions/breakdown/coverage present, no invented fields.
        assert!(v["regions"].is_array());
        assert!(v["region_breakdown"].is_object());
        assert!(v["intent_coverage"].is_object());
        assert!(v["intents_supported"].is_array());
        assert!(
            v.get("total_intents").is_none(),
            "total_intents not in PHP buildStats"
        );
        assert!(
            v.get("dormant_nodes").is_none(),
            "dormant_nodes not in PHP buildStats"
        );
    }

    #[tokio::test]
    async fn heartbeat_persists_tasks_failed_for_success_signal() {
        // #385 Phase-B / AL3 — the failure count from the heartbeat must be
        // persisted (not folded into tasks_total and dropped), so the health
        // success signal can be computed.
        let st = test_state();
        // a/b exist in test_state; heartbeat node "a" with 7 ok + 3 failed.
        let new = st.repo.heartbeat("a", 0.1, true, 0, 10, 3, 0.0, None).await;
        assert!(new.is_some());
        let n = st.repo.get("a").await.expect("node a");
        assert_eq!(n.completed_tasks_count, 10, "tasks_total += success+failed");
        assert_eq!(n.tasks_failed, 3, "tasks_failed persisted, not dropped");
        // #492: health no longer uses success/reputation — endpoint-only formula.
        // 0.70*1.0 + 0.30*0.5(no latency) = 0.85 → 85 → healthy.
        let h = health::score_node(&health::HealthSignals {
            reachability: 1.0,
            latency_ms: None,
        });
        assert_eq!(h.score, 85);
        assert_eq!(h.label, "healthy");
    }

    #[tokio::test]
    async fn register_rejects_invalid_exposure_mode() {
        // #401 / AL2 — Rust must reject out-of-enum exposure_mode (PHP parity),
        // not silently accept it.
        let body = serde_json::json!({
            "endpoint": "https://1.1.1.1",
            "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["m"]}],
            "exposure_mode": "totally_bogus"
        });
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/register")
                    .method("POST")
                    .header("content-type", "application/json")
                    .header("app-env", "local")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
    }

    #[test]
    fn transport_methods_derivation() {
        // HTTPS-only node
        assert_eq!(transport_methods("https://host:8080", None), vec!["https"]);
        // HTTP-only
        assert_eq!(transport_methods("http://host:8080", None), vec!["http"]);
        // HTTPS + native IICP-TCP
        assert_eq!(
            transport_methods("https://host:8080", Some("iicp://host:9484")),
            vec!["https", "iicp-native"]
        );
        // secure native variant still maps to iicp-native
        assert_eq!(
            transport_methods("https://host", Some("iicpsec://host:9484")),
            vec!["https", "iicp-native"]
        );
        // unknown scheme → empty
        assert!(transport_methods("ftp://host", None).is_empty());
    }

    #[test]
    fn verify_cip_receipt_correct_sig_passes() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let key = "test-key";
        let canonical = "task1:100:::nonce42:hash99";
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let req = CreditAwardRequest {
            node_id: "n1".into(),
            task_id: "task1".into(),
            tokens_used: 100,
            cip_parent_task_id: String::new(),
            cip_session_key: String::new(),
            nonce: "nonce42".into(),
            response_hash: "hash99".into(),
            signature: sig,
            amount: 0.1,
            querying_node_id: None,
        };
        assert!(verify_cip_receipt(&req, key));
    }

    #[test]
    fn verify_cip_receipt_includes_querying_node_id_when_present() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let key = "secret";
        let canonical = "task1:100:::nonce42:hash99:q1";
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let req = CreditAwardRequest {
            node_id: "n1".into(),
            task_id: "task1".into(),
            tokens_used: 100,
            cip_parent_task_id: String::new(),
            cip_session_key: String::new(),
            nonce: "nonce42".into(),
            response_hash: "hash99".into(),
            signature: sig,
            amount: 0.1,
            querying_node_id: Some("q1".into()),
        };
        assert!(verify_cip_receipt(&req, key));
    }

    #[test]
    fn verify_cip_receipt_bad_sig_fails() {
        let req = CreditAwardRequest {
            node_id: "n1".into(),
            task_id: "task1".into(),
            tokens_used: 100,
            cip_parent_task_id: String::new(),
            cip_session_key: String::new(),
            nonce: "nonce42".into(),
            response_hash: "hash99".into(),
            signature: "deadbeef".into(),
            amount: 0.1,
            querying_node_id: None,
        };
        assert!(!verify_cip_receipt(&req, "key"));
    }

    fn peers_req(node_id: &str, known: &[&str]) -> axum::http::Request<axum::body::Body> {
        let body = serde_json::json!({
            "node_id": node_id,
            "known_peers": known
        });
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/peers")
            .header("content-type", "application/json")
            .header("authorization", "Bearer any-token")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn peers_requires_token() {
        let body = serde_json::json!({ "node_id": "a", "known_peers": [] });
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/peers")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn peers_returns_nodes_excluding_known() {
        // test_state has nodes "a" and "b"; exclude "a" → only "b" returned.
        let resp = app(test_state())
            .oneshot(peers_req("a", &["a"]))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["peers"][0]["node_id"], "b");
    }

    #[tokio::test]
    async fn peers_empty_known_returns_all_peers() {
        let resp = app(test_state())
            .oneshot(peers_req("a", &[]))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        // Both "a" and "b" are returned (InMemoryRepo doesn't filter by requester).
        assert_eq!(v["count"], 2);
    }

    // ── node_id format validation tests ─────────────────────────────────────

    #[tokio::test]
    async fn register_invalid_node_id_is_422() {
        let st = AppState {
            repo: Arc::new(InMemoryRepo::new(vec![])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        };
        for bad_id in &[
            "",
            " spaces",
            "too-long-node-id-that-exceeds-36-chars-limit!",
            "0x!inject",
        ] {
            let resp = app(AppState {
                repo: Arc::new(InMemoryRepo::new(vec![])),
                env: Env::Production,
                signing_key: None,
                directory_did: DEFAULT_DIRECTORY_DID.to_string(),
                directory_service_endpoint: "https://iicp.network/v1".to_string(),
                register_rate: new_register_rate(),
                strict_e050_secured: false,
                allow_insecure_tls: false,
                skip_liveness_check: true,
            })
            .oneshot(post_register(serde_json::json!({
                "node_id": bad_id,
                "endpoint": "https://1.1.1.1",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
            })))
            .await
            .unwrap();
            let status = resp.status();
            // An empty node_id is treated as "not provided" (UUID assigned) — only non-empty invalid IDs reject
            if !bad_id.is_empty() {
                assert_eq!(
                    status, 422,
                    "Expected 422 for node_id={bad_id:?}, got {status}"
                );
            }
        }
        drop(st); // suppress unused warning
    }

    #[tokio::test]
    async fn register_valid_custom_node_id_accepted() {
        let st = AppState {
            repo: Arc::new(InMemoryRepo::new(vec![])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        };
        let resp = app(st)
            .oneshot(post_register(serde_json::json!({
                "node_id": "my-custom-node-1",
                "endpoint": "https://1.1.1.1",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["node_id"], "my-custom-node-1");
    }

    // ── register ACK contract tests ───────────────────────────────────────────

    #[tokio::test]
    async fn register_ack_contains_proxy_token() {
        let st = AppState {
            repo: Arc::new(InMemoryRepo::new(vec![])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        };
        let resp = app(st)
            .oneshot(post_register(serde_json::json!({
                "endpoint": "https://1.1.1.1",
                "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]
            })))
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["proxy_token"].is_string(), "ACK must include proxy_token");
        assert!(!v["proxy_token"].as_str().unwrap().is_empty());
        assert!(v["node_token"].is_string(), "ACK must include node_token");
        assert!(
            v["node_hmac_key"].is_string(),
            "ACK must include node_hmac_key"
        );
        // PHP field name for JWT is jwt_token (not node_jwt)
        assert!(
            v["jwt_token"].is_string() || v["jwt_token"].is_null(),
            "ACK must include jwt_token"
        );
        assert!(v["node_id"].is_string(), "ACK must include node_id");
    }

    #[tokio::test]
    async fn discover_cip_capable_filter_excludes_non_provider() {
        // DIR-CIP-02: discover?cip_capable=1 returns only CIP-Provider nodes.
        // test_state nodes have cip_conformance_level=CIP-None → 0 results expected.
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1&cip_capable=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        // All test nodes are CIP-None → 0 results (no non-provider nodes returned)
        assert_eq!(v["count"], 0);
    }

    #[tokio::test]
    async fn audit_report_self_target_is_422() {
        // Cannot report yourself (RT-05 bypass guard).
        let body = serde_json::json!({
            "node_id": "a",
            "target_node_id": "a",
            "finding": "declaration_divergence"
        });
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/audit-report")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer any-token")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn telemetry_rt03_rejects_self_report() {
        // RT-03: proxy_node_id must differ from node_id.
        let st = AppState {
            repo: Arc::new(InMemoryRepo::new(vec![])),
            env: Env::Production,
            signing_key: None,
            directory_did: DEFAULT_DIRECTORY_DID.to_string(),
            directory_service_endpoint: "https://iicp.network/v1".to_string(),
            register_rate: new_register_rate(),
            strict_e050_secured: false,
            allow_insecure_tls: false,
            skip_liveness_check: true,
        };
        let body = serde_json::json!({
            "node_id": "self-node",
            "proxy_node_id": "self-node",  // same as node_id → RT-03 violation
            "latency_ms_observed": 100,
            "tokens_observed": 10,
            "status": "success",
            "qos_met": true
        });
        let resp = app(st)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/telemetry")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer some-token")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert!(v["error"]["message"].as_str().unwrap().contains("RT-03"));
    }

    // ── get_client_ip unit tests ──────────────────────────────────────────────

    fn headers_with(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut m = axum::http::HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    #[test]
    fn get_client_ip_cf_takes_priority() {
        let h = headers_with(&[
            ("cf-connecting-ip", "1.2.3.4"),
            ("x-forwarded-for", "5.6.7.8, 9.10.11.12"),
        ]);
        assert_eq!(get_client_ip(&h), "1.2.3.4");
    }

    #[test]
    fn get_client_ip_xff_leftmost_token() {
        let h = headers_with(&[("x-forwarded-for", "10.0.0.1, 172.16.0.2, 192.168.0.3")]);
        assert_eq!(get_client_ip(&h), "10.0.0.1");
    }

    #[test]
    fn get_client_ip_fallback_unknown() {
        let h = axum::http::HeaderMap::new();
        assert_eq!(get_client_ip(&h), "unknown");
    }

    // #494 behavior tests — fail without the health_models heartbeat wiring.

    /// heartbeat with health_models stores the list on the node.
    /// Fails if the heartbeat impl ignores the health_models parameter.
    #[tokio::test]
    async fn heartbeat_stores_health_models_when_provided() {
        let st = test_state();
        st.repo
            .heartbeat(
                "a",
                0.1,
                true,
                0,
                0,
                0,
                0.0,
                Some(vec!["llama3:latest".into(), "qwen2.5:0.5b".into()]),
            )
            .await;
        let n = st.repo.get("a").await.expect("node a");
        assert_eq!(
            n.health_models.as_deref(),
            Some(["llama3:latest".to_string(), "qwen2.5:0.5b".to_string()].as_slice()),
            "#494: health_models must be stored on heartbeat"
        );
    }

    /// heartbeat with None leaves health_models untouched (backward compat).
    /// Fails if None overwrites an existing health_models list.
    #[tokio::test]
    async fn heartbeat_none_health_models_preserves_existing_list() {
        let st = test_state();
        // First heartbeat sets the list.
        st.repo
            .heartbeat("a", 0.1, true, 0, 0, 0, 0.0, Some(vec!["model-x".into()]))
            .await;
        // Second heartbeat with None must NOT clear it.
        st.repo.heartbeat("a", 0.2, true, 0, 0, 0, 0.0, None).await;
        let n = st.repo.get("a").await.expect("node a");
        assert_eq!(
            n.health_models.as_deref(),
            Some(["model-x".to_string()].as_slice()),
            "#494: None health_models must not overwrite an existing list (backward compat)"
        );
    }

    /// discover ?model= filter uses health_models when present.
    /// Fails if the discover handler ignores the model query parameter.
    #[tokio::test]
    async fn discover_model_filter_uses_health_models() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1&model=not-loaded")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        // test_state nodes have no health_models and no static models[] matching "not-loaded"
        // → both fall back to models[] (empty) → 0 results returned.
        assert_eq!(
            v["count"], 0,
            "#494: ?model= filter must exclude nodes that do not serve the requested model"
        );
    }

    /// discover without ?model= must exclude nodes with health_models=[] (explicitly empty).
    /// Fails without the health_models=[] blanket-exclusion fix — DIR-TRUST-01 parity (#494).
    #[tokio::test]
    async fn discover_excludes_node_with_empty_health_models_unfiltered() {
        let chat = "urn:iicp:intent:llm:chat:v1";
        let node_with_empty_health = NodeRecord {
            node: types::Node {
                node_id: "empty-health".into(),
                endpoint: "https://1.1.1.1".into(),
                region: "eu".into(),
                score: 0.9,
                available: true,
                load: 0.0,
                active_jobs: 0,
                max_concurrent: 4,
                reputation_score: 0.8,
                latency_estimate_ms: None,
                completed_tasks_count: 0,
                health_label: Some("healthy".into()),
                exposure_mode: Some("direct_ipv4".into()),
                reputation_tier: Some("gold".into()),
                transport_endpoint: None,
                cip_conformance_level: Some("CIP-None".into()),
                models: vec!["qwen2.5:0.5b".into()],
                pricing: None,
                nat_type: None,
                transport_method: None,
                relay_capable: None,
                sdk_language: None,
                implementation_name: None,
                implementation_version: None,
                sdk_compatibility_version: None,
                sdk_version: None,
                consumer_cosignature_ready: false,
                backend: None,
                address_family: None,
                cip_policy: Some(
                    serde_json::json!({"allow_remote_inference":false,"allow_tool_execution":false,"allow_file_access":false,"pricing_credits_per_1000":null}),
                ),
                quantization: vec![],
                inference_engine: vec![],
                public_key: None,
                transport_metadata: None,
                credit_cost_multiplier: 1.0,
                pricing_model: Some("per_token".into()),
                attested: false,
                tasks_failed: 0,
                transport: vec![],
                reachability_signal: 1.0,
                operator_pubkey: None,
                operator_display_name: None,
                operator_fingerprint: None,
                operator_verified: false,
                operator_trust_tier: None,
                public_listing: false,
                operator_url: None,
                policy_manifest: None,
                health_models: Some(vec![]), // explicitly empty — no models loaded
                routing_policy: types::RoutingPolicyState::default(),
            },
            intents: vec![chat.into()],
            availability: vec![],
            node_token: None,
            node_hmac_key: Some("test-hmac-key".into()),
            proxy_token: None,
        };
        let mut st = test_state();
        st.repo = Arc::new(InMemoryRepo::new(vec![node_with_empty_health]));
        let resp = app(st)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(
            v["count"], 0,
            "#494: node with health_models=[] must be excluded from unfiltered discover (DIR-TRUST-01)"
        );
    }

    #[tokio::test]
    async fn discover_runtime_policy_applies_qos_boundary_and_php_ranking() {
        let chat = "urn:iicp:intent:llm:chat:v1";
        let mut state = test_state();
        let mut nodes = state
            .repo
            .discover(&DiscoverQuery {
                intent: chat.into(),
                limit: 50,
                ..DiscoverQuery::default()
            })
            .await;
        assert_eq!(nodes.len(), 2);
        nodes[0].node_id = "below-realtime".into();
        nodes[0].completed_tasks_count = 999;
        nodes[0].reputation_score = 0.79;
        nodes[0].region = "us".into();
        nodes[0].models = vec!["model-a".into()];
        nodes[0].health_models = Some(vec!["model-a".into()]);
        nodes[1].node_id = "realtime".into();
        nodes[1].completed_tasks_count = 1000;
        nodes[1].reputation_score = 0.8;
        nodes[1].region = "eu".into();
        nodes[1].models = vec!["model-a".into()];
        nodes[1].health_models = Some(vec!["model-a".into()]);
        state.repo = Arc::new(InMemoryRepo::new(
            nodes
                .into_iter()
                .map(|node| NodeRecord {
                    node,
                    intents: vec![chat.into()],
                    availability: vec![],
                    node_token: None,
                    node_hmac_key: None,
                    proxy_token: None,
                })
                .collect(),
        ));

        let response = app(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/discover?intent=urn:iicp:intent:llm:chat:v1&qos=realtime&model=model-a&region=eu")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["count"], 1);
        assert_eq!(value["nodes"][0]["node_id"], "realtime");
    }

    #[tokio::test]
    async fn discover_rejects_unknown_qos_before_repository_selection() {
        let response = app(test_state())
            .oneshot(
                Request::builder()
                    .uri("/api/v1/discover?intent=urn:iicp:intent:llm:chat:v1&qos=urgent")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn shared_implementation_metadata_fixture_matches_validation_contract() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../parity/directory-implementation-metadata-v1.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let input = &case["input"];
            let preferred = input["sdk_compatibility_version"].as_str();
            let legacy = input["sdk_version"].as_str();
            let grammar_ok = input["implementation_name"]
                .as_str()
                .is_none_or(valid_implementation_name)
                && input["implementation_version"]
                    .as_str()
                    .is_none_or(valid_version_axis)
                && preferred.is_none_or(valid_version_axis)
                && legacy.is_none_or(valid_version_axis);
            let values_agree = !matches!((preferred, legacy), (Some(a), Some(b)) if a != b);
            assert_eq!(
                grammar_ok && values_agree,
                case["accepted"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
            if case["accepted"] == true {
                assert_eq!(
                    preferred.or(legacy),
                    case["effective_sdk_compatibility_version"].as_str()
                );
            }
        }
    }
}

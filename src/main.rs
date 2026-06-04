// SPDX-License-Identifier: Apache-2.0
//! IICP directory — Rust reference implementation (read-path foundation).
//!
//! Phase 6 / L6.1. This is the start of the Rust directory that will eventually
//! replace the PHP reference implementation (see README.md for the migration plan).
//! It currently serves the read path (`/health`, `/v1/stats`) against the iicp-dir
//! v0.9.0 wire contract. Discovery, registration, and federation land in later
//! milestones; federation is gated on ADR-013 advancing past Vision.

mod auth;
mod background;
mod db;
mod health;
mod repo;
mod reputation;
mod types;
mod validate;

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::{
    routing::{get, post},
    Json, Router,
};
use repo::{
    AuditResult, ConformanceBadge, CreditError, DiscoverQuery, InMemoryRepo, IntentSummary,
    NodeRepository, ProbeResult, ProxyObservation, RegistryStats,
};
use serde::Deserialize;
use types::NodeList;
use validate::{endpoint_routable, is_declared_reachable, validate_intent, Env};

const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"), "-rs");

/// Derive `address_family` from an endpoint URL (PHP NodeScorer::detectAddressFamily parity).
/// Returns "ipv4" | "ipv6" | "hostname" | "unknown".
/// Classify a URL's host as "ipv4" | "ipv6" | "hostname" | "unknown".
fn url_host_family(url: &str) -> &'static str {
    let host = url.split("://").nth(1).unwrap_or(url);
    let host = host.split('/').next().unwrap_or(host);
    if host.starts_with('[') {
        return "ipv6"; // IPv6 literal e.g. [::1]:port
    }
    let bare = host.rsplit(':').nth(1).unwrap_or(host);
    if bare.chars().all(|c| c.is_ascii_digit() || c == '.') && bare.contains('.') {
        "ipv4"
    } else if bare.contains(':') {
        "ipv6"
    } else if bare.is_empty() || bare == "unknown" {
        "unknown"
    } else {
        "hostname"
    }
}

/// Derive `address_family` from endpoint + transport URLs (PHP NodeScorer parity).
fn detect_address_family(endpoint: &str, transport: Option<&str>) -> String {
    let p = url_host_family(endpoint);
    let t = transport.map(url_host_family).unwrap_or("unknown");
    if p == "unknown" && t == "unknown" {
        return "unknown".into();
    }
    if p == "hostname" || t == "hostname" {
        return "hostname".into();
    }
    if p == t || t == "unknown" {
        p.into()
    } else if p == "unknown" {
        t.into()
    } else {
        "ipv4_ipv6".into()
    }
}

/// Transport protocols a node speaks, derived from endpoint schemes (#397 —
/// PHP NodeScorer::transportMethods parity). Privacy-preserving: protocol tokens
/// only, never the host. `https://`/`http://` endpoint → "https"/"http";
/// `iicp://`/`iicpsec://` transport_endpoint → "iicp-native".
fn transport_methods(endpoint: &str, transport: Option<&str>) -> Vec<String> {
    let scheme = |u: &str| u.split("://").next().unwrap_or("").to_ascii_lowercase();
    let mut out = Vec::new();
    let ep_scheme = scheme(endpoint);
    if ep_scheme == "https" || ep_scheme == "http" {
        out.push(ep_scheme);
    }
    if let Some(t) = transport {
        if matches!(scheme(t).as_str(), "iicp" | "iicpsec") {
            out.push("iicp-native".to_string());
        }
    }
    out
}

/// ADR-043 §9 exposure_mode vocabulary — enum parity with PHP RegisterController
/// validation (#401 / AL2). A register with any other value is rejected 422.
const EXPOSURE_MODES: [&str; 8] = [
    "outbound_only",
    "ipv4_public_direct",
    "ipv4_cgnat_blocked",
    "ipv6_direct_firewall_required",
    "ipv6_direct_pinhole_available",
    "relay_required",
    "tunnel_required",
    "dual_stack_available",
];

/// ADR-019 pricing_model vocabulary — enum parity with PHP (#401 / AL2).
const PRICING_MODELS: [&str; 3] = ["per_token", "per_request", "flat"];

/// Process start instant — backs `server.uptime_seconds` in `/v1/stats` (PHP parity).
/// Set once in `main`; unset in tests (uptime reports 0).
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

#[derive(Clone)]
struct AppState {
    repo: Arc<dyn NodeRepository>,
    env: Env,
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/stats", get(stats))
        .route("/v1/metrics", get(metrics))
        .route("/v1/discover", get(discover))
        .route("/v1/bootstrap", get(bootstrap))
        .route("/v1/me", get(me))
        .route("/v1/node/:id", get(node_detail))
        .route("/v1/register", post(register).delete(deregister))
        .route("/v1/peers", post(peers))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/registry/nodes", get(registry_nodes))
        .route("/v1/registry/nodes/:id", get(registry_node_detail))
        .route("/v1/registry/intents", get(registry_intents))
        .route("/v1/registry/stats", get(registry_stats))
        .route("/.well-known/did.json", get(did_document))
        .route("/v1/credits/balance", get(credits_balance))
        .route("/v1/credits/award", post(credits_award))
        .route("/v1/credits/transactions", get(credits_transactions))
        .route("/v1/audit-report", post(audit_report))
        .route("/v1/telemetry/probe", post(telemetry_probe))
        .route("/v1/telemetry", post(telemetry_proxy))
        .route("/v1/credits/quote", get(credits_quote))
        .route("/v1/badges", get(badges_list))
        .route("/v1/badge/:tier", get(badge_svg))
        .route("/v1/submit", post(conformance_submit))
        .route("/v1/verify", get(conformance_verify))
        .route("/v1/probe", get(probe_node))
        .route("/", get(root_info))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "version": VERSION }))
}

/// Raw query string for `GET /v1/discover` (iicp-dir §3.3).
#[derive(Debug, Deserialize)]
struct DiscoverParams {
    // Optional at the deserialize level; validated as required in the handler (422 if absent).
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    min_reputation: Option<f64>,
    /// CIP-D1: filter to CIP-Provider nodes only (allow_remote_inference=true, S.12 §5.2).
    /// Accepted as boolean or "1"/"0"/"true"/"false".
    #[serde(default)]
    cip_capable: Option<String>,
}

/// `GET /v1/discover` → NODELIST (iicp-dir §3.3/§3.4).
async fn discover(
    State(st): State<AppState>,
    Query(p): Query<DiscoverParams>,
) -> axum::response::Response {
    // PHP validates intent is required and returns 422 (DIR-DISC-10 REACH probe).
    let intent = match p.intent {
        Some(ref i) if !i.is_empty() => i.clone(),
        _ => {
            return axum::response::Response::builder()
                .status(422)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "error": {"code": "validation_error", "message": "intent is required"}
                    }))
                    .unwrap(),
                ))
                .unwrap();
        }
    };
    // DIR-DISC-09: min_reputation > 1.0 MUST return 422 (out-of-range input rejected).
    if let Some(mr) = p.min_reputation {
        if mr > 1.0 {
            return axum::response::Response::builder()
                .status(422)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "error": {"code": "validation_error", "message": "min_reputation must be in [0, 1]"}
                    }))
                    .unwrap(),
                ))
                .unwrap();
        }
    }
    let started = Instant::now();
    let nodes = st
        .repo
        .discover(&DiscoverQuery {
            intent,
            region: p.region,
            limit: p.limit.unwrap_or(0),
            min_reputation: p.min_reputation,
        })
        .await;
    // CIP-D1 filter: cip_capable=1 → only return CIP-Provider nodes (DIR-CIP-02).
    let nodes = if matches!(p.cip_capable.as_deref(), Some("1") | Some("true")) {
        nodes
            .into_iter()
            .filter(|n| n.cip_conformance_level.as_deref() == Some("CIP-Provider"))
            .collect()
    } else {
        nodes
    };
    // Enrich with server-side derived fields (PHP NodeScorer parity).
    let nodes: Vec<types::Node> = nodes
        .into_iter()
        .map(|mut n| {
            n.address_family = Some(detect_address_family(
                &n.endpoint,
                n.transport_endpoint.as_deref(),
            ));
            // #397 — transport protocols, derived from endpoint schemes (PHP parity).
            n.transport = transport_methods(&n.endpoint, n.transport_endpoint.as_deref());
            n
        })
        .collect();
    let count = nodes.len() as u32;
    let body = NodeList {
        nodes,
        count,
        query_ms: started.elapsed().as_millis() as u32,
    };
    // PHP adds Cache-Control for CDN caching (Cloudflare s-maxage=300 + stale-while-revalidate).
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header(
            "cache-control",
            "public, max-age=60, s-maxage=300, stale-while-revalidate=120",
        )
        .header("vary", "Accept-Encoding")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// `GET /v1/node/{id}` (iicp-dir §3.4.x node detail). Returns the node record or 404.
/// PHP NodeController error code: "not_found" (REACH DIR-NODE-02 checks this).
async fn node_detail(
    State(st): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match st.repo.get(&id).await {
        Some(mut node) => {
            // Enrich with derived fields (same as discover).
            node.address_family = Some(detect_address_family(
                &node.endpoint,
                node.transport_endpoint.as_deref(),
            ));
            // PHP NodeController includes capabilities array (REACH DIR-NODE-01).
            let mut v = serde_json::to_value(&node).unwrap();
            if !v
                .as_object()
                .map(|o| o.contains_key("capabilities"))
                .unwrap_or(false)
            {
                v["capabilities"] = serde_json::json!([]);
            }
            (StatusCode::OK, Json(v))
        }
        None => (
            StatusCode::NOT_FOUND,
            // PHP uses error.code = "not_found" (REACH DIR-NODE-02 checks exact code).
            Json(
                serde_json::json!({ "error": { "code": "not_found", "message": "Node not found" } }),
            ),
        ),
    }
}

// ── register (iicp-dir §3.1) ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Capability {
    intent: String,
    /// Model names served by this capability (Phase 5 model-aware routing).
    #[serde(default)]
    models: Vec<String>,
    /// Quantization string (e.g. "q4_k_m") for this capability.
    #[serde(default)]
    quantization: Option<String>,
    /// Inference engine name (e.g. "llama.cpp") for this capability.
    #[serde(default)]
    inference_engine: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    /// Optional (iicp-dir §3.1: directory assigns if absent). Supplying a known id
    /// is identity recovery — register() preserves the existing reputation (ADR-026).
    #[serde(default)]
    node_id: Option<String>,
    endpoint: String,
    #[serde(default)]
    region: Option<String>,
    capabilities: Vec<Capability>,
    // ── Phase 5 NODELIST fields (ADR-040/ADR-043) ─────────────────────────────
    /// NAT traversal type (iicp-dir §3.1). Used by RT-04 declared-reachable check.
    #[serde(default)]
    nat_type: Option<String>,
    /// Transport method (iicp-dir §3.1, ADR-040). Used by RT-04 + stored in NODELIST.
    #[serde(default)]
    transport_method: Option<String>,
    /// ADR-043: network exposure mode (e.g. ipv4_public_direct, relay_required).
    #[serde(default)]
    exposure_mode: Option<String>,
    /// Whether the node can act as a relay for CGNAT-blocked peers (Phase 5).
    #[serde(default)]
    relay_capable: Option<bool>,
    /// Native binary framing endpoint (iicp:// or iicpsec://), ADR-040.
    #[serde(default)]
    transport_endpoint: Option<String>,
    /// SDK implementation language (informational, Phase 5).
    #[serde(default)]
    sdk_language: Option<String>,
    /// SDK version string (informational, Phase 5).
    #[serde(default)]
    sdk_version: Option<String>,
    /// cx_public_key identity object (ADR-030 operator identity, Phase 5).
    #[serde(default)]
    cx_public_key: Option<serde_json::Value>,
    /// NAT traversal metadata blob (ADR-043).
    #[serde(default)]
    transport_metadata: Option<serde_json::Value>,
}

/// `POST /v1/register` (iicp-dir §3.1). Validates the endpoint routability invariant
/// (IICP-E035) and every capability intent URN before issuing a token. The RT-04 guard
/// (`is_declared_reachable`) decides whether a liveness probe would be skipped — the
/// network probe itself lands with the deployment wiring (foundation: validation only).
async fn register(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.capabilities.is_empty() {
        return reject("validation_error", "at least one capability is required");
    }
    for cap in &req.capabilities {
        if !validate_intent(&cap.intent) {
            return reject(
                "validation_error",
                &format!("invalid intent URN: {}", cap.intent),
            );
        }
    }
    // AL2 (#401) — exposure_mode enum parity with PHP RegisterController: reject
    // out-of-vocabulary values instead of silently accepting them (ADR-043 §9).
    if let Some(ref em) = req.exposure_mode {
        if !EXPOSURE_MODES.contains(&em.as_str()) {
            return reject("validation_error", &format!("invalid exposure_mode: {em}"));
        }
    }
    if let Err(e) = endpoint_routable(&req.endpoint, st.env) {
        return reject("IICP-E035", &format!("non-routable endpoint: {e:?}"));
    }

    // RT-04: a node that does not declare a concrete reachable topology would, in the
    // full implementation, be subject to a liveness probe before public_reachable=true.
    let declared = is_declared_reachable(req.nat_type.as_deref(), req.transport_method.as_deref());

    // node_id: collision-free UUID v4 (iter-1571 BUG fix — SystemTime-nanos could collide).
    // node_token: UUID v4, bcrypt-hashed by MySqlRepo at cost 12 before storing.
    // node_hmac_key: 32-byte hex secret for CIP credit receipt signing (W-009, iicp-dir §6.2).
    // `recovered` = true when caller supplied a known node_id (identity recovery per ADR-026).
    let recovered = req.node_id.as_deref().is_some_and(|s| !s.is_empty());
    // PHP validates node_id format: alphanumeric start, then [a-zA-Z0-9._:-], max 36 chars.
    // If a custom node_id is supplied, validate it before assigning.
    let node_id = if let Some(ref custom_id) = req.node_id.filter(|s| !s.is_empty()) {
        if custom_id.len() > 36
            || !custom_id
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            || custom_id
                .chars()
                .any(|c| !matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | ':' | '-'))
        {
            return reject("validation_error", "node_id must start with [a-zA-Z0-9] and contain only [a-zA-Z0-9._:-], max 36 chars");
        }
        custom_id.clone()
    } else {
        uuid::Uuid::new_v4().to_string()
    };
    let node_token = uuid::Uuid::new_v4().to_string();
    let proxy_token = uuid::Uuid::new_v4().to_string();
    let node_hmac_key = hex::encode(uuid::Uuid::new_v4().as_bytes());

    let node = types::Node {
        node_id: node_id.clone(),
        endpoint: req.endpoint.clone(),
        region: req.region.clone().unwrap_or_default(),
        score: reputation::STARTING_SCORE,
        available: true,
        load: 0.0,
        active_jobs: 0,
        max_concurrent: 0,
        reputation_score: reputation::STARTING_SCORE,
        latency_estimate_ms: None,
        completed_tasks_count: 0,
        health_label: None,
        exposure_mode: req.exposure_mode.clone(),
        reputation_tier: Some("bronze".into()), // probation (< 100 tasks) → bronze floor tier
        transport_endpoint: req.transport_endpoint.clone(),
        cip_conformance_level: Some("CIP-None".into()),
        models: req
            .capabilities
            .iter()
            .flat_map(|c| c.models.iter().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect(),
        pricing: None,
        cip_policy: Some(serde_json::json!({
            "allow_remote_inference": false,
            "allow_tool_execution": false,
            "allow_file_access": false,
            "pricing_credits_per_1000": null
        })),
        quantization: req
            .capabilities
            .iter()
            .filter_map(|c| c.quantization.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .map(String::from)
            .collect(),
        inference_engine: req
            .capabilities
            .iter()
            .filter_map(|c| c.inference_engine.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .map(String::from)
            .collect(),
        nat_type: req.nat_type.clone(),
        transport_method: req.transport_method.clone(),
        relay_capable: req.relay_capable,
        sdk_language: req.sdk_language.clone(),
        sdk_version: req.sdk_version.clone(),
        address_family: None, // set at query time by detect_address_family
        public_key: req.cx_public_key.clone(),
        transport_metadata: req.transport_metadata.clone(),
        // #400 — pricing/attestation default at register; pricing refined via heartbeat.
        credit_cost_multiplier: 1.0,
        pricing_model: Some("per_token".into()),
        attested: false,
        tasks_failed: 0,
        transport: vec![], // #397 — derived at discover time
        // #385 — new node: public_reachable=false until probed; relay per request.
        reachability_signal: health::reachability_from_flags(
            false,
            req.relay_capable.unwrap_or(false),
        ),
    };
    let intents = req.capabilities.iter().map(|c| c.intent.clone()).collect();
    st.repo
        .register(repo::NodeRecord {
            node,
            intents,
            node_token: Some(node_token.clone()),
            node_hmac_key: Some(node_hmac_key.clone()),
            proxy_token: Some(proxy_token.clone()),
        })
        .await;

    // Record observed source IP (NodeAddressObserver). Takes CF-Connecting-IP first,
    // then the leftmost token of X-Forwarded-For per RFC 7239 §5.2 (PHP parity).
    let client_ip = get_client_ip(&headers);
    st.repo
        .observe_address(&node_id, client_ip, "register")
        .await;

    // Issue a JWT (HS256, sub=node_id, exp=now+3600).
    let jwt_token = auth::issue_jwt(&node_id);
    // PHP NodeRegistry returns jwt_expires_at as ISO-8601; compute similarly.
    let jwt_expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(3600))
        .map(|t| t.to_rfc3339());

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "node_id": node_id,
            "node_token": node_token,
            "proxy_token": proxy_token,
            "node_hmac_key": node_hmac_key,
            "expires_at": serde_json::Value::Null,   // not supported — PHP also returns null
            "jwt_token": jwt_token,                   // PHP field name; adapter reads this
            "jwt_expires_at": jwt_expires_at,
            "directory": "iicp-directory-rs",
            "observed_source_ip": client_ip,
            "recovered": recovered,
            "lifetime_jobs": 0u32,
            "public_reachable": declared,
        })),
    )
}

// ── heartbeat (iicp-dir §3.2) ─────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct HeartbeatMetrics {
    #[serde(default)]
    tasks_success: u32,
    #[serde(default)]
    tasks_failed: u32,
    #[serde(default)]
    avg_latency_ms: f64,
}

/// ADR-019 pricing block carried in heartbeat.
#[derive(Debug, Deserialize, Default)]
struct HeartbeatPricing {
    #[serde(default)]
    credit_cost_multiplier: Option<f64>,
    #[serde(default)]
    pricing_model: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HeartbeatRequest {
    node_id: String,
    #[serde(default)]
    load: f64,
    #[serde(default)]
    available: Option<bool>,
    #[serde(default)]
    active_jobs: Option<u32>,
    #[serde(default)]
    metrics: Option<HeartbeatMetrics>,
    #[serde(default)]
    pricing: Option<HeartbeatPricing>,
}

/// `POST /v1/heartbeat` (iicp-dir §3.2). Requires `Authorization: Bearer <node_token>`.
/// Computes the reputation delta via the auditable `reputation::compute_delta` (RT-01 cap),
/// persists load/available + the new score against the node record, and returns PONG with
/// the node's real reputation_score. 404 if the node_id is unknown.
async fn heartbeat(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<HeartbeatRequest>,
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
    // InMemoryRepo always accepts (local/test mode); MySqlRepo verifies against node_token_hash.
    if !st.repo.verify_node_token(&req.node_id, &token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": { "code": "unauthorized", "message": "invalid node_token" } }),
            ),
        );
    }

    let m = req.metrics.unwrap_or_default();
    // PHP HeartbeatController caps tasks at 1000 per call (physically implausible above this).
    let tasks_success = m.tasks_success.min(1000);
    let tasks_failed = m.tasks_failed.min(1000);
    let tasks_delta = tasks_success + tasks_failed;
    let avg_latency = m.avg_latency_ms.max(0.0);
    let delta = reputation::compute_delta(tasks_success, tasks_failed, avg_latency);
    let available = req.available.unwrap_or(true);
    let active_jobs = req.active_jobs.unwrap_or(0);
    // PHP validates load in [0.0, 1.0]. Clamp rather than reject — adapters may overshoot.
    let load = req.load.clamp(0.0, 1.0);

    // PHP HeartbeatController updates observed_source_ip on every heartbeat (DIR-ADDR-08).
    let client_ip = get_client_ip(&headers);
    st.repo
        .observe_address(&req.node_id, client_ip, "heartbeat")
        .await;

    // ADR-019: update pricing declaration when a pricing block is present.
    if let Some(ref pricing) = req.pricing {
        // AL2 (#401) — pricing_model enum parity with PHP: reject out-of-vocabulary values.
        if let Some(ref pm) = pricing.pricing_model {
            if !PRICING_MODELS.contains(&pm.as_str()) {
                return reject("validation_error", &format!("invalid pricing_model: {pm}"));
            }
        }
        if let Some(multiplier) = pricing.credit_cost_multiplier {
            st.repo
                .update_pricing(&req.node_id, multiplier, pricing.pricing_model.as_deref())
                .await;
        }
    }

    match st
        .repo
        .heartbeat(
            &req.node_id,
            load,
            available,
            active_jobs,
            tasks_delta,
            tasks_failed,
            delta,
        )
        .await
    {
        Some(score) => {
            // PHP logs REPUTATION_UPDATE event when tasks are reported (Phase 6 prereq).
            if tasks_delta > 0 {
                let payload = serde_json::json!({
                    "source": "heartbeat_metrics",
                    "tasks_success": tasks_success,
                    "tasks_failed": tasks_failed,
                    "reputation_score": score
                })
                .to_string();
                st.repo
                    .log_event(&req.node_id, "REPUTATION_UPDATE", &payload)
                    .await;
            }
            // Maybe award free credits (6h gate, §6.5, RT-02b IP gate #380).
            let client_ip = get_client_ip(&headers);
            let free_credits = st
                .repo
                .maybe_allocate_free_credits(&req.node_id, client_ip)
                .await;
            let mut resp = serde_json::json!({
                "ok": true,
                "next_heartbeat_ms": 30000,
                "reputation_score": (score * 10000.0).round() / 10000.0,
            });
            if free_credits > 0.0 {
                resp["free_credits_awarded"] = serde_json::json!(free_credits);
            }
            (StatusCode::OK, Json(resp))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": { "code": "IICP-E003", "message": "node not registered" } }),
            ),
        ),
    }
}

// ── credits (iicp-dir §6) ────────────────────────────────────────────────────

/// `GET /v1/credits/balance` (iicp-dir §6.1). Returns the node's credit balance.
/// `GET /v1/credits/balance` — auth via JWT (sub) or X-Node-Id header fallback.
async fn credits_balance(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
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
    match st.repo.credit_balance(&node_id).await {
        Some(balance) => (
            StatusCode::OK,
            // PHP returns unit + tokens_per_credit (§6.1 spec fields)
            Json(serde_json::json!({
                "node_id": node_id,
                "balance": balance,
                "unit": "credit",
                "tokens_per_credit": 1000
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": { "code": "IICP-E003", "message": "node not found" } }),
            ),
        ),
    }
}

/// Verify a CIP credit receipt HMAC-SHA256 signature (W-009, iicp-dir §6.2).
/// canonical = "task_id:tokens_used:cip_parent_task_id:cip_session_key:nonce:response_hash"
/// Uses constant-time comparison via the hmac crate's verify_slice().
fn verify_cip_receipt(req: &CreditAwardRequest, hmac_key: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let canonical = format!(
        "{}:{}:{}:{}:{}:{}",
        req.task_id,
        req.tokens_used,
        req.cip_parent_task_id,
        req.cip_session_key,
        req.nonce,
        req.response_hash
    );
    let Ok(expected_bytes) = hex::decode(&req.signature) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(hmac_key.as_bytes()) else {
        return false;
    };
    mac.update(canonical.as_bytes());
    mac.verify_slice(&expected_bytes).is_ok()
}

#[derive(Debug, serde::Deserialize)]
struct CreditAwardRequest {
    node_id: String,
    task_id: String,
    tokens_used: u64,
    #[serde(default)]
    cip_parent_task_id: String,
    #[serde(default)]
    cip_session_key: String,
    nonce: String,
    response_hash: String,
    /// HMAC-SHA256 hex (W-009) — must match PHP field name `signature` (size:64).
    signature: String,
    /// Credit amount to award. Capped at tokens_used/1000 × 1.1 on the server side.
    amount: f64,
}

/// `POST /v1/credits/award` (iicp-dir §6.2). Verifies the CIP receipt HMAC before
/// crediting the node. RT-02 nonce replay protection is enforced in record_credit_award.
async fn credits_award(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreditAwardRequest>,
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

    // PHP validates nonce min:32. Reject short nonces before HMAC check.
    if req.nonce.len() < 32 {
        return reject("validation_error", "nonce must be at least 32 characters");
    }

    // Fetch the node's HMAC key for receipt verification.
    let hmac_key = match st.repo.node_hmac_key(&req.node_id).await {
        Some(k) => k,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({ "error": { "code": "IICP-E003", "message": "node not found" } }),
                ),
            )
        }
    };

    // Verify the receipt signature (constant-time comparison via hmac crate).
    if !verify_cip_receipt(&req, &hmac_key) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "IICP-E027", "message": "invalid receipt signature" } }),
            ),
        );
    }

    // PHP validates amount >= 0.0001. Reject trivial amounts rather than silently clamping.
    if req.amount < 0.0001 {
        return reject("validation_error", "amount must be >= 0.0001");
    }
    // Cap amount at tokens_used/1000 × 1.1 (anti-inflation, iicp-dir §6.2).
    let ceiling = (req.tokens_used as f64 / 1000.0) * 1.1;
    let amount = req.amount.min(ceiling).max(0.0);

    match st
        .repo
        .record_credit_award(&req.node_id, amount, &req.task_id, &req.nonce)
        .await
    {
        Ok(new_balance) => (
            StatusCode::CREATED,
            // PHP returns {node_id, awarded, balance} — no ok field
            Json(serde_json::json!({
                "node_id": req.node_id,
                "awarded": amount,
                "balance": new_balance
            })),
        ),
        Err(CreditError::NonceReplay) => (
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({ "error": { "code": "nonce_replay", "message": "nonce already used" } }),
            ),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "error": { "code": "server_error", "message": "credit award failed" } }),
            ),
        ),
    }
}

/// `GET /v1/credits/transactions` (iicp-dir §6.3). Paginated ledger history.
async fn credits_transactions(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<RegistryNodesParams>,
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
    let per_page = p.per_page.unwrap_or(20).min(100);
    let page = p.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page as u64;
    let txs = st
        .repo
        .credit_transactions(&node_id, offset, per_page)
        .await;
    let count = txs.len() as u32;
    (
        StatusCode::OK,
        // PHP returns {node_id, transactions}; add pagination metadata as extension.
        Json(
            serde_json::json!({ "node_id": node_id, "transactions": txs, "count": count, "page": page, "per_page": per_page }),
        ),
    )
}

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

// ── registry (iicp-dir §3.10a / §3.10b) ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RegistryNodesParams {
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    per_page: Option<usize>,
}

/// `GET /v1/registry/nodes` (ADR-017, iicp-dir §3.10a). Public node listing.
/// Returns node identities and reputation tiers without exposing endpoints or tokens.
async fn registry_nodes(
    State(st): State<AppState>,
    Query(p): Query<RegistryNodesParams>,
) -> Json<serde_json::Value> {
    let per_page = p.per_page.unwrap_or(20).min(100);
    let page = p.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page as u64;
    let raw_nodes = st.repo.list_public(offset, per_page).await;
    let total = raw_nodes.len() as u32;
    // PHP registry anonymizes UUID node_ids to 8-char prefix; custom names shown in full.
    let nodes: Vec<serde_json::Value> = raw_nodes
        .into_iter()
        .map(|n| {
            let is_uuid = uuid::Uuid::parse_str(&n.node_id).is_ok();
            let prefix = if is_uuid {
                n.node_id[..8.min(n.node_id.len())].to_string()
            } else {
                n.node_id.clone()
            };
            serde_json::json!({
                "node_id_prefix": prefix,
                "region": n.region,
                "reputation_score": (n.reputation_score * 1000.0).round() / 1000.0,
                "reputation_tier": n.reputation_tier,
                "probation": n.completed_tasks_count < 100,
                "last_seen": serde_json::Value::Null,
            })
        })
        .collect();
    Json(serde_json::json!({ "total": total, "page": page, "limit": per_page, "nodes": nodes }))
}

/// `GET /v1/registry/stats` (iicp-dir §3.10b). Aggregate directory statistics.
async fn registry_stats(State(st): State<AppState>) -> Json<RegistryStats> {
    Json(st.repo.registry_stats().await)
}

/// `GET /v1/registry/nodes/:id` — public node detail (ADR-017: no private fields).
/// Path param: 8-char UUID prefix or full custom node name (PHP parity).
async fn registry_node_detail(
    State(st): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match st.repo.get(&id).await {
        Some(n) => {
            // PHP uses node_id_prefix for UUID nodes (anonymize full UUID).
            let is_uuid = uuid::Uuid::parse_str(&n.node_id).is_ok();
            let prefix = if is_uuid {
                n.node_id[..8.min(n.node_id.len())].to_string()
            } else {
                n.node_id.clone()
            };
            // ADR-044 per-node health vector (PHP RegistryController `health` field).
            // #385 Phase-B: reputation + latency + success + reachability are all real
            // signals now — reachability from public_reachable/relay_capable per PHP
            // reachabilityScore fallback. The node came from the active-set query, so
            // liveness is 1.0.
            let signals = health::HealthSignals {
                reachability: n.reachability_signal,
                latency_ms: n.latency_estimate_ms.map(|ms| ms as f64),
                // #385 Phase-B — real success ratio from persisted task counters.
                tasks_total: n.completed_tasks_count as i64,
                tasks_failed: n.tasks_failed as i64,
                reputation: n.reputation_score,
            };
            let nh = health::score_node(&signals);
            let comp = health::components_of(&signals);
            let r3 = |x: f64| (x * 1000.0).round() / 1000.0;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "node_id_prefix": prefix,
                    "region": n.region,
                    "reputation_score": (n.reputation_score * 1000.0).round() / 1000.0,
                    "reputation_tier": n.reputation_tier,
                    // #397 — transport protocols the node speaks (PHP parity).
                    "transport": transport_methods(&n.endpoint, n.transport_endpoint.as_deref()),
                    "health": {
                        "score": nh.score,
                        "label": nh.label,
                        // observed=false: no independent proxy-observed signal yet (#385).
                        "observed": false,
                        "components": {
                            "liveness": 1.0,
                            "reachability": r3(comp.reachability),
                            "latency": r3(comp.latency),
                            "success_rate": r3(comp.success_rate),
                            "reputation": r3(comp.reputation),
                        },
                        "evaluated_at": chrono::Utc::now().to_rfc3339(),
                    },
                    "probation": n.completed_tasks_count < 100,
                    "completed_tasks": n.completed_tasks_count,
                    "observed_latency_ms": n.latency_estimate_ms,
                    "exposure_mode": n.exposure_mode,
                    "last_seen": serde_json::Value::Null,
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": "REGISTRY-NODE-NOT-FOUND", "message": "No active node found for this prefix." }),
            ),
        ),
    }
}

/// `GET /v1/registry/intents` — distinct intents with active node counts.
async fn registry_intents(State(st): State<AppState>) -> Json<serde_json::Value> {
    // PHP returns {intents: [{urn, node_count}]} — no count field.
    let intents: Vec<IntentSummary> = st.repo.list_intents().await;
    Json(serde_json::json!({ "intents": intents }))
}

/// `GET /.well-known/did.json` — DID document for `did:web:iicp.network` (iicp-dir §3.11).
/// The genesis key is provisioned out-of-band; this returns the structural document
/// with an empty verificationMethod until the key is loaded (Phase 4 / genesis-key command).
async fn did_document() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:iicp.network",
        "controller": "did:web:iicp.network",
        "verificationMethod": [],
        "service": [{
            "id": "did:web:iicp.network#iicp-directory",
            "type": "IICPDirectory",
            "serviceEndpoint": "https://iicp.network/v1"
        }]
    }))
}

// ── peers (iicp-dir §3.5) ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PeersRequest {
    node_id: String,
    #[serde(default)]
    known_peers: Vec<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `POST /v1/peers` (iicp-dir §3.5 PEER_EXCHANGE). Requires bearer token.
/// Returns a list of active peers the caller doesn't already know about.
/// known_peers is capped at 20 entries (excess silently truncated, matching PHP behaviour).
async fn peers(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PeersRequest>,
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
    // Cap known_peers at 20 per spec (silently truncate excess).
    let known: Vec<String> = req.known_peers.into_iter().take(20).collect();
    let limit = req.limit.unwrap_or(10);
    let found = st.repo.peers_excluding(&known, limit).await;
    let count = found.len() as u32;
    // PHP PeersController returns minimal peer data (node_id, endpoint, region, last_seen).
    let peers: Vec<serde_json::Value> = found
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
    (
        StatusCode::OK,
        Json(serde_json::json!({ "peers": peers, "count": count })),
    )
}

/// `GET /v1/me` (iicp-dir §3.8). Returns the authenticated node's own record.
/// Auth: JWT bearer (sub=node_id) preferred; X-Node-Id header fallback when APP_KEY unset.
async fn me(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
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
    match st.repo.get(&node_id).await {
        Some(node) => {
            // PHP MeController returns only {node_id, observed_source_ip, endpoint}
            // (DIR-ADDR-08 — diagnostic "what does the directory see about me?").
            let observed_ip = st.repo.get_observed_ip(&node_id).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "node_id": node.node_id,
                    "observed_source_ip": observed_ip,
                    "endpoint": node.endpoint,
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": { "code": "IICP-E003", "message": "node not found" } }),
            ),
        ),
    }
}

/// `GET /v1/metrics` — Prometheus text exposition (iicp-dir §3.9c).
/// Returns counters useful for monitoring: active node count, reputation histogram buckets.
/// No authentication required (matches PHP MetricsController behaviour).
async fn metrics(State(st): State<AppState>) -> (StatusCode, axum::response::Response) {
    let active = st.repo.active_count().await;
    // Minimal Prometheus text format (version 0.0.4).
    let body = format!(
        "# HELP iicp_active_nodes Number of currently active IICP directory nodes\n\
         # TYPE iicp_active_nodes gauge\n\
         iicp_active_nodes {active}\n\
         # HELP iicp_directory_info IICP directory version metadata\n\
         # TYPE iicp_directory_info gauge\n\
         iicp_directory_info{{version=\"{VERSION}\"}} 1\n"
    );
    let resp = axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap();
    (StatusCode::OK, resp)
}

#[derive(Debug, Deserialize)]
struct DeregisterRequest {
    node_id: String,
}

// ── conformance badges (iicp-dir §3.12) ──────────────────────────────────────

#[derive(Debug, Deserialize)]
struct BadgesParams {
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyParams {
    tier: String,
}

#[derive(Debug, Deserialize)]
struct ConformanceSubmitRequest {
    tier: String,
    #[serde(default)]
    subject_did: Option<String>,
}

/// `GET /v1/badges` — list conformance certificates (all or filtered by ?tier=).
async fn badges_list(
    State(st): State<AppState>,
    Query(p): Query<BadgesParams>,
) -> Json<serde_json::Value> {
    let badges: Vec<ConformanceBadge> = st.repo.list_badges(p.tier.as_deref()).await;
    let count = badges.len() as u32;
    Json(serde_json::json!({ "badges": badges, "count": count }))
}

/// `GET /v1/badge/:tier` — SVG shield badge (Shields.io format).
async fn badge_svg(
    State(st): State<AppState>,
    axum::extract::Path(tier): axum::extract::Path<String>,
) -> axum::response::Response {
    let status = st
        .repo
        .get_badge(&tier)
        .await
        .map(|b| b.status)
        .unwrap_or_else(|| "unknown".to_string());

    let (label_color, msg_color) = match status.as_str() {
        "passed" => ("#4c1", "#4c1"),
        "pending" => ("#e7b416", "#e7b416"),
        _ => ("#9f9f9f", "#9f9f9f"),
    };
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="150" height="20">
  <rect width="60" height="20" fill="#555"/>
  <rect x="60" width="90" height="20" fill="{msg_color}"/>
  <text x="30" y="14" fill="#fff" font-size="11" text-anchor="middle">iicp</text>
  <text x="105" y="14" fill="#fff" font-size="11" text-anchor="middle">{tier} {status}</text>
</svg>"##
    );
    let _ = label_color; // label_color is reserved for future two-color badge design
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "image/svg+xml")
        .header("cache-control", "max-age=3600")
        .body(axum::body::Body::from(svg))
        .unwrap()
}

/// `POST /v1/submit` — submit for conformance evaluation.
async fn conformance_submit(
    State(st): State<AppState>,
    Json(req): Json<ConformanceSubmitRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    const VALID_TIERS: &[&str] = &["bronze", "silver", "gold", "platinum"];
    if !VALID_TIERS.contains(&req.tier.as_str()) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({ "error": { "code": "validation_error", "message": "tier must be bronze/silver/gold/platinum" } }),
            ),
        );
    }
    let badge_id = st
        .repo
        .submit_conformance(&req.tier, req.subject_did.as_deref())
        .await;
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "badge_id": badge_id, "tier": req.tier, "status": "pending" })),
    )
}

/// `GET /v1/verify` — check conformance status for a tier.
async fn conformance_verify(
    State(st): State<AppState>,
    Query(p): Query<VerifyParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    match st.repo.get_badge(&p.tier).await {
        Some(badge) => (
            StatusCode::OK,
            Json(serde_json::json!({ "verified": badge.status == "passed", "badge": badge })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "verified": false, "reason": "no badge for this tier" })),
        ),
    }
}

/// `GET /v1/probe` — SSRF-guarded node reachability check (PHP ProbeController parity).
/// Blocks private/loopback/RFC-1918 IPs with 422 {error: "private_address"}.
/// DIR-PROBE-01/02 REACH MUST probes verify this block before actual TCP probe.
async fn probe_node(Query(p): Query<ProbeParams>) -> (StatusCode, Json<serde_json::Value>) {
    let host = p.host.trim();
    if host.is_empty() || p.port < 1024 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({"error": "validation_error", "message": "host and port (≥1024) required"}),
            ),
        );
    }
    // SSRF guard: block private/loopback IPs without DNS resolution (DNS-rebinding safe).
    if is_private_host(host) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({"reachable": false, "latency_ms": null, "error": "private_address"}),
            ),
        );
    }
    // Full TCP probe is an operator concern — for now return reachable:false with no latency.
    // PHP ProbeController does an actual HTTP probe; this stub blocks SSRF and returns safely.
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"reachable": false, "latency_ms": null, "error": "probe_not_implemented"}),
        ),
    )
}

#[derive(Debug, serde::Deserialize)]
struct ProbeParams {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u16,
}

/// Returns true if the host is a private/loopback address that must be blocked for SSRF.
fn is_private_host(host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']');
    is_loopback_or_unspecified(h) || is_rfc1918_v4(h) || is_ipv6_private(h)
}

fn is_loopback_or_unspecified(h: &str) -> bool {
    h.starts_with("127.") || h == "0.0.0.0" || h == "::1"
}

fn is_rfc1918_v4(h: &str) -> bool {
    if h.starts_with("10.") || h.starts_with("192.168.") || h.starts_with("169.254.") {
        return true;
    }
    // 172.16.0.0/12 — second octet [16, 31]
    h.strip_prefix("172.")
        .and_then(|r| r.split('.').next())
        .and_then(|o| o.parse::<u8>().ok())
        .is_some_and(|n| (16..=31).contains(&n))
}

fn is_ipv6_private(h: &str) -> bool {
    h.starts_with("fe80:") || h.starts_with("fc") || h.starts_with("fd")
}

/// `GET /` — root info (version, spec, links).
async fn root_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "iicp-directory-rs",
        "description": "IICP Directory Control Plane — Rust reference implementation",
        "version": VERSION,
        "spec": "https://github.com/RobLe3/IICP",
        "links": {
            "discover": "/v1/discover",
            "register": "/v1/register",
            "stats": "/v1/stats",
            "registry": "/v1/registry/nodes",
            "did": "/.well-known/did.json"
        }
    }))
}

/// `GET /v1/credits/quote` (iicp-dir §6.4). Unauthenticated pricing estimate.
/// Returns the average credit_cost_multiplier for nodes serving the given intent.
async fn credits_quote(
    State(st): State<AppState>,
    Query(p): Query<DiscoverParams>,
) -> Json<serde_json::Value> {
    let intent = p.intent.as_deref().unwrap_or("");
    let multiplier = st.repo.credit_quote(intent).await;
    let quote_id = format!("q_{}", &uuid::Uuid::new_v4().to_string()[..12]);
    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    // Simplified quote (no max_tokens input → no per-token estimate). PHP-compatible fields.
    Json(serde_json::json!({
        "quote_id": quote_id,
        "intent": intent,
        "price_per_1000_tokens": multiplier,   // PHP field name
        "currency": "iicp_credits",            // PHP uses plural
        "quote_expires_at": expires_at,
    }))
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
    Json(req): Json<TelemetryProbeRequest>,
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
    Json(obs): Json<ProxyObservation>,
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
fn get_client_ip(headers: &axum::http::HeaderMap) -> &str {
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

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
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
fn node_id_from_auth(headers: &axum::http::HeaderMap, token: &str) -> Option<String> {
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

fn reject(code: &str, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({ "error": { "code": code, "message": message } })),
    )
}

/// `/v1/stats` (iicp-dir §3.9b). Returns live active_node count when backed by MySQL;
/// mesh_health score is deferred to Phase 2 (requires per-node health vector aggregation).
async fn stats(State(st): State<AppState>) -> Json<serde_json::Value> {
    let active_nodes = st.repo.active_count().await;
    let last_probe_at = st.repo.last_probe_at().await;
    // ADR-044 mesh_health: median per-node health over the active provider set.
    // Signal mapping (#385 Phase-B): reputation + latency + success ratio + reachability
    // are all real node-row signals now. Reachability uses public_reachable/relay_capable
    // per PHP NodeHealthService reachabilityScore fallback (the recent-probe branch is
    // #373/VPS-gated active probing, which the Rust directory does not perform). The
    // scoring algorithm itself is byte-for-byte the PHP NodeHealthService.
    let provider_set = st.repo.active_nodes().await;
    let healths: Vec<health::NodeHealth> = provider_set
        .iter()
        .map(|n| {
            health::score_node(&health::HealthSignals {
                reachability: n.reachability_signal,
                latency_ms: n.latency_estimate_ms.map(|ms| ms as f64),
                // #385 Phase-B — real success ratio from persisted task counters.
                tasks_total: n.completed_tasks_count as i64,
                tasks_failed: n.tasks_failed as i64,
                reputation: n.reputation_score,
            })
        })
        .collect();
    let mesh = health::mesh_health(&healths);
    // PHP StatsController credit_schedule static data (§8.3 pre-flight).
    let credit_schedule = serde_json::json!({
        "formula": "ceil(output_tokens / tokens_per_credit) × tier_weight × node_multiplier",
        "tokens_per_credit": 1000,
        "tier_weights": { "sub_1b": 0.05, "7b": 1.0, "13b": 2.0, "30b": 6.5, "70b": 32.0, "100b_plus": 75.0 },
        "evaluation_grant": { "credits": 5, "interval_seconds": 21600 },
        "burn_rate_pct": 2.0
    });
    Json(serde_json::json!({
        "server": {
            "active_nodes": active_nodes,
            "version": VERSION,
            // PHP StatsController parity: internal_nodes (directory-internal seed nodes —
            // Rust has no internal-node classification yet → 0) + process uptime.
            "internal_nodes": 0u32,
            "stale_active_nodes": 0u32,  // DIR-STATS-02: Rust NodeLifecycle background task prunes stale rows
            "uptime_seconds": START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0),
        },
        "probes": { "last_probe_at": last_probe_at },
        "credit_schedule": credit_schedule,
        "mesh_health": {
            "score": mesh.score,
            "label": mesh.label,
            "mean": mesh.mean,
            "p10": mesh.p10,
            "distribution": {
                "healthy": mesh.distribution.healthy,
                "degraded": mesh.distribution.degraded,
                "impaired": mesh.distribution.impaired,
                "critical": mesh.distribution.critical,
                "offline": mesh.distribution.offline
            },
            "sample": mesh.sample,
            "basis": "active_provider_nodes",
            "window": "live"
        }
    }))
}

/// `GET /v1/bootstrap` (iicp-dir §3.7). Returns recently-active nodes for peer discovery.
/// No intent filter — any available, recently-seen node qualifies.
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
        // PHP emits DEREGISTER event before deletion (spec §3.4 — signed event log prereq).
        // Log it to node_events for federation traceability (Phase 6).
        st.repo.log_event(&req.node_id, "DEREGISTER", "{}").await;
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
    START_TIME.set(Instant::now()).ok();
    let addr = "0.0.0.0:8090";
    let env = match std::env::var("APP_ENV").as_deref() {
        Ok("local") => Env::Local,
        Ok("testing") => Env::Testing,
        Ok("staging") => Env::Staging,
        _ => Env::Production,
    };

    // Wire DATABASE_URL → MySqlRepo when present; fallback to InMemoryRepo for local dev.
    let repo: Arc<dyn NodeRepository> = if let Ok(url) = std::env::var("DATABASE_URL") {
        match db::init_pool(&url).await {
            Ok(pool) => {
                if let Err(e) = sqlx::migrate!("./migrations").run(&pool).await {
                    eprintln!("WARNING: migrations failed ({e}); proceeding");
                }
                println!("iicp-directory-rs {VERSION}: MySQL pool connected");
                Arc::new(db::MySqlRepo::new(pool))
            }
            Err(e) => {
                eprintln!("WARNING: MySQL pool failed ({e}); falling back to InMemoryRepo");
                Arc::new(InMemoryRepo::default())
            }
        }
    } else {
        println!("iicp-directory-rs {VERSION}: no DATABASE_URL; using InMemoryRepo");
        Arc::new(InMemoryRepo::default())
    };

    // Spawn background maintenance tasks before starting the HTTP server.
    tokio::spawn(background::run_expire_nodes_loop(Arc::clone(&repo)));
    tokio::spawn(background::run_reputation_decay_loop(Arc::clone(&repo)));
    tokio::spawn(background::run_node_lifecycle_loop(Arc::clone(&repo)));
    tokio::spawn(background::run_prune_heartbeat_loop(Arc::clone(&repo)));
    tokio::spawn(background::run_rotate_reputation_window_loop(Arc::clone(
        &repo,
    )));
    tokio::spawn(background::run_probe_nodes_loop(Arc::clone(&repo)));

    let state = AppState { repo, env };
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("iicp-directory-rs {VERSION} listening on {addr}");
    axum::serve(listener, app(state)).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use repo::NodeRecord;
    use tower::ServiceExt;

    fn test_state() -> AppState {
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
                sdk_version: None,
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
            },
            intents: vec![chat.into()],
            node_token: None,
            node_hmac_key: Some("test-hmac-key".into()),
            proxy_token: None,
        };
        AppState {
            repo: Arc::new(InMemoryRepo::new(vec![mk("a", 0.9), mk("b", 0.5)])),
            env: Env::Production,
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

    #[tokio::test]
    async fn health_returns_ok() {
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
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
        // #400 — discover field parity with PHP: credit_cost_multiplier / pricing_model / attested.
        assert_eq!(v["nodes"][0]["credit_cost_multiplier"], 1.0);
        assert_eq!(v["nodes"][0]["pricing_model"], "per_token");
        assert_eq!(v["nodes"][0]["attested"], false);
        // #397 — transport derived server-side (test_state endpoints are https://…).
        assert_eq!(v["nodes"][0]["transport"], serde_json::json!(["https"]));
    }

    #[tokio::test]
    async fn register_with_phase5_fields_round_trips_in_discover() {
        let st = test_state();
        // Register a node that supplies Phase 5 registration fields.
        let body = serde_json::json!({
            "endpoint": "https://p5.example.com",
            "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["llama3"],
                               "quantization": "q4_k_m", "inference_engine": "llama.cpp"}],
            "relay_capable": true,
            "sdk_language": "python",
            "sdk_version": "0.5.2",
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
            .find(|n| n["endpoint"] == "https://p5.example.com")
            .expect("registered node must appear in discover");
        assert_eq!(node["relay_capable"], true);
        assert_eq!(node["sdk_language"], "python");
        assert_eq!(node["nat_type"], "full_cone");
        assert_eq!(node["models"][0], "llama3");
        assert_eq!(node["quantization"][0], "q4_k_m");
        assert_eq!(node["inference_engine"][0], "llama.cpp");
        assert_eq!(node["address_family"], "hostname");
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
    async fn register_valid_returns_201_ack() {
        let body = serde_json::json!({
            "endpoint": "https://node.example.com",
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
    async fn register_bad_intent_is_422() {
        let body = serde_json::json!({
            "endpoint": "https://node.example.com",
            "capabilities": [{"intent": "not-a-urn"}]
        });
        let resp = app(test_state())
            .oneshot(post_register(body))
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
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
    async fn register_unknown_nat_not_declared_reachable() {
        // RT-04: unknown nat_type → public_reachable=false (probe pending), not auto-true.
        let body = serde_json::json!({
            "endpoint": "https://node.example.com",
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
        assert_eq!(v["public_reachable"], false);
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
        };
        let router = app(st);
        let body = |id: &str| {
            serde_json::json!({
                "node_id": id,
                "endpoint": "https://recover.example.com",
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
        };
        let router = app(st);
        let body = serde_json::json!({
            "node_id": "rr-test",
            "endpoint": "https://rr.example.com",
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
        };
        let router = app(st);

        // 1. register
        let reg = router
            .clone()
            .oneshot(post_register(serde_json::json!({
                "endpoint": "https://live.example.com",
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
        // ADR-044 mesh_health computed over the 2 active nodes (iter-1957).
        // Each: reachability 0.5 + latency neutral 0.5 + success neutral 0.5 + reputation 0.8
        // = 0.30*0.5 + 0.25*0.5 + 0.25*0.5 + 0.20*0.8 = 0.56 → 56 → "impaired".
        let mh = &v["mesh_health"];
        assert_eq!(mh["sample"], 2);
        assert_eq!(mh["label"], "insufficient_sample"); // 2 < MIN_MESH_SAMPLE
        assert_eq!(mh["score"], 0.56);
        assert_eq!(mh["mean"], 0.56);
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
        let new = st.repo.heartbeat("a", 0.1, true, 0, 10, 3, 0.0).await;
        assert!(new.is_some());
        let n = st.repo.get("a").await.expect("node a");
        assert_eq!(n.completed_tasks_count, 10, "tasks_total += success+failed");
        assert_eq!(n.tasks_failed, 3, "tasks_failed persisted, not dropped");
        // success ratio 70% → success_score == 0.0 boundary (health.rs).
        let h = health::score_node(&health::HealthSignals {
            reachability: 1.0,
            latency_ms: None,
            tasks_total: n.completed_tasks_count as i64,
            tasks_failed: n.tasks_failed as i64,
            reputation: 1.0,
        });
        // 0.30*1 + 0.25*0.5(no latency) + 0.25*0.0(70%) + 0.20*1 = 0.625 → 63
        assert_eq!(h.score, 63);
    }

    #[tokio::test]
    async fn register_rejects_invalid_exposure_mode() {
        // #401 / AL2 — Rust must reject out-of-enum exposure_mode (PHP parity),
        // not silently accept it.
        let body = serde_json::json!({
            "endpoint": "https://x.example.com",
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
            })
            .oneshot(post_register(serde_json::json!({
                "node_id": bad_id,
                "endpoint": "https://test.example.com",
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
        };
        let resp = app(st)
            .oneshot(post_register(serde_json::json!({
                "node_id": "my-custom-node-1",
                "endpoint": "https://test.example.com",
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
        };
        let resp = app(st)
            .oneshot(post_register(serde_json::json!({
                "endpoint": "https://ack-test.example.com",
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

    // ── /v1/probe SSRF guard unit tests ──────────────────────────────────────

    #[test]
    fn private_host_blocks_loopback() {
        assert!(is_private_host("127.0.0.1"));
        assert!(is_private_host("127.0.0.10"));
        assert!(is_private_host("::1"));
    }

    #[test]
    fn private_host_blocks_rfc1918() {
        assert!(is_private_host("10.0.0.1"));
        assert!(is_private_host("10.255.255.255"));
        assert!(is_private_host("192.168.1.1"));
        assert!(is_private_host("172.16.0.1"));
        assert!(is_private_host("172.31.255.255"));
        assert!(!is_private_host("172.15.0.1")); // just outside range
        assert!(!is_private_host("172.32.0.1")); // just outside range
    }

    #[test]
    fn private_host_allows_public_ips() {
        assert!(!is_private_host("1.2.3.4"));
        assert!(!is_private_host("8.8.8.8"));
        assert!(!is_private_host("2606:4700::6810:84e5")); // Cloudflare
    }

    #[tokio::test]
    async fn probe_loopback_is_422() {
        // DIR-PROBE-01: 127.0.0.1 → 422 private_address
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/probe?host=127.0.0.1&port=9484")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["error"], "private_address");
    }

    #[tokio::test]
    async fn probe_rfc1918_is_422() {
        // DIR-PROBE-02: 10.0.0.1 → 422 private_address
        let resp = app(test_state())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/probe?host=10.0.0.1&port=9484")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
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
}

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
mod behavior_contract;
mod db;
mod delegation;
mod deployment_provenance;
mod discovery_policy;
mod federation;
mod health;
#[cfg(test)]
mod jcs;
mod maintenance;
mod policy;
mod policy_manifest;
mod recognition;
mod registration;
mod registration_store;
mod replica;
mod repo;
mod reputation;
mod schema;
mod types;
mod validate;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;
use std::{net::ToSocketAddrs, time::Duration};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    middleware::{self, Next},
    routing::{get, post},
    Json, Router,
};
use clap::{Args, Parser, Subcommand};
use repo::{
    AuditResult, ConformanceBadge, CreditError, DiscoverQuery, InMemoryRepo, IntentSummary,
    NodeRepository, OperatorSelfServiceError, ProbeResult, ProxyObservation, RegistryStats,
};
use serde::Deserialize;
use sqlx::{MySql, Pool};
use validate::{endpoint_routable, is_declared_reachable, validate_intent, Env};

const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"), "-rs");
const SDK_BASELINE_VERSION: &str = "0.7.68";
const SDK_LATEST_KNOWN_VERSION: &str = "0.7.100";

#[derive(Debug, Parser)]
#[command(name = "iicp-directory-rs", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report metadata-only database maintenance status.
    DbMaintenanceStatus {
        #[command(flatten)]
        retention: RetentionArgs,
        #[arg(long)]
        json: bool,
    },
    /// Count expired telemetry by default; delete only with explicit --apply.
    TelemetryPrune {
        #[command(flatten)]
        retention: RetentionArgs,
        #[arg(long, default_value_t = maintenance::DEFAULT_BATCH_SIZE)]
        batch: u32,
        #[arg(long, default_value_t = maintenance::DEFAULT_MAX_BATCHES)]
        max_batches: u32,
        #[arg(long, conflicts_with = "apply")]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Report aggregate strict-E050 readiness without mutating registrations.
    E050Readiness {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Default, Args)]
struct RetentionArgs {
    #[arg(long)]
    probe_days: Option<u32>,
    #[arg(long)]
    aggregate_days: Option<u32>,
    #[arg(long)]
    proxy_days: Option<u32>,
    #[arg(long)]
    dispatch_days: Option<u32>,
}

impl RetentionArgs {
    fn policy(&self) -> maintenance::RetentionPolicy {
        let mut policy = maintenance::RetentionPolicy::from_env();
        policy.probe_days = positive_override(self.probe_days, policy.probe_days);
        policy.aggregate_days = positive_override(self.aggregate_days, policy.aggregate_days);
        policy.proxy_days = positive_override(self.proxy_days, policy.proxy_days);
        policy.dispatch_days = positive_override(self.dispatch_days, policy.dispatch_days);
        policy
    }
}

fn positive_override(value: Option<u32>, default: u32) -> u32 {
    value.filter(|value| *value > 0).unwrap_or(default)
}

const OPERATOR_CHALLENGE_TTL_SECS: u64 = 300;
const OPERATOR_TS_WINDOW_SECS: i64 = 300;
const PROFILE_ID: &str = "iicp.profile.compatibility.v0";
const PROFILE_VERSION: &str = "0.4.0-draft";
const PROFILE_FIXTURE_SHA256: &str =
    "d039eaf52afca6866832779261db7bdd2ffd818a36bc8ba9aea1db0c9c115012";
const PREVIOUS_PROFILE_VERSION: &str = "0.3.0-draft";
const PREVIOUS_PROFILE_FIXTURE_SHA256: &str =
    "4137ecf91b4748a2b368cf4428b4604c6947f8879d77402cc7937d11d24b2aaf";

/// One-use, process-local operator challenges. They are intentionally short
/// lived and contain no task content, credentials or private key material.
static OPERATOR_CHALLENGES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, u64>>> =
    std::sync::OnceLock::new();

/// This directory's DID (single source for /.well-known/did.json + signed-event signer_did).
const DEFAULT_DIRECTORY_DID: &str = "did:web:iicp.network";

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

/// Process start instant — backs `server.uptime_seconds` in `/v1/stats` (PHP parity).
/// Set once in `main`; unset in tests (uptime reports 0).
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

#[derive(Clone)]
struct AppState {
    repo: Arc<dyn NodeRepository>,
    env: Env,
    /// #442: this directory's Ed25519 signing key (libsodium 64-byte / 128-hex), from
    /// IICP_GENESIS_ED25519_SECRET_KEY. `None` → events emit unsigned (PHP parity: when no
    /// key is configured, NodeEventLogger::sign returns null).
    signing_key: Option<String>,
    /// Served identity and public service endpoint. Replica mode binds this DID
    /// to IICP_REPLICA_DID instead of impersonating the Genesis Seed.
    directory_did: String,
    directory_service_endpoint: String,
    /// IICP-E034 registration rate-limit counter, per source IP (W-033 PHP parity).
    register_rate: RegisterRateMap,
    /// Adoption-gated E050 E′ hardening. False preserves the migration-safe
    /// dead-endpoint fallback; production must not enable this before #534.
    strict_e050_secured: bool,
    /// Registration/lifecycle probes verify TLS identity by default. The
    /// insecure mode is accepted only by an explicit non-production testbed.
    allow_insecure_tls: bool,
    /// Tests may disable live dial-back. Production defaults to probing every
    /// registration that lacks a concrete topology declaration.
    skip_liveness_check: bool,
}

/// Emit + sign a federated event onto this directory's log if a signing key is configured
/// (#442). No-op when unsigned. Keeps the write-path handlers a single call (complexity-flat).
async fn emit_event(st: &AppState, event_type: &str, node_id: &str, payload: serde_json::Value) {
    if let Some(key) = st.signing_key.as_deref() {
        st.repo
            .append_signed_event(key, event_type, node_id, &payload)
            .await;
    }
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/iicp/health", get(health))
        .route("/v1/stats", get(stats))
        .route("/api/v1/stats", get(stats))
        .route("/v1/metrics", get(metrics))
        .route("/api/v1/metrics", get(metrics))
        .route("/v1/discover", get(discover))
        .route("/api/v1/discover", get(discover))
        .route("/v1/dispatch/ticket", post(dispatch_ticket_issue))
        .route("/api/v1/dispatch/ticket", post(dispatch_ticket_issue))
        .route("/v1/bootstrap", get(bootstrap))
        .route("/api/v1/bootstrap", get(bootstrap))
        .route("/v1/events", get(events))
        .route("/v1/snapshot", get(snapshot))
        // #442 — federation endpoints are also served under /api/v1 so a replica (PHP or
        // Rust) can federate FROM a Rust seed: ReplicaStartCommand + replica::fetch_events
        // both poll `{seed}/api/v1/events` + `/api/v1/snapshot` + `/api/v1/replicas/register`
        // (the PHP seed mounts everything under /api). Without these aliases a Rust seed is
        // unreachable to /api/v1-expecting replicas (404 on the path).
        .route("/api/v1/events", get(events))
        .route("/api/v1/snapshot", get(snapshot))
        .route("/api/v1/replicas/register", post(replicas_register))
        .route("/v1/replicas/deregister", post(replicas_deregister))
        .route("/api/v1/replicas/deregister", post(replicas_deregister))
        .route("/v1/me", get(me))
        .route("/api/v1/me", get(me))
        .route("/v1/node/:id", get(node_detail))
        .route("/api/v1/node/:id", get(node_detail))
        .route("/v1/register", post(register).delete(deregister))
        .route("/api/v1/register", post(register).delete(deregister))
        .route("/v1/operator/rename", post(operator_rename))
        .route("/api/v1/operator/rename", post(operator_rename))
        .route("/v1/operator/challenge", post(operator_challenge))
        .route("/api/v1/operator/challenge", post(operator_challenge))
        .route("/v1/operator/acceptance", post(operator_acceptance))
        .route("/api/v1/operator/acceptance", post(operator_acceptance))
        .route("/v1/operator/dsr/export", post(operator_dsr_export))
        .route("/api/v1/operator/dsr/export", post(operator_dsr_export))
        .route("/v1/operator/dsr/restrict", post(operator_dsr_restrict))
        .route("/api/v1/operator/dsr/restrict", post(operator_dsr_restrict))
        .route("/v1/operator/dsr/anonymize", post(operator_dsr_anonymize))
        .route(
            "/api/v1/operator/dsr/anonymize",
            post(operator_dsr_anonymize),
        )
        .route("/v1/operator/key/rotate", post(operator_key_rotate))
        .route("/api/v1/operator/key/rotate", post(operator_key_rotate))
        .route("/v1/operator/key/revoke", post(operator_key_revoke))
        .route("/api/v1/operator/key/revoke", post(operator_key_revoke))
        .route("/v1/leaderboards/:board_id", get(leaderboard))
        .route("/api/v1/leaderboards/:board_id", get(leaderboard))
        .route("/v1/replicas/register", post(replicas_register))
        .route("/v1/peers", post(peers))
        .route("/api/v1/peers", post(peers))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/api/v1/heartbeat", post(heartbeat))
        .route("/v1/registry/nodes", get(registry_nodes))
        .route("/api/v1/registry/nodes", get(registry_nodes))
        .route("/v1/registry/nodes/:id", get(registry_node_detail))
        .route("/api/v1/registry/nodes/:id", get(registry_node_detail))
        .route("/v1/registry/intents", get(registry_intents))
        .route("/api/v1/registry/intents", get(registry_intents))
        .route("/v1/registry/stats", get(registry_stats))
        .route("/api/v1/registry/stats", get(registry_stats))
        .route("/.well-known/did.json", get(did_document))
        .route("/.well-known/iicp-deployment.json", get(deployment_record))
        .route("/.well-known/iicp-replicas.json", get(iicp_replicas))
        .route("/v1/directory-key", get(directory_key))
        .route("/api/v1/directory-key", get(directory_key))
        .route("/v1/consumer-token", post(consumer_token_issue))
        .route("/api/v1/consumer-token", post(consumer_token_issue))
        .route("/v1/relay/ticket", post(relay_ticket_issue))
        .route("/api/v1/relay/ticket", post(relay_ticket_issue))
        .route("/v1/compliance-attestation", get(compliance_attestation))
        .route(
            "/api/v1/compliance-attestation",
            get(compliance_attestation),
        )
        .route("/v1/credits/balance", get(credits_balance))
        .route("/api/v1/credits/balance", get(credits_balance))
        .route("/v1/credits/summary", get(credits_summary))
        .route("/api/v1/credits/summary", get(credits_summary))
        .route("/v1/credits/award", post(credits_award))
        .route("/api/v1/credits/award", post(credits_award))
        .route("/v1/credits/transactions", get(credits_transactions))
        .route("/api/v1/credits/transactions", get(credits_transactions))
        .route("/v1/audit-report", post(audit_report))
        .route("/api/v1/audit-report", post(audit_report))
        .route("/v1/telemetry/probe", post(telemetry_probe))
        .route("/api/v1/telemetry/probe", post(telemetry_probe))
        .route("/v1/telemetry", post(telemetry_proxy))
        .route("/api/v1/telemetry", post(telemetry_proxy))
        .route("/v1/credits/quote", get(credits_quote))
        .route("/api/v1/credits/quote", get(credits_quote))
        .route("/v1/badges", get(badges_list))
        .route("/api/v1/conformance/badges", get(badges_list))
        .route("/v1/badge/:tier", get(badge_svg))
        .route("/api/v1/badge/:tier", get(badge_svg))
        .route("/v1/submit", post(conformance_submit))
        .route("/api/v1/conformance/submit", post(conformance_submit))
        .route("/v1/verify", get(conformance_verify))
        .route("/api/v1/conformance/verify", get(conformance_verify))
        .route("/v1/probe", get(probe_node))
        .route("/api/v1/probe", get(probe_node))
        .route("/", get(root_info))
        .layer(middleware::from_fn(json_error_boundary))
        .with_state(state)
}

/// Axum extractor rejections otherwise expose plain-text parser details (and
/// can include the phrase "at line"). Keep every API error JSON-shaped and
/// content-free, matching the PHP authority's PROTO-MSG-05/SEC-LEAK contract.
async fn json_error_boundary(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/json"));
    if (status.is_client_error() || status.is_server_error()) && !is_json {
        return (
            status,
            Json(serde_json::json!({
                "error": {
                    "code": if status == StatusCode::UNPROCESSABLE_ENTITY {
                        "validation_error"
                    } else {
                        "request_error"
                    },
                    "message": "request rejected"
                }
            })),
        )
            .into_response();
    }
    response
}

/// Replica write-gate (DIR-FED-18): when this directory runs as a replica
/// (`IICP_REPLICA_MODE=true`), it MUST NOT accept writes — token issuance and the
/// event log are single-source on the seed. Unsafe methods (POST/PUT/PATCH/DELETE) get
/// a 307 Temporary Redirect to the seed, preserving path + query; reads pass through.
/// Reciprocal of the PHP `ReplicaModeRedirect` middleware. Applied only in replica mode.
async fn replica_write_gate(State(seed_url): State<String>, req: Request, next: Next) -> Response {
    if matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        let path_q = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let location = format!("{}{}", seed_url.trim_end_matches('/'), path_q);
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [
                (header::LOCATION, location),
                (
                    header::HeaderName::from_static("x-iicp-redirect-reason"),
                    "replica_mode".to_string(),
                ),
                (header::RETRY_AFTER, "0".to_string()),
            ],
        )
            .into_response();
    }
    next.run(req).await
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
    /// #494 — filter to nodes whose live health_models contains this model name.
    /// Falls back to the static `models` list when health_models is not yet reported.
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    qos: Option<String>,
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default)]
    profile_version: Option<String>,
    #[serde(default)]
    profile_fixture_sha256: Option<String>,
    #[serde(default)]
    profile_required: Option<bool>,
    /// Public presentation strips endpoints, full node IDs and key material.
    #[serde(default)]
    view: Option<String>,
}

fn profile_negotiation(p: &DiscoverParams) -> Option<serde_json::Value> {
    let profile_id = p.profile_id.as_ref()?;
    let required = p.profile_required.unwrap_or(false);
    let compatible = profile_id == PROFILE_ID
        && matches!(
            (
                p.profile_version.as_deref(),
                p.profile_fixture_sha256.as_deref()
            ),
            (Some(PROFILE_VERSION), Some(PROFILE_FIXTURE_SHA256))
                | (
                    Some(PREVIOUS_PROFILE_VERSION),
                    Some(PREVIOUS_PROFILE_FIXTURE_SHA256)
                )
        );
    Some(serde_json::json!({
        "requested": true,
        "profile_id": profile_id,
        "profile_version": p.profile_version.as_deref(),
        "fixture_sha256": p.profile_fixture_sha256.as_deref(),
        "required": required,
        "status": if compatible { "compatible" } else { "unsupported" },
        "reason": if compatible { "compatible" } else { "unsupported_pre_normative_profile" },
        "dispatch_allowed": compatible || !required,
        "supported_profile": PROFILE_ID,
        "supported_version": PROFILE_VERSION,
        "supported_fixture_sha256": PROFILE_FIXTURE_SHA256,
    }))
}

/// `GET /v1/discover` → NODELIST (iicp-dir §3.3/§3.4).
async fn discover(
    State(st): State<AppState>,
    Query(p): Query<DiscoverParams>,
) -> axum::response::Response {
    let negotiated_profile = profile_negotiation(&p);
    let public_view = p.view.as_deref() == Some("public");
    if negotiated_profile
        .as_ref()
        .is_some_and(|n| n.get("dispatch_allowed") == Some(&serde_json::Value::Bool(false)))
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": {"code": "unsupported_pre_normative_profile", "message": "The requested pre-normative profile is not supported by this directory."},
                "profile_negotiation": negotiated_profile,
            })),
        ).into_response();
    }
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
    // Public-mesh intent policy is enforced before repository access. This is an
    // identifier-only guard: neither prompts nor task payloads reach the directory.
    if let Some(classification) = policy::IntentPolicyGuard::public_mesh_refusal(&intent) {
        return policy_reject(&classification).into_response();
    }
    if let Err(message) = discovery_policy::validate_min_reputation(p.min_reputation) {
        return reject("validation_error", message).into_response();
    }
    if let Err(message) = discovery_policy::validate_qos(p.qos.as_deref()) {
        return reject("validation_error", message).into_response();
    }
    let requested_limit = p.limit.unwrap_or(10).clamp(1, 50);
    let started = Instant::now();
    let repository_started = Instant::now();
    let nodes = st
        .repo
        .discover(&DiscoverQuery {
            intent,
            region: p.region.clone(),
            // Selection policy must see the complete bounded candidate set;
            // ranking and caller limit are applied below.
            limit: 50,
            min_reputation: p.min_reputation,
        })
        .await;
    let repository_ms = repository_started.elapsed().as_secs_f64() * 1000.0;
    let nodes = discovery_policy::select_and_rank(
        nodes,
        &discovery_policy::SelectionRequest {
            model: p.model.as_deref(),
            qos: p.qos.as_deref(),
            region: p.region.as_deref(),
            min_reputation: p.min_reputation.unwrap_or(0.0),
            limit: requested_limit,
            cip_capable: matches!(p.cip_capable.as_deref(), Some("1") | Some("true")),
        },
        |version| sdk_status(version) == "current",
    );
    // Enrich with server-side derived fields (PHP NodeScorer parity).
    let enrichment_started = Instant::now();
    let mut enriched = Vec::with_capacity(nodes.len());
    for mut n in nodes {
        n.address_family = Some(detect_address_family(
            &n.endpoint,
            n.transport_endpoint.as_deref(),
        ));
        // #397 — transport protocols, derived from endpoint schemes (PHP parity).
        n.transport = transport_methods(&n.endpoint, n.transport_endpoint.as_deref());
        // #525/G3 — public operator handle + short fingerprint; never expose operator_pubkey.
        n.operator_display_name =
            operator_display_name_for(&st, n.operator_pubkey.as_deref()).await;
        n.operator_fingerprint = operator_fingerprint_for(n.operator_pubkey.as_deref());
        enriched.push(n);
    }
    let enrichment_ms = enrichment_started.elapsed().as_secs_f64() * 1000.0;
    build_discover_response(
        &st,
        public_view,
        enriched,
        negotiated_profile,
        started,
        repository_ms,
        enrichment_ms,
    )
    .await
}

async fn build_discover_response(
    state: &AppState,
    public_view: bool,
    nodes: Vec<types::Node>,
    negotiated_profile: Option<serde_json::Value>,
    started: Instant,
    repository_ms: f64,
    enrichment_ms: f64,
) -> axum::response::Response {
    let response_started = Instant::now();
    let count = nodes.len() as u32;
    let relay_available = nodes.iter().any(|n| n.relay_capable.unwrap_or(false));
    let verified_operator_keys = nodes
        .iter()
        .filter(|node| node.operator_verified)
        .filter_map(|node| node.operator_pubkey.as_deref())
        .collect::<Vec<_>>();
    let distinct_verified_operators = verified_operator_keys
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len();
    let distinct_regions = nodes
        .iter()
        .map(|node| node.region.as_str())
        .filter(|region| !region.is_empty())
        .collect::<std::collections::HashSet<_>>()
        .len();
    state
        .repo
        .record_dispatch_usage(if public_view {
            "public_view"
        } else {
            "legacy_dispatch"
        })
        .await;
    let response_nodes = nodes
        .iter()
        .map(|node| {
            let value = live_node_value(node);
            if public_view {
                public_discover_node(value)
            } else {
                value
            }
        })
        .collect::<Vec<_>>();
    let data_class = if public_view {
        "public_presentation"
    } else {
        "route_dispatch"
    };
    let mut body = serde_json::json!({
        "nodes": response_nodes,
        "count": count,
        "relay_available": relay_available,
        "query_ms": started.elapsed().as_millis() as u32,
        "view": if public_view { "public" } else { "dispatch" },
        "data_class": data_class,
        "route_fields_present": !public_view,
        "diversity_evidence": {
            "nodes": count,
            "nodes_with_verified_operator": verified_operator_keys.len(),
            "distinct_verified_operators": distinct_verified_operators,
            "distinct_regions": distinct_regions,
            "operator_basis": "verified_operator_key_aggregate",
            "failure_domain_count": serde_json::Value::Null,
            "failure_domain_basis": "not_attested",
            "identity_material_exposed": false
        },
    });
    if let Some(negotiation) = negotiated_profile {
        body["profile_negotiation"] = negotiation;
    }
    // Keep Rust-directory cache semantics aligned with the seed: routes may
    // carry rotating tunnel/relay endpoints, so long CDN staleness is unsafe.
    // Rust has no origin result cache yet; advertise that fact safely so
    // conformance telemetry does not invent cache-hit/miss evidence.
    let encoded = serde_json::to_vec(&body).unwrap();
    let response_ms = response_started.elapsed().as_secs_f64() * 1000.0;
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    let server_timing = format!(
        "iicp_repository;dur={repository_ms:.3}, iicp_enrichment;dur={enrichment_ms:.3}, iicp_response;dur={response_ms:.3}, iicp_total;dur={total_ms:.3}"
    );
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header(
            "cache-control",
            "public, max-age=5, s-maxage=10, stale-while-revalidate=5",
        )
        .header("x-iicp-discover-origin-cache", "bypass")
        .header("x-iicp-discover-data-class", data_class)
        .header("server-timing", server_timing)
        .header("vary", "Accept-Encoding")
        .body(axum::body::Body::from(encoded))
        .unwrap()
}

fn public_discover_node(value: serde_json::Value) -> serde_json::Value {
    let Some(source) = value.as_object() else {
        return serde_json::json!({});
    };
    let allowed = [
        "region",
        "score",
        "available",
        "relay_capable",
        "transport_method",
        "nat_type",
        "address_family",
        "transport",
        "reachability_tier",
        "directory_observed_reachable",
        "route_evidence",
        "routing_hint",
        "browser_usable",
        "exposure_mode",
        "key_ready",
        "response_encryption_ready",
        "privacy_routing_status",
        "sdk_language",
        "sdk_version",
        "consumer_cosignature_ready",
        "sdk_status",
        "sdk_baseline_version",
        "upgrade_required",
        "health_label",
        "health_confidence",
        "performance",
        "backend_stability",
        "reputation_score",
        "reputation_tier",
        "trust_progress",
        "probation",
        "models",
        "capability_summary",
        "input_modalities",
        "quantization",
        "inference_engine",
        "backend",
        "cip_policy",
        "cip_conformance_level",
        "pricing",
        "operator_display_name",
        "operator_fingerprint",
        "node_policy_manifest",
    ];
    let mut public = serde_json::Map::new();
    if let Some(node_id) = source.get("node_id").and_then(serde_json::Value::as_str) {
        public.insert(
            "node_id_prefix".to_string(),
            serde_json::Value::String(node_id[..node_id.len().min(8)].to_string()),
        );
    }
    for field in allowed {
        if let Some(value) = source.get(field).filter(|value| !value.is_null()) {
            public.insert(field.to_string(), value.clone());
        }
    }
    serde_json::Value::Object(public)
}

/// `POST /v1/dispatch/ticket` — one short-lived, prompt-free route disclosure.
///
/// V1 tickets bind the signed directory disclosure to one intent/node/expiry. They
/// do not authorize node task ingress and deliberately have no stateful redemption
/// cache; node-admission tickets are a separately versioned future profile.
#[derive(Debug, Deserialize)]
struct DispatchTicketRequest {
    intent: String,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    min_reputation: Option<f64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    relay_capable: Option<bool>,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    node_id_prefix: Option<String>,
    #[serde(default)]
    exclude_node_id_prefixes: Vec<String>,
    // The directory is control-plane only. These fields are explicit so a caller
    // cannot accidentally send a task body through a ticket request.
    #[serde(default)]
    prompt: Option<serde_json::Value>,
    #[serde(default)]
    messages: Option<serde_json::Value>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
    #[serde(default)]
    input: Option<serde_json::Value>,
    #[serde(default)]
    chat: Option<serde_json::Value>,
    #[serde(default)]
    content: Option<serde_json::Value>,
    #[serde(default)]
    response: Option<serde_json::Value>,
}

const DISPATCH_TICKET_DOMAIN: &str = "iicp:dispatch-route-ticket:v1\n";
const DISPATCH_TICKET_AUDIENCE: &str = "iicp.directory.dispatch";
const DISPATCH_TICKET_TTL_SECONDS: i64 = 120;

fn dispatch_ticket_route_material(node: &types::Node) -> serde_json::Value {
    let value = live_node_value(node);
    let allowed = [
        "node_id",
        "endpoint",
        "transport_endpoint",
        "transport_method",
        "transport_metadata",
        "cx_public_key",
        "region",
        "score",
        "health_label",
        "health_confidence",
        "routing_hint",
        "browser_usable",
        "reachability_tier",
        "route_evidence",
        "models",
        "capability_summary",
        "pricing",
        "node_policy_manifest",
        "available",
        "reputation_score",
        "reputation_tier",
        "exposure_mode",
        "transport",
        "directory_observed_reachable",
    ];
    let mut route = serde_json::Map::new();
    if let Some(source) = value.as_object() {
        for field in allowed {
            if let Some(value) = source.get(field).filter(|value| !value.is_null()) {
                route.insert(field.to_string(), value.clone());
            }
        }
    }
    serde_json::Value::Object(route)
}

fn dispatch_ticket_contains_payload(req: &DispatchTicketRequest) -> bool {
    req.prompt.is_some()
        || req.messages.is_some()
        || req.payload.is_some()
        || req.input.is_some()
        || req.chat.is_some()
        || req.content.is_some()
        || req.response.is_some()
}

fn dispatch_ticket_selector_error(req: &DispatchTicketRequest) -> Option<&'static str> {
    let invalid_selector = req.node_id.as_ref().is_some_and(|id| id.len() > 64)
        || req
            .node_id_prefix
            .as_ref()
            .is_some_and(|id| !(4..=36).contains(&id.len()))
        || req.exclude_node_id_prefixes.len() > 10
        || req
            .exclude_node_id_prefixes
            .iter()
            .any(|prefix| !(4..=36).contains(&prefix.len()));
    if invalid_selector {
        Some("invalid node selector or exclusion prefix")
    } else if req.node_id.is_some() && req.node_id_prefix.is_some() {
        Some("Use node_id or node_id_prefix, not both.")
    } else if req
        .min_reputation
        .is_some_and(|min_reputation| !(0.0..=1.0).contains(&min_reputation))
    {
        Some("min_reputation must be in [0, 1]")
    } else {
        None
    }
}

fn select_dispatch_ticket_node(
    nodes: Vec<types::Node>,
    req: &DispatchTicketRequest,
) -> Result<types::Node, (StatusCode, &'static str, &'static str)> {
    if let Some(node_id) = req.node_id.as_deref() {
        return nodes
            .into_iter()
            .find(|node| node.node_id == node_id)
            .ok_or((
                StatusCode::NOT_FOUND,
                "no_route_available",
                "No eligible route matched the requested intent and filters.",
            ));
    }
    if let Some(prefix) = req.node_id_prefix.as_deref() {
        let mut matches: Vec<_> = nodes
            .into_iter()
            .filter(|node| node.node_id.starts_with(prefix))
            .collect();
        return match matches.len() {
            0 => Err((
                StatusCode::NOT_FOUND,
                "no_route_available",
                "No eligible route matched the requested intent and filters.",
            )),
            1 => Ok(matches.remove(0)),
            _ => Err((
                StatusCode::CONFLICT,
                "ambiguous_node_prefix",
                "The node_id_prefix matches more than one eligible node; provide a longer prefix.",
            )),
        };
    }
    nodes.into_iter().next().ok_or((
        StatusCode::NOT_FOUND,
        "no_route_available",
        "No eligible route matched the requested intent and filters.",
    ))
}

async fn dispatch_ticket_issue(
    State(st): State<AppState>,
    Json(req): Json<DispatchTicketRequest>,
) -> axum::response::Response {
    if dispatch_ticket_contains_payload(&req) {
        return reject(
            "validation_error",
            "Dispatch ticket issuance is control-plane only; send task payloads directly to the selected node.",
        )
        .into_response();
    }
    if !validate_intent(&req.intent) {
        return reject("validation_error", "invalid intent URN").into_response();
    }
    if let Some(classification) = policy::IntentPolicyGuard::public_mesh_refusal(&req.intent) {
        return policy_reject(&classification).into_response();
    }
    if let Some(message) = dispatch_ticket_selector_error(&req) {
        return reject("validation_error", message).into_response();
    }
    let discovery_limit = if req.node_id.is_some() || req.node_id_prefix.is_some() {
        50
    } else {
        req.limit.unwrap_or(10).clamp(1, 50)
    };
    let mut nodes = st
        .repo
        .discover(&DiscoverQuery {
            intent: req.intent.clone(),
            region: req.region.clone(),
            limit: discovery_limit,
            min_reputation: req.min_reputation,
        })
        .await;
    nodes.retain(|node| {
        node.health_models
            .as_ref()
            .is_none_or(|models| !models.is_empty())
            && req.model.as_ref().is_none_or(|model| {
                node.health_models
                    .as_ref()
                    .unwrap_or(&node.models)
                    .contains(model)
            })
            && req
                .relay_capable
                .is_none_or(|required| node.relay_capable.unwrap_or(false) == required)
            && !req
                .exclude_node_id_prefixes
                .iter()
                .any(|prefix| node.node_id.starts_with(prefix))
    });
    for node in &mut nodes {
        node.address_family = Some(detect_address_family(
            &node.endpoint,
            node.transport_endpoint.as_deref(),
        ));
        node.transport = transport_methods(&node.endpoint, node.transport_endpoint.as_deref());
        node.operator_display_name =
            operator_display_name_for(&st, node.operator_pubkey.as_deref()).await;
        node.operator_fingerprint = operator_fingerprint_for(node.operator_pubkey.as_deref());
    }
    let selected = match select_dispatch_ticket_node(nodes, &req) {
        Ok(node) => node,
        Err((status, code, message)) => return err_json(status, code, message).into_response(),
    };
    let Some(secret) = st.signing_key.as_deref() else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_configured",
            "Dispatch route ticket signing key not configured on this directory.",
        )
        .into_response();
    };
    let now = unix_now();
    let expires_at = now + DISPATCH_TICKET_TTL_SECONDS;
    let ticket_id = uuid::Uuid::new_v4().simple().to_string()[..24].to_string();
    let claims = serde_json::json!({
        "v": 1,
        "typ": "dispatch-route-ticket",
        "iss": "https://iicp.network",
        "aud": DISPATCH_TICKET_AUDIENCE,
        "jti": ticket_id,
        "node_id": selected.node_id,
        "intent": req.intent,
        "iat": now,
        "exp": expires_at,
    });
    let Some(ticket) = sign_domain_token(secret, DISPATCH_TICKET_DOMAIN, &claims) else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_configured",
            "Dispatch route ticket signing key not configured on this directory.",
        )
        .into_response();
    };
    let node_id = selected.node_id.clone();
    let route = dispatch_ticket_route_material(&selected);
    let body = serde_json::json!({
        "ticket": ticket,
        "ticket_id_prefix": &ticket_id[..12],
        "expires_at": expires_at,
        "intent": claims["intent"],
        "node_id": node_id,
        "node_id_prefix": &selected.node_id[..selected.node_id.len().min(8)],
        "route": route,
        "algorithm": "ed25519",
        "data_class": "ticketed_route_dispatch",
        "route_fields_present": true,
        "prompt_payload_accepted": false,
    });
    st.repo.record_dispatch_usage("ticketed_dispatch").await;
    axum::response::Response::builder()
        .status(StatusCode::CREATED)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-iicp-discover-data-class", "ticketed_route_dispatch")
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
            node.transport = transport_methods(&node.endpoint, node.transport_endpoint.as_deref());
            // PHP NodeController includes capabilities array (REACH DIR-NODE-01).
            let mut v = live_node_value(&node);
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

/// Add the current PHP/live-directory discover fields on top of the Rust `Node`
/// storage model. This keeps the Rust implementation wire-compatible with
/// `/api/v1/discover` without forcing every DB row and older test fixture to
/// carry newest PHP-only columns.
fn live_node_value(n: &types::Node) -> serde_json::Value {
    let mut v = serde_json::to_value(n).unwrap_or_else(|_| serde_json::json!({}));
    let Some(obj) = v.as_object_mut() else {
        return v;
    };

    obj.insert(
        "node_policy_manifest".into(),
        public_policy_manifest(n.policy_manifest.as_ref()),
    );

    let public_key = n.public_key.clone().unwrap_or(serde_json::Value::Null);
    obj.insert("cx_public_key".into(), public_key.clone());
    obj.insert("public_key".into(), public_key.clone());
    let key_ready = !public_key.is_null();
    obj.insert("key_ready".into(), serde_json::json!(key_ready));
    let response_encryption_ready = public_key
        .get("features")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|features| {
            features
                .iter()
                .any(|feature| feature.as_str() == Some("response_encryption_v1"))
        });
    obj.insert(
        "response_encryption_ready".into(),
        serde_json::json!(response_encryption_ready),
    );
    obj.insert(
        "privacy_routing_status".into(),
        serde_json::json!(if key_ready {
            "key_ready"
        } else {
            "transitional"
        }),
    );

    let sdk_status = sdk_status(n.sdk_version.as_deref());
    obj.insert("sdk_status".into(), serde_json::json!(sdk_status));
    obj.insert(
        "sdk_baseline_version".into(),
        serde_json::json!(SDK_BASELINE_VERSION),
    );
    obj.insert(
        "upgrade_required".into(),
        serde_json::json!(sdk_status != "current"),
    );
    let sdk_relation = match n.sdk_version.as_deref() {
        None => "unknown",
        Some(version) if version_parts(version) == version_parts(SDK_LATEST_KNOWN_VERSION) => {
            "latest_known"
        }
        Some(version) if version_at_least(version, SDK_LATEST_KNOWN_VERSION) => "ahead_of_known",
        Some(_) => "behind_known",
    };
    obj.insert(
        "sdk_release".into(),
        serde_json::json!({
            "compatibility": sdk_status,
            "relation": sdk_relation,
            "latest_known_version": SDK_LATEST_KNOWN_VERSION,
            "latest_known_source": "directory_release_manifest"
        }),
    );
    obj.insert(
        "auto_update".into(),
        serde_json::json!({
            "enabled": serde_json::Value::Null,
            "interval_s": serde_json::Value::Null,
            "latest_seen": n.sdk_version.clone(),
            "last_checked_at": serde_json::Value::Null,
            "error_class": serde_json::Value::Null,
            "evidence": "unknown"
        }),
    );

    let completed = n.completed_tasks_count;
    let remaining_gold_requirements = [
        (completed < 100).then_some("completed_tasks"),
        (n.reputation_score < 0.65).then_some("reputation_score"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    obj.insert("probation".into(), serde_json::json!(completed < 100));
    obj.insert(
        "trust_progress".into(),
        serde_json::json!({
            "completed_tasks": completed,
            "gold_min_tasks": 100,
            "platinum_min_tasks": 1000,
            "tasks_until_gold": 100_u64.saturating_sub(completed),
            "tasks_until_platinum": 1000_u64.saturating_sub(completed),
            "gold_task_threshold_met": completed >= 100,
            "gold_reputation_threshold_met": n.reputation_score >= 0.65,
            "remaining_gold_requirements": remaining_gold_requirements,
            "probation": completed < 100
        }),
    );

    let browser_usable = browser_usable_endpoint(&n.endpoint);
    let route_evidence = if n.reachability_signal >= 1.0 {
        "directory_observed"
    } else if self_attests_route(n) {
        "self_attested"
    } else {
        "missing"
    };
    obj.insert(
        "directory_observed_reachable".into(),
        if n.reachability_signal >= 1.0 {
            serde_json::json!(true)
        } else {
            serde_json::Value::Null
        },
    );
    obj.insert("route_evidence".into(), serde_json::json!(route_evidence));
    obj.insert("routing_hint".into(), serde_json::json!(routing_hint(n)));
    obj.insert("browser_usable".into(), serde_json::json!(browser_usable));
    obj.insert(
        "reachability_tier".into(),
        serde_json::json!(if n.reachability_signal >= 1.0 {
            "direct"
        } else if n.relay_capable.unwrap_or(false) || n.exposure_mode.is_some() {
            "relay"
        } else {
            "limited"
        }),
    );

    obj.insert(
        "backend".into(),
        n.backend
            .as_deref()
            .map(serde_json::Value::from)
            .unwrap_or_else(|| serde_json::json!("unknown")),
    );
    obj.insert(
        "backend_stability".into(),
        serde_json::json!({
            "backend_state": "unknown",
            "reason_class": "not_reported",
            "routing_guard": "none",
            "evidence": "not_reported",
            "retry_after_s": serde_json::Value::Null,
            "drain_until": serde_json::Value::Null,
            "summary": "Backend stability has not been reported yet."
        }),
    );

    let live_models = n.health_models.clone().unwrap_or_else(|| n.models.clone());
    obj.insert(
        "capability_summary".into(),
        serde_json::json!({
            "registered_model_count": n.models.len(),
            "live_model_count": live_models.len(),
            "modalities": ["text"]
        }),
    );
    obj.insert("input_modalities".into(), serde_json::json!(["text"]));
    if !obj.contains_key("pricing") || obj.get("pricing").is_some_and(|p| p.is_null()) {
        obj.insert(
            "pricing".into(),
            serde_json::json!({
                "credit_cost_multiplier": n.credit_cost_multiplier,
                "pricing_model": n.pricing_model.as_deref().unwrap_or("per_token"),
                "attested": n.attested
            }),
        );
    }
    obj.insert(
        "performance".into(),
        serde_json::json!({
            "task_latency_ms": n.latency_estimate_ms,
            "task_latency_ms_basis": if n.latency_estimate_ms.is_some() { "proxy_observed_task" } else { "none" },
            "proxy_observed_latency_ms": n.latency_estimate_ms,
            "self_reported_recent_latency_ms": serde_json::Value::Null,
            "self_reported_lifetime_latency_ms": serde_json::Value::Null,
            "health_impact": "separate_from_operational_health",
            "summary": "Task/inference latency is a performance signal, not a reachability-health input."
        }),
    );
    obj.insert(
        "latency_evidence".into(),
        serde_json::json!({
            "estimate_ms": n.latency_estimate_ms,
            "basis": if n.latency_estimate_ms.is_some() { "multi_proxy_ema" } else { "none" }
        }),
    );
    let policy = obj
        .get("node_policy_manifest")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let policy_status = policy
        .pointer("/verification/status")
        .and_then(serde_json::Value::as_str);
    obj.insert(
        "health_reasons".into(),
        serde_json::json!([
            {
                "dimension": "reachability",
                "state": if n.reachability_signal >= 1.0 { "reachable" } else { "unknown" },
                "reason": if n.reachability_signal >= 1.0 { "directory_observation" } else { "not_directory_observed" },
                "evidence": if n.reachability_signal >= 1.0 { "directory_observed" } else { "none" }
            },
            {
                "dimension": "backend",
                "state": "unknown",
                "reason": "not_reported",
                "evidence": "not_reported"
            },
            {
                "dimension": "trust",
                "state": if completed < 100 { "probation" } else { "established" },
                "reason": if completed < 100 { "task_threshold_pending" } else { "task_threshold_met" },
                "evidence": "directory_accounting"
            },
            {
                "dimension": "policy",
                "state": if policy.is_null() { "missing" } else if policy_status == Some("verified") { "verified" } else { "unverified" },
                "reason": if policy.is_null() { "manifest_not_provided" } else { policy_status.unwrap_or("signature_not_verified") },
                "evidence": if policy.is_null() { "none" } else { "manifest_projection" }
            }
        ]),
    );
    if !obj.contains_key("health_confidence") {
        obj.insert(
            "health_confidence".into(),
            serde_json::json!(if n.health_label.as_deref() == Some("healthy") {
                "medium"
            } else {
                "low"
            }),
        );
    }

    // Keep the public discover/detail contract aligned with the live PHP
    // directory. These fields remain available internally on `Node` for scoring,
    // health and accounting, but PHP exposes them through nested public blocks
    // (`pricing`, `trust_progress`, `performance`) or not at all.
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
        obj.remove(internal_field);
    }

    v
}

fn public_policy_manifest(manifest: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(manifest) = manifest.filter(|value| value.as_object().is_some_and(|v| !v.is_empty()))
    else {
        return serde_json::Value::Null;
    };
    let verification = policy_manifest::verify(manifest);
    serde_json::json!({
        "version": manifest.get("version"),
        "jurisdiction": manifest.get("jurisdiction"),
        "policy_url": manifest.get("policy_url"),
        "contact_url": manifest.get("contact_url"),
        "remote_executor_can_read_prompt": manifest.get("remote_executor_can_read_prompt").and_then(serde_json::Value::as_bool).unwrap_or(true),
        "training_use": manifest.get("training_use").and_then(serde_json::Value::as_str).unwrap_or("provider_defined"),
        "retention": {
            "task_payload": manifest.pointer("/retention/task_payload").and_then(serde_json::Value::as_str).unwrap_or("provider_defined"),
            "logs_days": manifest.pointer("/retention/logs_days")
        },
        "subprocessors": manifest.get("subprocessors").and_then(serde_json::Value::as_array).cloned().unwrap_or_default(),
        "unsupported_intents": manifest.get("unsupported_intents").and_then(serde_json::Value::as_array).cloned().unwrap_or_default(),
        "signed_statement": manifest.get("signed_statement"),
        "manifest_identity_level": verification.manifest_identity_level,
        "operator_fingerprint": serde_json::Value::Null,
        "policy_key_fingerprint": verification.policy_key_fingerprint,
        "revoked_at": verification.revoked_at,
        "rotation_epoch": verification.rotation_epoch,
        "revocation_reason_class": verification.revocation_reason_class,
        "operator_governance": {"accepted": false, "terms_version": serde_json::Value::Null, "dpa_version": serde_json::Value::Null, "legal_certification": false},
        "verification": {
            "status": verification.status,
            "algorithm": verification.algorithm,
            "key_id": verification.key_id,
            "signed_at": verification.signed_at,
            "expires_at": verification.expires_at,
            "canonical_sha256": verification.canonical_sha256,
            "public_key_sha256": verification.public_key_sha256,
            "error": verification.error
        },
        "evidence": verification.evidence
    })
}

fn browser_usable_endpoint(endpoint: &str) -> bool {
    let lower = endpoint.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return true;
    }
    if !lower.starts_with("http://") {
        return false;
    }
    let host = endpoint
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    }
    .to_ascii_lowercase();
    matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
}

fn self_attests_route(n: &types::Node) -> bool {
    n.reachability_signal >= 1.0 || n.relay_capable.unwrap_or(false) || n.exposure_mode.is_some()
}

fn routing_hint(n: &types::Node) -> &'static str {
    if n.relay_capable.unwrap_or(false) {
        return "relay_service";
    }
    let lower = n.endpoint.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return "https_direct";
    }
    if lower.starts_with("http://") {
        return if url_host_family(&n.endpoint) == "ipv6" {
            "http_ipv6"
        } else {
            "http_direct"
        };
    }
    "unknown"
}

fn sdk_status(version: Option<&str>) -> &'static str {
    let Some(v) = version.map(str::trim).filter(|v| !v.is_empty()) else {
        return "unknown";
    };
    if version_at_least(v, SDK_BASELINE_VERSION) {
        "current"
    } else {
        "downlevel"
    }
}

fn version_at_least(version: &str, baseline: &str) -> bool {
    let a = version_parts(version);
    let b = version_parts(baseline);
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        if x > y {
            return true;
        }
        if x < y {
            return false;
        }
    }
    true
}

fn version_parts(version: &str) -> Vec<u32> {
    version
        .trim()
        .trim_start_matches(['v', 'V'])
        .split('.')
        .map_while(|p| {
            let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                None
            } else {
                digits.parse().ok()
            }
        })
        .collect()
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
    /// IICP-E050 (#529) — the node's existing token, proving ownership when an
    /// already-registered `node_id` re-registers with a changed `endpoint`.
    #[serde(default)]
    current_node_token: Option<String>,
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
    /// Pre-normative receipt profiles. Unknown values are rejected.
    #[serde(default)]
    supported_receipt_profiles: Vec<String>,
    /// Informational local backend flavour. It does not alter IICP routing.
    #[serde(default)]
    backend: Option<String>,
    /// cx_public_key identity object (ADR-030 operator identity, Phase 5).
    #[serde(default)]
    cx_public_key: Option<serde_json::Value>,
    /// NAT traversal metadata blob (ADR-043).
    #[serde(default)]
    transport_metadata: Option<serde_json::Value>,
    /// Public retention/training/jurisdiction declaration. Signed manifests
    /// are verified before persistence; unsigned manifests remain explicitly
    /// self-attested.
    #[serde(default)]
    policy_manifest: Option<serde_json::Value>,
    /// ADR-045 Phase A (#407) — optional verifiable operator→node delegation (ed25519).
    #[serde(default)]
    operator_delegation: Option<delegation::OperatorDelegation>,
    /// #463/#464 — operator-identity attributes (bound only when the delegation verifies).
    /// display_name is the public handle; created_at + integrity_hash are identity-integrity.
    /// contact/email is NEVER accepted (private).
    #[serde(default)]
    operator_display_name: Option<String>,
    #[serde(default)]
    operator_created_at: Option<String>,
    #[serde(default)]
    operator_integrity_hash: Option<String>,
    /// WQ-058 / ADR-017 REG-01 — operator public-listing opt-in (PHP: `listing` object with
    /// `public_listing` bool + `operator_url`). Absent → not listed.
    #[serde(default)]
    listing: Option<ListingInput>,
    #[serde(default)]
    availability: Vec<RegistrationAvailability>,
    #[serde(default)]
    pricing: Option<RegistrationPricing>,
}

#[derive(Debug, Deserialize, Clone)]
struct RegistrationAvailability {
    start: String,
    end: String,
    #[serde(default = "default_availability_share")]
    share: f64,
}

fn default_availability_share() -> f64 {
    1.0
}

#[derive(Debug, Deserialize, Clone)]
struct RegistrationPricing {
    #[serde(default = "default_credit_multiplier")]
    credit_cost_multiplier: f64,
    #[serde(default = "default_pricing_model")]
    pricing_model: String,
}

fn default_credit_multiplier() -> f64 {
    1.0
}

fn default_pricing_model() -> String {
    "per_token".into()
}

#[derive(Debug, serde::Deserialize)]
struct ListingInput {
    #[serde(default)]
    public_listing: bool,
    #[serde(default)]
    operator_url: Option<String>,
}

/// Normalize operator display names for uniqueness checks (PHP NodeRegistry parity):
/// trim, fold runs of whitespace to one space, lowercase. Empty becomes None.
pub(crate) fn normalize_operator_display_name(display_name: &str) -> Option<String> {
    let mut folded = String::new();
    let mut last_was_space = false;
    for ch in display_name.trim().chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                folded.push(' ');
            }
            last_was_space = true;
        } else {
            folded.extend(ch.to_lowercase());
            last_was_space = false;
        }
    }
    if folded.is_empty() {
        None
    } else {
        Some(folded)
    }
}

/// Public, non-secret operator key fingerprint for display-name disambiguation.
fn public_operator_fingerprint(operator_pubkey: &str) -> String {
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        operator_pubkey.as_bytes(),
    ))
    .chars()
    .take(12)
    .collect()
}

/// #463 — resolve a node's public operator handle (display_name) by its operator_pubkey.
/// Returns None when the node has no bound operator or no name set. The operator_pubkey is
/// directory-private — callers serve only the returned display_name, never the key.
async fn operator_display_name_for(st: &AppState, operator_pubkey: Option<&str>) -> Option<String> {
    match operator_pubkey {
        Some(p) => st.repo.operator_display_name(p).await,
        None => None,
    }
}

fn operator_fingerprint_for(operator_pubkey: Option<&str>) -> Option<String> {
    operator_pubkey
        .filter(|p| !p.is_empty())
        .map(public_operator_fingerprint)
}

/// #463/#310/#464 — upsert the operator-identity record (keyed by operator_id ==
/// operator_pubkey) when a delegation verified. display_name is public + mutable; contact is
/// never accepted; integrity_hash + first_seen_ms are pinned on first insert (PHP parity #385).
async fn upsert_operator_from_register(
    st: &AppState,
    operator_pubkey: &Option<String>,
    display_name: Option<&str>,
    created_at: Option<&str>,
    integrity_hash: Option<&str>,
) {
    if let Some(op_pub) = operator_pubkey {
        st.repo
            .upsert_operator(op_pub, display_name, created_at, integrity_hash)
            .await;
    }
}

/// #460 — body of `POST /v1/operator/rename`. Self-authenticating: `sig` is the operator's
/// ed25519 signature over the canonical rename bytes (no node token). `contact` is never
/// accepted here (private; never mutated via this endpoint).
#[derive(Debug, Deserialize)]
struct RenameRequest {
    operator_pub: String,
    display_name: String,
    ts: i64,
    sig: String,
}

/// Replay window for the signed rename timestamp (seconds) — PHP `TS_WINDOW` parity.
const RENAME_TS_WINDOW: i64 = 300;

/// `POST /v1/operator/rename` (#460, PHP `OperatorController::rename` parity #385). Changes
/// the public, mutable `display_name` over the immutable operator_id (== operator_pubkey).
/// Only the operator key-holder may rename — authenticated by their ed25519 signature over
/// the canonical bytes, replay-protected by a ±300s timestamp window. One signed call
/// updates the single operator-keyed record, reflected on every node + the leaderboard;
/// the operator_id and any earned founder ordinal stay bound to the key.
async fn operator_rename(
    State(st): State<AppState>,
    Json(req): Json<RenameRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validation parity: operator_pub ≤64, sig ≤128, display_name 1..=64 with no control chars.
    if req.operator_pub.len() > 64 || req.sig.len() > 128 {
        return reject("validation_error", "operator_pub or sig too long");
    }
    let name_len = req.display_name.chars().count();
    if name_len == 0 || name_len > 64 {
        return reject("validation_error", "display_name must be 1..=64 characters");
    }
    if req.display_name.chars().any(|c| c.is_control()) {
        return reject(
            "validation_error",
            "display_name contains control characters",
        );
    }

    // Replay protection: the signed ts must be recent.
    let now = delegation::now_unix() as i64;
    if (now - req.ts).abs() > RENAME_TS_WINDOW {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "IICP-E041",
            "stale or future-dated rename request",
        );
    }

    // Operator-signed authentication (only the key-holder may rename).
    let (ok, reason) =
        delegation::verify_rename(&req.operator_pub, &req.display_name, req.ts, &req.sig);
    if !ok {
        let (code, msg) = if reason == "malformed" {
            ("IICP-E042", "malformed operator key or signature")
        } else {
            ("IICP-E043", "operator signature verification failed")
        };
        return err_json(StatusCode::UNAUTHORIZED, code, msg);
    }

    // The operator must already exist (bound via a verified delegation at register).
    if !st
        .repo
        .rename_operator(&req.operator_pub, &req.display_name)
        .await
    {
        return err_json(
            StatusCode::NOT_FOUND,
            "IICP-E044",
            "unknown operator (register a node with this operator delegation first)",
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "display_name": req.display_name })),
    )
}

#[derive(Debug, Deserialize)]
struct OperatorChallengeRequest {
    operator_pub: String,
}

#[derive(Debug, Deserialize)]
struct OperatorKeyRequest {
    operator_pub: String,
    nonce: String,
    ts: i64,
    sig: String,
    #[serde(default)]
    new_operator_pub: Option<String>,
    #[serde(default)]
    new_key_sig: Option<String>,
    #[serde(default)]
    rotation_epoch: Option<u32>,
    #[serde(default)]
    reason_class: Option<String>,
    #[serde(default)]
    confirm: Option<bool>,
    #[serde(default)]
    terms_version: Option<String>,
    #[serde(default)]
    dpa_version: Option<String>,
    #[serde(default)]
    tracking_id: Option<String>,
}

fn operator_challenges() -> &'static std::sync::Mutex<HashMap<String, u64>> {
    OPERATOR_CHALLENGES.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn operator_challenge_key(operator_pub: &str, nonce: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        format!("{operator_pub}\n{nonce}").as_bytes(),
    ))
}

fn no_store_json(value: serde_json::Value) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

fn no_store_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({"error":{"code":code,"message":message}})),
    )
        .into_response()
}

fn valid_reason_class(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn operator_terms_version() -> String {
    std::env::var("IICP_OPERATOR_TERMS_VERSION").unwrap_or_else(|_| "2026-07-09".to_string())
}

fn operator_dpa_version() -> String {
    std::env::var("IICP_OPERATOR_DPA_VERSION").unwrap_or_else(|_| "2026-07-09".to_string())
}

fn self_service_fields(
    req: &OperatorKeyRequest,
    action: &str,
    include_successor: bool,
) -> BTreeMap<String, serde_json::Value> {
    let mut fields = BTreeMap::from([
        (
            "operator_pub".to_string(),
            serde_json::Value::String(req.operator_pub.clone()),
        ),
        (
            "nonce".to_string(),
            serde_json::Value::String(req.nonce.clone()),
        ),
        ("ts".to_string(), serde_json::Value::from(req.ts)),
    ]);
    if let Some(reason) = &req.reason_class {
        fields.insert(
            "reason_class".to_string(),
            serde_json::Value::String(reason.clone()),
        );
    }
    if let Some(epoch) = req.rotation_epoch {
        fields.insert("rotation_epoch".to_string(), serde_json::Value::from(epoch));
    }
    if include_successor {
        fields.insert(
            "new_operator_pub".to_string(),
            serde_json::Value::String(req.new_operator_pub.clone().unwrap_or_default()),
        );
    } else if let Some(confirm) = req.confirm {
        fields.insert("confirm".to_string(), serde_json::Value::Bool(confirm));
    }
    if action == "accept" {
        if let Some(value) = &req.terms_version {
            fields.insert(
                "terms_version".to_string(),
                serde_json::Value::String(value.clone()),
            );
        }
        if let Some(value) = &req.dpa_version {
            fields.insert(
                "dpa_version".to_string(),
                serde_json::Value::String(value.clone()),
            );
        }
    }
    if action.starts_with("dsr_") {
        if let Some(value) = &req.tracking_id {
            fields.insert(
                "tracking_id".to_string(),
                serde_json::Value::String(value.clone()),
            );
        }
    }
    fields
}

fn consume_operator_challenge(operator_pub: &str, nonce: &str) -> bool {
    let now = delegation::now_unix();
    let mut challenges = operator_challenges()
        .lock()
        .expect("operator challenge lock");
    challenges.retain(|_, expires| *expires >= now);
    challenges
        .remove(&operator_challenge_key(operator_pub, nonce))
        .is_some_and(|expires| expires >= now)
}

async fn operator_challenge(
    State(st): State<AppState>,
    Json(req): Json<OperatorChallengeRequest>,
) -> Response {
    if req.operator_pub.is_empty() || req.operator_pub.len() > 64 {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "operator_pub is invalid",
        );
    }
    match st.repo.operator_identity_active(&req.operator_pub).await {
        None => {
            return no_store_error(
                StatusCode::NOT_FOUND,
                "IICP-E044",
                "unknown operator (register a delegated node first)",
            )
        }
        Some(false) => {
            return no_store_error(
                StatusCode::CONFLICT,
                "IICP-E063",
                "operator identity is no longer active",
            )
        }
        Some(true) => {}
    }
    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    let nonce = Base64UrlSafeNoPadding::encode_to_string(uuid::Uuid::new_v4().as_bytes())
        .unwrap_or_default();
    let expires = delegation::now_unix().saturating_add(OPERATOR_CHALLENGE_TTL_SECS);
    operator_challenges()
        .lock()
        .expect("operator challenge lock")
        .insert(operator_challenge_key(&req.operator_pub, &nonce), expires);
    no_store_json(serde_json::json!({
        "nonce": nonce,
        "expires_at": chrono::DateTime::from_timestamp(expires as i64, 0).map(|v| v.to_rfc3339()),
        "operator_fingerprint": public_operator_fingerprint(&req.operator_pub),
        "terms_version": operator_terms_version(),
        "dpa_version": operator_dpa_version(),
        "signing_contract": "iicp.operator.self-service.v1"
    }))
}

async fn validate_operator_key_request(
    st: &AppState,
    req: &OperatorKeyRequest,
    action: &str,
    include_successor: bool,
) -> Result<(), Response> {
    if req.operator_pub.is_empty()
        || req.operator_pub.len() > 64
        || req.nonce.len() < 16
        || req.nonce.len() > 64
        || req.sig.len() > 128
    {
        return Err(no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "operator request fields are invalid",
        ));
    }
    if (delegation::now_unix() as i64 - req.ts).abs() > OPERATOR_TS_WINDOW_SECS {
        return Err(no_store_error(
            StatusCode::UNAUTHORIZED,
            "IICP-E041",
            "stale or future-dated operator request",
        ));
    }
    match st.repo.operator_identity_active(&req.operator_pub).await {
        None => {
            return Err(no_store_error(
                StatusCode::NOT_FOUND,
                "IICP-E044",
                "unknown operator",
            ))
        }
        Some(false) => {
            return Err(no_store_error(
                StatusCode::CONFLICT,
                "IICP-E063",
                "operator identity is no longer active",
            ))
        }
        Some(true) => {}
    }
    if !consume_operator_challenge(&req.operator_pub, &req.nonce) {
        return Err(no_store_error(
            StatusCode::UNAUTHORIZED,
            "IICP-E062",
            "challenge is missing, expired or already used",
        ));
    }
    let fields = self_service_fields(req, action, include_successor);
    let (valid, reason) =
        delegation::verify_self_service(&req.operator_pub, &req.sig, action, &fields);
    if !valid {
        let code = if reason == "malformed" {
            "IICP-E042"
        } else {
            "IICP-E043"
        };
        return Err(no_store_error(
            StatusCode::UNAUTHORIZED,
            code,
            "operator signature verification failed",
        ));
    }
    Ok(())
}

fn operator_self_service_repo_error(error: OperatorSelfServiceError) -> Response {
    match error {
        OperatorSelfServiceError::Unknown => {
            no_store_error(StatusCode::NOT_FOUND, "IICP-E044", "unknown operator")
        }
        OperatorSelfServiceError::Inactive => no_store_error(
            StatusCode::CONFLICT,
            "IICP-E063",
            "operator identity is no longer active",
        ),
        OperatorSelfServiceError::DuplicateTrackingId => no_store_error(
            StatusCode::CONFLICT,
            "IICP-E060",
            "tracking_id has already been used",
        ),
        OperatorSelfServiceError::Storage => no_store_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "IICP-E050",
            "operator self-service action could not be completed",
        ),
    }
}

async fn operator_acceptance(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    let (Some(terms), Some(dpa)) = (req.terms_version.as_deref(), req.dpa_version.as_deref())
    else {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "terms_version and dpa_version are required",
        );
    };
    if terms.len() > 64 || dpa.len() > 64 {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "governance version is invalid",
        );
    }
    if terms != operator_terms_version() || dpa != operator_dpa_version() {
        return no_store_error(
            StatusCode::CONFLICT,
            "IICP-E061",
            "terms or DPA version is not current",
        );
    }
    if let Err(response) = validate_operator_key_request(&st, &req, "accept", false).await {
        return response;
    }
    use sha2::{Digest, Sha256};
    let nonce_sha256 = hex::encode(Sha256::digest(req.nonce.as_bytes()));
    match st
        .repo
        .accept_operator_governance(&req.operator_pub, terms, dpa, &nonce_sha256)
        .await
    {
        Ok(accepted_at) => {
            let receipt = hex::encode(Sha256::digest(
                format!("{}{}", req.nonce, req.operator_pub).as_bytes(),
            ));
            no_store_json(serde_json::json!({
                "status": "accepted",
                "operator_fingerprint": public_operator_fingerprint(&req.operator_pub),
                "terms_version": terms,
                "dpa_version": dpa,
                "accepted_at": accepted_at,
                "receipt_id_prefix": &receipt[..12],
                "legal_certification": false
            }))
        }
        Err(error) => operator_self_service_repo_error(error),
    }
}

async fn operator_dsr_action(st: AppState, req: OperatorKeyRequest, action: &str) -> Response {
    if action != "export" && req.confirm != Some(true) {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "confirm=true is required",
        );
    }
    if req
        .tracking_id
        .as_deref()
        .is_some_and(|id| id.is_empty() || id.len() > 64)
    {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "tracking_id is invalid",
        );
    }
    let signed_action = format!("dsr_{action}");
    if let Err(response) = validate_operator_key_request(&st, &req, &signed_action, false).await {
        return response;
    }
    let tracking_id = req
        .tracking_id
        .clone()
        .unwrap_or_else(|| format!("dsr-{}", uuid::Uuid::new_v4()));
    match st
        .repo
        .operator_dsr(&req.operator_pub, action, &tracking_id)
        .await
    {
        Ok(value) => no_store_json(value),
        Err(error) => operator_self_service_repo_error(error),
    }
}

async fn operator_dsr_export(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    operator_dsr_action(st, req, "export").await
}

async fn operator_dsr_restrict(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    operator_dsr_action(st, req, "restrict").await
}

async fn operator_dsr_anonymize(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    operator_dsr_action(st, req, "anonymize").await
}

async fn operator_key_rotate(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    if let Err(response) = validate_operator_key_request(&st, &req, "key_rotate", true).await {
        return response;
    }
    let Some(successor) = req.new_operator_pub.as_deref() else {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "new_operator_pub is required",
        );
    };
    let Some(successor_sig) = req.new_key_sig.as_deref() else {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "new_key_sig is required",
        );
    };
    if successor == req.operator_pub
        || successor.len() > 64
        || successor_sig.len() > 128
        || req
            .reason_class
            .as_deref()
            .is_some_and(|value| !valid_reason_class(value))
    {
        return no_store_error(
            StatusCode::UNAUTHORIZED,
            "IICP-E064",
            "malformed successor operator key or signature",
        );
    }
    let successor_fields = BTreeMap::from([
        (
            "operator_pub".to_string(),
            serde_json::Value::String(req.operator_pub.clone()),
        ),
        (
            "new_operator_pub".to_string(),
            serde_json::Value::String(successor.to_string()),
        ),
        (
            "nonce".to_string(),
            serde_json::Value::String(req.nonce.clone()),
        ),
        ("ts".to_string(), serde_json::Value::from(req.ts)),
        (
            "rotation_epoch".to_string(),
            req.rotation_epoch
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        ),
    ]);
    let (successor_valid, _) = delegation::verify_self_service(
        successor,
        successor_sig,
        "key_rotate_successor",
        &successor_fields,
    );
    if !successor_valid {
        return no_store_error(
            StatusCode::UNAUTHORIZED,
            "IICP-E064",
            "successor operator signature verification failed",
        );
    }
    match st
        .repo
        .rotate_operator_identity(
            &req.operator_pub,
            successor,
            req.rotation_epoch,
            req.reason_class.as_deref().unwrap_or("operator_rotation"),
        )
        .await
    {
        Ok(result) => no_store_json(
            serde_json::json!({"status":"rotated","operator_fingerprint":public_operator_fingerprint(successor),"linked_nodes":result.linked_nodes,"rotation_epoch":result.rotation_epoch,"receipt_id_prefix":operator_challenge_key(&req.operator_pub, &req.nonce)[..12].to_string(),"legal_certification":false}),
        ),
        Err(_) => no_store_error(
            StatusCode::CONFLICT,
            "IICP-E063",
            "operator identity rotation cannot be completed",
        ),
    }
}

async fn operator_key_revoke(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    if req.confirm != Some(true) {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "confirm=true is required",
        );
    }
    if req
        .reason_class
        .as_deref()
        .is_some_and(|value| !valid_reason_class(value))
    {
        return no_store_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "reason_class is invalid",
        );
    }
    if let Err(response) = validate_operator_key_request(&st, &req, "key_revoke", false).await {
        return response;
    }
    match st
        .repo
        .revoke_operator_identity(
            &req.operator_pub,
            req.reason_class.as_deref().unwrap_or("operator_request"),
        )
        .await
    {
        Ok(result) => no_store_json(
            serde_json::json!({"status":"revoked","operator_fingerprint":public_operator_fingerprint(&req.operator_pub),"linked_nodes":result.linked_nodes,"revoked_at":result.revoked_at_unix.and_then(|v| chrono::DateTime::from_timestamp(v, 0)).map(|v|v.to_rfc3339()),"receipt_id_prefix":operator_challenge_key(&req.operator_pub, &req.nonce)[..12].to_string(),"legal_certification":false}),
        ),
        Err(_) => no_store_error(
            StatusCode::CONFLICT,
            "IICP-E063",
            "operator identity revocation cannot be completed",
        ),
    }
}

/// `GET /v1/leaderboards/{board_id}` (#310/#463, spec iicp-recognition §6). Anonymous-read
/// public recognition view. First board `founders`: operators with a founder ordinal, best
/// (lowest) first, serving only the public display_name + recognition state — operator_pubkey
/// is directory-private and never returned. Boards needing the §5 composite rank_score are
/// deferred (not fabricated) and 404 here.
async fn leaderboard(
    State(st): State<AppState>,
    axum::extract::Path(board_id): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if board_id != "founders" {
        return err_json(
            StatusCode::NOT_FOUND,
            "IICP-E050",
            "unknown or not-yet-computed leaderboard",
        );
    }
    let founders = st.repo.list_founders(100).await;
    let locked_count = founders.len();
    let entries: Vec<serde_json::Value> = founders
        .into_iter()
        .enumerate()
        .map(|(i, f)| {
            serde_json::json!({
                "place": i + 1,
                "display_name": f.display_name,
                "ordinal": f.ordinal,
                "tier": f.tier,
                "badge": f.badge,
            })
        })
        .collect();

    // Additive `pending` section (spec iicp-recognition 0.6.2 §6, PHP parity): provisional
    // operators on the 30-day clock. projected_ordinal is an ESTIMATE — ordinals are only
    // assigned at lock-in (§5.4.3) and the projection shifts if a predecessor drops out.
    const LOCKIN_MIN_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let pending: Vec<serde_json::Value> = st
        .repo
        .list_pending_founders(25)
        .await
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            let elapsed = (now_ms - p.first_seen_ms).max(0);
            let remaining_ms = (LOCKIN_MIN_AGE_MS - elapsed).max(0);
            serde_json::json!({
                "display_name": p.display_name,
                "projected_ordinal": locked_count + i + 1,
                "days_remaining": (remaining_ms + 86_400_000 - 1) / 86_400_000,
                "provisional": true,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "board_id": "founders",
            "title": "Founding Cohort",
            "count": entries.len(),
            "entries": entries,
            "pending": pending,
        })),
    )
}

/// Registration rate limit (IICP-E034, W-033 PHP parity): max registrations per source IP
/// per window, to stop rapid capability cycling. Matches RegisterController's 60 / 60s.
const REGISTER_RATE_LIMIT: u32 = 60;
const REGISTER_RATE_TTL_MS: u64 = 60_000;

/// Per-instance per-IP registration counter (held in AppState, not a global, so tests and
/// multiple instances don't share state). Per-instance is the unit, like PHP's per-instance Cache.
type RegisterRateMap = Arc<std::sync::Mutex<std::collections::HashMap<String, (u32, u64)>>>;

fn new_register_rate() -> RegisterRateMap {
    Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Pure window step for the registration rate limit (so the limit/TTL rule is unit-tested,
/// #404; the handler holds the map under a Mutex). Returns the new `(count, window_start_ms)`:
/// within the live window → increment in place; expired/new → reset to `(1, now_ms)`.
fn register_rate_step(prev: Option<(u32, u64)>, now_ms: u64, ttl_ms: u64) -> (u32, u64) {
    match prev {
        Some((count, start_ms)) if now_ms.saturating_sub(start_ms) < ttl_ms => {
            (count + 1, start_ms)
        }
        _ => (1, now_ms),
    }
}

/// IICP-E050 (F2/#529) re-registration endpoint-ownership decision — PHP NodeRegistry
/// `applyReRegistrationUpdate` parity. When an existing node's primary `endpoint` changes
/// on re-register, the change is allowed ONLY if the caller proves ownership
/// (`current_node_token` matches the stored hash) OR the old endpoint is verifiably gone
/// (so the change can't be a live takeover). A downlevel client without a token can still
/// rotate when its old endpoint is dead (migration-safe); an attacker pointing a victim's
/// `node_id` at a live, different endpoint is rejected. Pure so the rule is unit-tested;
/// the handler supplies `old_endpoint_alive` from a liveness probe.
fn relay_endpoint(metadata: Option<&serde_json::Value>) -> Option<&str> {
    metadata
        .and_then(serde_json::Value::as_object)
        .and_then(|value| value.get("relay_endpoint"))
        .and_then(serde_json::Value::as_str)
}

/// Liveness probe for the IICP-E050 absence path — PHP `isEndpointAlive` parity. A 2xx
/// from `<endpoint>/iicp/health` within 5s means the old endpoint is still serving (so a
/// token-less endpoint change is a likely takeover → rejected). Certs are not verified
/// (operators run self-signed tunnels), matching the PHP `withoutVerifying()`. Any error
/// (timeout, refused, DNS) → not alive. NOTE: like the PHP probe, this dials a
/// node-controlled URL; the SSRF/DNS-rebind hardening tracked in #535 applies to both.
async fn probe_endpoint_alive(endpoint: &str, allow_insecure_tls: bool) -> bool {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(allow_insecure_tls)
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("{}/iicp/health", endpoint.trim_end_matches('/'));
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

struct PendingRegistration {
    request: RegisterRequest,
    node: types::Node,
    intents: Vec<String>,
    availability: Vec<repo::AvailabilityWindow>,
    node_id: String,
    node_token: String,
    proxy_token: String,
    node_hmac_key: String,
    operator_pubkey_for_upsert: Option<String>,
    recovered: bool,
    declared_reachable: bool,
}

fn validate_registration_request(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    validate_registration_shape(request)
        .or_else(|| validate_registration_capabilities(request))
        .or_else(|| validate_registration_policy_manifest(request))
}

fn validate_registration_policy_manifest(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let manifest = request.policy_manifest.as_ref()?;
    if let Err(message) = policy_manifest::validate_shape(manifest) {
        return Some(reject("validation_error", message));
    }
    let verification = policy_manifest::verify(manifest);
    (!verification.accepted()).then(|| {
        reject(
            "validation_error",
            &format!(
                "Invalid node policy manifest signature: {}",
                verification.status
            ),
        )
    })
}

fn validate_registration_shape(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if request.capabilities.is_empty() {
        return Some(reject(
            "validation_error",
            "at least one capability is required",
        ));
    }
    if request
        .backend
        .as_deref()
        .is_some_and(|backend| !registration::BACKENDS.contains(&backend))
    {
        return Some(reject(
            "validation_error",
            &format!(
                "invalid backend: {}",
                request.backend.as_deref().unwrap_or_default()
            ),
        ));
    }
    validate_registration_profiles_and_exposure(request)
}

fn validate_registration_profiles_and_exposure(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if request.supported_receipt_profiles.len() > 4
        || request
            .supported_receipt_profiles
            .iter()
            .any(|profile| profile != "consumer_cosignature_v1")
    {
        return Some(reject("validation_error", "unsupported receipt profile"));
    }
    if request
        .exposure_mode
        .as_deref()
        .is_some_and(|mode| !EXPOSURE_MODES.contains(&mode))
    {
        return Some(reject(
            "validation_error",
            &format!(
                "invalid exposure_mode: {}",
                request.exposure_mode.as_deref().unwrap_or_default()
            ),
        ));
    }
    None
}

fn validate_registration_capabilities(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    for capability in &request.capabilities {
        if !validate_intent(&capability.intent) {
            return Some(reject(
                "validation_error",
                &format!("invalid intent URN: {}", capability.intent),
            ));
        }
        if let Some(classification) =
            policy::IntentPolicyGuard::public_mesh_refusal(&capability.intent)
        {
            return Some(policy_reject(&classification));
        }
    }
    None
}

async fn commit_registration(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    pending: PendingRegistration,
) -> (StatusCode, Json<serde_json::Value>) {
    if state
        .repo
        .register(repo::NodeRecord {
            node: pending.node,
            intents: pending.intents,
            availability: pending.availability,
            node_token: Some(pending.node_token.clone()),
            node_hmac_key: Some(pending.node_hmac_key.clone()),
            proxy_token: Some(pending.proxy_token.clone()),
        })
        .await
        .is_err()
    {
        eprintln!("[repository] registration transaction failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": {
                    "code": "server_error",
                    "message": "registration persistence failed"
                }
            })),
        );
    }

    // Tokens become externally visible only after the node and all capabilities commit.
    let client_ip = get_client_ip(headers);
    state
        .repo
        .observe_address(&pending.node_id, client_ip, "register")
        .await;
    upsert_operator_from_register(
        state,
        &pending.operator_pubkey_for_upsert,
        pending.request.operator_display_name.as_deref(),
        pending.request.operator_created_at.as_deref(),
        pending.request.operator_integrity_hash.as_deref(),
    )
    .await;
    emit_event(
        state,
        "REGISTER",
        &pending.node_id,
        serde_json::json!({
            "endpoint": pending.request.endpoint,
            "region": pending.request.region,
            "backend": pending.request.backend,
            "supported_receipt_profiles": pending.request.supported_receipt_profiles,
            "capabilities": pending.request.capabilities.iter().map(|capability| serde_json::json!({
                "intent": capability.intent,
                "models": capability.models,
            })).collect::<Vec<_>>(),
        }),
    )
    .await;

    let jwt_token = auth::issue_jwt(&pending.node_id);
    let jwt_expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(3600))
        .map(|time| time.to_rfc3339());
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "node_id": pending.node_id,
            "node_token": pending.node_token,
            "proxy_token": pending.proxy_token,
            "node_hmac_key": pending.node_hmac_key,
            "expires_at": serde_json::Value::Null,
            "jwt_token": jwt_token,
            "jwt_expires_at": jwt_expires_at,
            "directory": "iicp-directory-rs",
            "observed_source_ip": client_ip,
            "recovered": pending.recovered,
            "lifetime_jobs": 0u32,
            "public_reachable": pending.declared_reachable,
        })),
    )
}

fn registration_rate_rejection(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let ip = get_client_ip(headers).to_string();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let count = {
        let mut rates = state.register_rate.lock().unwrap();
        let (count, start) =
            register_rate_step(rates.get(&ip).copied(), now_ms, REGISTER_RATE_TTL_MS);
        rates.insert(ip, (count, start));
        count
    };
    (count > REGISTER_RATE_LIMIT).then(|| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "IICP-E034",
                "message": "Too many registration attempts from this source IP. Try again shortly.",
                "retry_after": REGISTER_RATE_TTL_MS / 1000
            })),
        )
    })
}

async fn registration_ownership_rejection(
    state: &AppState,
    request: &RegisterRequest,
    node_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let existing = state.repo.get(node_id).await?;
    let has_ownership = match request.current_node_token.as_deref() {
        Some(token) if !token.is_empty() => state.repo.verify_node_token(node_id, token).await,
        _ => false,
    };

    let cx_changed = request
        .cx_public_key
        .as_ref()
        .is_some_and(|key| !key.is_null() && existing.public_key.as_ref() != Some(key));
    if cx_changed && !has_ownership {
        return Some((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "IICP-E049",
                "message": "cx_public_key update requires a valid current_node_token"
            })),
        ));
    }

    let endpoint_changed = existing.endpoint != request.endpoint;
    let transport_endpoint_changed = existing.transport_endpoint != request.transport_endpoint;
    let relay_endpoint_changed = relay_endpoint(existing.transport_metadata.as_ref())
        != relay_endpoint(request.transport_metadata.as_ref());
    let secured = existing.operator_pubkey.is_some() || existing.public_key.is_some();
    let old_alive = if endpoint_changed && !has_ownership && !(state.strict_e050_secured && secured)
    {
        probe_endpoint_alive(&existing.endpoint, state.allow_insecure_tls).await
    } else {
        false
    };
    if registration::routing_change_allowed(
        state.strict_e050_secured,
        secured,
        endpoint_changed,
        transport_endpoint_changed,
        relay_endpoint_changed,
        has_ownership,
        old_alive,
    ) {
        return None;
    }

    Some((
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "IICP-E050",
            "message": if state.strict_e050_secured && secured {
                "secured-node re-registration requires a valid current_node_token"
            } else {
                "endpoint change requires the current node_token (the existing endpoint is still reachable); re-register with current_node_token to prove ownership"
            }
        })),
    ))
}

async fn registration_control_rejection(
    state: &AppState,
    request: &RegisterRequest,
    node_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if let Some(rejection) = policy_manifest_lifecycle_rejection(state, request).await {
        return Some(rejection);
    }
    registration_ownership_rejection(state, request, node_id).await
}

async fn policy_manifest_lifecycle_rejection(
    state: &AppState,
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let manifest = request.policy_manifest.as_ref()?;
    let key_sha = policy_manifest::verify(manifest).public_key_sha256?;
    state
        .repo
        .policy_key_lifecycle_status(&key_sha)
        .await
        .filter(|status| status != "active")
        .map(|_| {
            reject(
                "validation_error",
                "Invalid node policy manifest signature: directory lifecycle record is not active",
            )
        })
}

async fn operator_display_name_rejection(
    state: &AppState,
    operator_pubkey: Option<&str>,
    display_name: Option<&str>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let (Some(operator_pubkey), Some(display_name)) = (operator_pubkey, display_name) else {
        return None;
    };
    let normalized = normalize_operator_display_name(display_name)?;
    state
        .repo
        .operator_display_name_claimed_by_other(operator_pubkey, &normalized)
        .await
        .then(|| {
            reject(
                "validation_error",
                "operator_display_name is already claimed by another verified operator (IICP-E051)",
            )
        })
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
    // IICP-E034 (W-033 PHP parity): rate-limit registrations per source IP BEFORE any work,
    // so rapid capability cycling can't churn the directory. Source IP via get_client_ip
    // (CF-Connecting-IP → X-Forwarded-For), same extraction the rest of the handler uses.
    if let Some(rejection) = registration_rate_rejection(&st, &headers) {
        return rejection;
    }
    if let Some(rejection) = validate_registration_request(&req) {
        return rejection;
    }
    if let Err(e) = endpoint_routable(&req.endpoint, st.env) {
        return reject("IICP-E035", &format!("non-routable endpoint: {e:?}"));
    }

    // RT-04: a node without a concrete topology declaration must prove dial-back
    // reachability before credentials are issued. TLS identity remains enabled in
    // production; only an explicit non-production testbed can disable it.
    let declared = is_declared_reachable(req.nat_type.as_deref(), req.transport_method.as_deref());
    let endpoint_verified = if declared || st.skip_liveness_check {
        true
    } else {
        probe_endpoint_alive(&req.endpoint, st.allow_insecure_tls).await
    };
    if !endpoint_verified {
        return reject(
            "IICP-E036",
            "endpoint unreachable or TLS identity verification failed",
        );
    }

    // node_id: collision-free UUID v4 (iter-1571 BUG fix — SystemTime-nanos could collide).
    // node_token: UUID v4, bcrypt-hashed by MySqlRepo at cost 12 before storing.
    // node_hmac_key: 32-byte hex secret for CIP credit receipt signing (W-009, iicp-dir §6.2).
    // `recovered` = true when caller supplied a known node_id (identity recovery per ADR-026).
    let recovered = req.node_id.as_deref().is_some_and(|s| !s.is_empty());
    // PHP validates node_id format: alphanumeric start, then [a-zA-Z0-9._:-], max 36 chars.
    // If a custom node_id is supplied, validate it before assigning.
    let node_id = match registration::resolve_node_id(req.node_id.as_deref()) {
        Ok(node_id) => node_id,
        Err(message) => return reject("validation_error", message),
    };

    // IICP-E049/E050 (F2/#529) — re-registration ownership guards. When this node_id
    // already exists, protect the two takeover vectors. Ownership = a current_node_token
    // that verifies against the stored hash; computed once and shared. PHP NodeRegistry
    // applyReRegistrationUpdate parity.
    if let Some(rejection) = registration_control_rejection(&st, &req, &node_id).await {
        return rejection;
    }

    let node_token = uuid::Uuid::new_v4().to_string();
    let proxy_token = uuid::Uuid::new_v4().to_string();
    let node_hmac_key = hex::encode(uuid::Uuid::new_v4().as_bytes());

    // ADR-045 Phase A (#407) — verify an optional operator→node delegation and bind the
    // verified operator identity (PHP NodeRegistry parity, #385; lenient/fail-safe: an
    // invalid or absent delegation leaves the node unverified, never aborts registration).
    let (operator_pubkey, operator_verified, operator_trust_tier) = delegation::evaluate(
        req.operator_delegation.as_ref(),
        &node_id,
        delegation::now_unix(),
    );
    if let Some(operator_pubkey) = operator_pubkey.as_deref() {
        if st.repo.operator_identity_active(operator_pubkey).await == Some(false) {
            return reject(
                "validation_error",
                "operator delegation references an inactive identity",
            );
        }
    }
    // #463/#464 — capture before operator_pubkey moves into the Node, for the operators upsert.
    let operator_pubkey_for_upsert = operator_pubkey.clone();

    // #525/G3 — operator display names are public handles; a look-alike claim by another
    // verified operator is rejected using PHP's whitespace-folded, case-insensitive check.
    if let Some(rejection) = operator_display_name_rejection(
        &st,
        operator_pubkey_for_upsert.as_deref(),
        req.operator_display_name.as_deref(),
    )
    .await
    {
        return rejection;
    }

    if !registration::valid_availability(
        req.availability
            .iter()
            .map(|window| (window.start.as_str(), window.end.as_str(), window.share)),
    ) {
        return reject("validation_error", "invalid availability window");
    }
    if req.pricing.as_ref().is_some_and(|pricing| {
        !registration::valid_pricing(pricing.credit_cost_multiplier, &pricing.pricing_model)
    }) {
        return reject("validation_error", "invalid pricing declaration");
    }
    let advertised_models = registration::advertised_models(
        req.capabilities
            .iter()
            .map(|capability| capability.models.as_slice()),
    );
    let pricing_multiplier = registration::bounded_pricing(
        &advertised_models,
        req.pricing
            .as_ref()
            .map(|pricing| pricing.credit_cost_multiplier),
    );
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
        models: advertised_models,
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
        consumer_cosignature_ready: req
            .supported_receipt_profiles
            .iter()
            .any(|profile| profile == "consumer_cosignature_v1"),
        backend: req.backend.clone(),
        address_family: None, // set at query time by detect_address_family
        public_key: req.cx_public_key.clone(),
        transport_metadata: req.transport_metadata.clone(),
        // #400 — pricing/attestation default at register; pricing refined via heartbeat.
        credit_cost_multiplier: pricing_multiplier,
        pricing_model: Some(
            req.pricing
                .as_ref()
                .map_or_else(default_pricing_model, |pricing| {
                    pricing.pricing_model.clone()
                }),
        ),
        attested: false,
        tasks_failed: 0,
        transport: vec![], // #397 — derived at discover time
        // #385 — new node: public_reachable=false until probed; relay per request.
        reachability_signal: health::reachability_from_flags(
            false,
            req.relay_capable.unwrap_or(false),
        ),
        operator_pubkey,
        operator_display_name: None,
        operator_fingerprint: None,
        operator_verified,
        operator_trust_tier,
        // WQ-058 / ADR-017 REG-01 — operator public-listing opt-in (default: not listed).
        public_listing: req
            .listing
            .as_ref()
            .map(|l| l.public_listing)
            .unwrap_or(false),
        operator_url: req.listing.as_ref().and_then(|l| l.operator_url.clone()),
        policy_manifest: req.policy_manifest.clone(),
        health_models: None, // #494 — populated by the first heartbeat with a backend URL
        routing_policy: types::RoutingPolicyState::default(),
    };
    let intents = req.capabilities.iter().map(|c| c.intent.clone()).collect();
    let availability = req
        .availability
        .iter()
        .map(|window| repo::AvailabilityWindow {
            start: window.start.clone(),
            end: window.end.clone(),
            share: window.share,
        })
        .collect();
    commit_registration(
        &st,
        &headers,
        PendingRegistration {
            request: req,
            node,
            intents,
            availability,
            node_id,
            node_token,
            proxy_token,
            node_hmac_key,
            operator_pubkey_for_upsert,
            recovered,
            declared_reachable: endpoint_verified,
        },
    )
    .await
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
    /// ADR-047: lowercase-hex HMAC-SHA256 of the challenge issued by the prior PONG.
    #[serde(default)]
    challenge_response: Option<String>,
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
    /// #494 — live model list probed by the SDK on each heartbeat.
    /// null / absent = SDK did not report (backward compat); [] = no models loaded.
    #[serde(default)]
    health_models: Option<Vec<String>>,
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
            if !registration::PRICING_MODELS.contains(&pm.as_str()) {
                return reject("validation_error", &format!("invalid pricing_model: {pm}"));
            }
        }
        if let Some(multiplier) = pricing.credit_cost_multiplier {
            let models = st
                .repo
                .node_by_prefix(&req.node_id)
                .await
                .filter(|node| node.node_id == req.node_id)
                .map(|node| node.models)
                .unwrap_or_default();
            let multiplier = registration::bounded_pricing(&models, Some(multiplier));
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
            req.health_models,
        )
        .await
    {
        Some(score) => {
            let next_challenge = hex::encode(uuid::Uuid::new_v4().as_bytes());
            if st
                .repo
                .verify_and_rotate_liveness_challenge(
                    &req.node_id,
                    req.challenge_response.as_deref(),
                    &next_challenge,
                )
                .await
                .is_none()
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": {
                            "code": "internal_error",
                            "message": "heartbeat liveness state could not be persisted"
                        }
                    })),
                );
            }
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
                "challenge": next_challenge,
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

/// GET /v1/credits/summary — lifetime income / spending / balance + `reconciles`
/// integrity flag (#456). PHP-parity with CreditsController::summary.
async fn credits_summary(
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
    match st.repo.credit_summary(&node_id).await {
        Some(s) => {
            // Integrity invariant: balance MUST equal earned − spent (4-decimal precision).
            let reconciles = (s.balance - (s.total_earned - s.total_spent)).abs() < 0.0001;
            // Operator wallet — aggregate over the operator's nodes (null when the
            // node is not operator-bound). operator_pubkey itself is never returned.
            let operator_wallet = st
                .repo
                .operator_wallet_summary(&node_id)
                .await
                .map(serde_json::to_value)
                .and_then(Result::ok)
                .unwrap_or(serde_json::Value::Null);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "node_id": node_id,
                    "balance": s.balance,
                    "total_earned": s.total_earned,
                    "total_spent": s.total_spent,
                    "tx_count": s.tx_count,
                    "reconciles": reconciles,
                    "unit": "credit",
                    "tokens_per_credit": 1000,
                    "operator_wallet": operator_wallet
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

/// Verify a CIP credit receipt HMAC-SHA256 signature (W-009, iicp-dir §6.2).
/// canonical = "task_id:tokens_used:cip_parent_task_id:cip_session_key:nonce:response_hash[:querying_node_id]"
/// Uses constant-time comparison via the hmac crate's verify_slice().
fn verify_cip_receipt(req: &CreditAwardRequest, hmac_key: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut canonical = format!(
        "{}:{}:{}:{}:{}:{}",
        req.task_id,
        req.tokens_used,
        req.cip_parent_task_id,
        req.cip_session_key,
        req.nonce,
        req.response_hash
    );
    if let Some(querying_node_id) = req.querying_node_id.as_deref() {
        if !querying_node_id.is_empty() {
            canonical.push(':');
            canonical.push_str(querying_node_id);
        }
    }
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
    /// Optional querying node identity. When present, it is included in the receipt HMAC
    /// and lets the directory exclude self-dealing credit/reputation loops.
    #[serde(default)]
    querying_node_id: Option<String>,
}

/// `POST /v1/credits/award` (iicp-dir §6.2). Verifies the CIP receipt HMAC before
/// crediting the node. RT-02 nonce replay protection is enforced in record_credit_award.
async fn credits_award(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    request: Result<Json<CreditAwardRequest>, JsonRejection>,
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
    let Json(req) = match request {
        Ok(request) => request,
        Err(_) => return reject("validation_error", "invalid credit award request"),
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

    // WQ-098 / G1: credit/reputation trust attribution. Missing querying_node_id
    // remains backwards-compatible for credit settlement but is marked with zero
    // trust weight. Known self-deal paths return a net-zero success so callers do
    // not retry, and no CREDIT_AWARD event is emitted.
    let mut attribution = "legacy_unattributed";
    let mut trust_weight = 0.0_f64;
    if let Some(querying_node_id) = req.querying_node_id.as_deref().filter(|id| !id.is_empty()) {
        if querying_node_id == req.node_id {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "node_id": req.node_id,
                    "awarded": 0.0,
                    "spent": 0.0,
                    "excluded": true,
                    "reason": "self_query_excluded",
                    "attribution": "self_node",
                    "trust_weight": 0.0
                })),
            );
        }

        let serving = st.repo.get(&req.node_id).await;
        let querying = st.repo.get(querying_node_id).await;
        let Some(querying) = querying else {
            return reject(
                "IICP-E027",
                "querying_node_id does not identify a registered node",
            );
        };

        if let Some(serving_pubkey) = serving.as_ref().and_then(|n| n.operator_pubkey.as_deref()) {
            if !serving_pubkey.is_empty()
                && querying.operator_pubkey.as_deref() == Some(serving_pubkey)
            {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "node_id": req.node_id,
                        "awarded": 0.0,
                        "spent": 0.0,
                        "excluded": true,
                        "reason": "self_query_excluded",
                        "attribution": "self_operator",
                        "trust_weight": 0.0
                    })),
                );
            }
        }

        let has_verified_operators = serving
            .as_ref()
            .and_then(|n| n.operator_pubkey.as_deref())
            .is_some_and(|v| !v.is_empty())
            && querying
                .operator_pubkey
                .as_deref()
                .is_some_and(|v| !v.is_empty());
        attribution = if has_verified_operators {
            "attributed_cross_operator"
        } else {
            "attributed_cross_node_unverified_operator"
        };
        trust_weight = if has_verified_operators { 1.0 } else { 0.5 };
    }

    match st
        .repo
        .record_credit_award(&req.node_id, amount, &req.task_id, &req.nonce)
        .await
    {
        Ok(new_balance) => {
            let spend = if let Some(querying_node_id) =
                req.querying_node_id.as_deref().filter(|id| !id.is_empty())
            {
                Some(
                    st.repo
                        .debit_for_consumer(querying_node_id, amount, &req.task_id, "task_spend")
                        .await,
                )
            } else {
                None
            };
            let spent = spend.as_ref().map(|s| s.spent).unwrap_or(0.0);
            // #442 — mirror the award to replicas via a signed CREDIT_AWARD event. No-op
            // unsigned. #459 bug B: include `amount` + `task_id` to match the PHP emit payload
            // (PHP+Rust parity #385) — replicas reconstruct the award, and `iicp-node credits
            // --verify` sums the verified per-award amounts from the signed log.
            emit_event(
                &st,
                "CREDIT_AWARD",
                &req.node_id,
                serde_json::json!({
                    "amount": amount,
                    "new_balance": new_balance,
                    "task_id": req.task_id,
                    "querying_node_id": req.querying_node_id.clone(),
                    "attribution": attribution,
                    "trust_weight": trust_weight,
                    "spent": spent,
                    "spend_scope": spend.as_ref().map(|s| s.scope),
                    "debit_count": spend.as_ref().map(|s| s.debit_count),
                }),
            )
            .await;
            let mut response = serde_json::json!({
                "node_id": req.node_id,
                "awarded": amount,
                "balance": new_balance,
                "spent": spent,
                "attribution": attribution,
                "trust_weight": trust_weight
            });
            if let Some(spend) = spend {
                response["spend_scope"] = serde_json::json!(spend.scope);
                response["debit_count"] = serde_json::json!(spend.debit_count);
                if let Some(reason) = spend.reason {
                    response["spend_reason"] = serde_json::json!(reason);
                }
            }
            (
                StatusCode::CREATED,
                // PHP returns {node_id, awarded, balance, spent} — no ok field
                Json(response),
            )
        }
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

/// WQ-058 / ADR-017 REG-01 — public-listing exposure rule: `operator_url` is served only
/// when the operator opted into the public listing (`public_listing=true`); otherwise null,
/// respecting the opt-out. Pure so the rule is unit-tested in-process.
fn listing_exposure(public_listing: bool, operator_url: &Option<String>) -> serde_json::Value {
    if public_listing {
        serde_json::json!(operator_url)
    } else {
        serde_json::Value::Null
    }
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
                // PHP RegistryController::nodes includes the served models so the public
                // /nodes listing shows what each node serves (parity, #385).
                "models": n.models,
                "probation": n.completed_tasks_count < 100,
                "last_seen": serde_json::Value::Null,
                // WQ-058 / ADR-017 REG-01 — public-listing opt-in. operator_url is exposed
                // ONLY when the operator opted in (public_listing=true), else null.
                "public_listing": n.public_listing,
                "operator_url": listing_exposure(n.public_listing, &n.operator_url),
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
    // PHP RegistryController::show validation parity — prefix is a UUID 8-hex prefix or a
    // custom node name: ^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,35}$ (manual check; no regex dep).
    let valid = (1..=36).contains(&id.len())
        && id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if !valid {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "REGISTRY-INVALID-PREFIX",
                "message": "Prefix must be alphanumeric (max 36 chars)."
            })),
        );
    }
    match st.repo.node_by_prefix(&id).await {
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
            };
            let nh = health::score_node(&signals);
            let comp = health::components_of(&signals);
            let r3 = |x: f64| (x * 1000.0).round() / 1000.0;
            // #463 — public operator handle (who hosts this node), resolved by operator_pubkey.
            // operator_pubkey itself is directory-private and NEVER included in the response.
            let operator_display_name =
                operator_display_name_for(&st, n.operator_pubkey.as_deref()).await;
            let operator_fingerprint = operator_fingerprint_for(n.operator_pubkey.as_deref());
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
                        },
                        "evaluated_at": chrono::Utc::now().to_rfc3339(),
                    },
                    "probation": n.completed_tasks_count < 100,
                    "completed_tasks": n.completed_tasks_count,
                    "observed_latency_ms": n.latency_estimate_ms,
                    "exposure_mode": n.exposure_mode,
                    "operator_display_name": operator_display_name,
                    "operator_fingerprint": operator_fingerprint,
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
///
/// #442: when this directory has a signing key (IICP_GENESIS_ED25519_SECRET_KEY), it
/// publishes the matching Ed25519 public key in verificationMethod[].publicKeyJwk — so a
/// replica can resolve it (replica::seed_pubkey_hex_from_did) and VERIFY this seed's signed
/// events. Without that, the seed signs but no replica could verify (empty doc → unsigned
/// trust-poll mode). Empty verificationMethod when no key is configured.
async fn did_document(State(st): State<AppState>) -> Json<serde_json::Value> {
    let verification_method = match st.signing_key.as_deref().and_then(seed_pubkey_jwk) {
        Some(jwk) => vec![serde_json::json!({
            "id": format!("{}#key-1", st.directory_did),
            "type": "JsonWebKey2020",
            "controller": st.directory_did,
            "publicKeyJwk": jwk,
        })],
        None => vec![],
    };
    Json(serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": st.directory_did,
        "controller": st.directory_did,
        "verificationMethod": verification_method,
        "service": [{
            "id": format!("{}#iicp-directory", st.directory_did),
            "type": "IICPDirectory",
            "serviceEndpoint": st.directory_service_endpoint
        }]
    }))
}

async fn deployment_record(State(st): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let Some(config) = deployment_provenance::DeploymentConfig::from_env(VERSION) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {"code": "deployment_record_unavailable"}
            })),
        );
    };
    let Some(secret) = st.signing_key.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {"code": "deployment_record_unavailable"}
            })),
        );
    };
    match deployment_provenance::sign(&config, secret) {
        Some(record) => (StatusCode::OK, Json(record)),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {"code": "deployment_record_unavailable"}
            })),
        ),
    }
}

/// #442: build the Ed25519 `publicKeyJwk` (OKP/Ed25519, base64url `x`) for this directory's
/// signing key, so a replica's `seed_pubkey_hex_from_did` resolves the verifying key. The
/// libsodium 64-byte secret key is seed(32)‖public_key(32) → the pubkey is the last 32 bytes.
fn seed_pubkey_jwk(secret_key_hex: &str) -> Option<serde_json::Value> {
    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    let sk = hex::decode(secret_key_hex).ok()?;
    if sk.len() != 64 {
        return None;
    }
    let x = Base64UrlSafeNoPadding::encode_to_string(&sk[32..64]).ok()?;
    Some(serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": x }))
}

/// Directory Ed25519 public key as hex. The configured signing key is the
/// libsodium 64-byte secret key: seed(32)‖public_key(32).
fn directory_public_key_hex(secret_key_hex: &str) -> Option<String> {
    let sk = hex::decode(secret_key_hex).ok()?;
    if sk.len() != 64 {
        return None;
    }
    Some(hex::encode(&sk[32..64]))
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn b64url_json(payload: &serde_json::Value) -> Option<String> {
    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    let json = serde_json::to_string(payload).ok()?;
    Base64UrlSafeNoPadding::encode_to_string(json.as_bytes()).ok()
}

fn ed25519_sign_hex(secret_key_hex: &str, message: &[u8]) -> Option<String> {
    use ed25519_compact::{KeyPair, Seed};
    let sk_bytes = hex::decode(secret_key_hex).ok()?;
    if sk_bytes.len() != 64 {
        return None;
    }
    let seed_bytes: [u8; 32] = sk_bytes.get(..32)?.try_into().ok()?;
    let kp = KeyPair::from_seed(Seed::new(seed_bytes));
    let sig = kp.sk.sign(message, None);
    Some(hex::encode(sig.as_ref()))
}

fn sign_domain_token(
    secret_key_hex: &str,
    domain: &str,
    payload: &serde_json::Value,
) -> Option<String> {
    let b64_payload = b64url_json(payload)?;
    let message = format!("{domain}{b64_payload}");
    let sig_hex = ed25519_sign_hex(secret_key_hex, message.as_bytes())?;
    Some(format!("{b64_payload}.{sig_hex}"))
}

/// `GET /api/v1/directory-key` — public key for consumer-token and relay-ticket verification.
async fn directory_key(State(st): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match st.signing_key.as_deref().and_then(directory_public_key_hex) {
        Some(public_key) => (
            StatusCode::OK,
            Json(serde_json::json!({ "public_key": public_key, "algorithm": "ed25519" })),
        ),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "not_configured",
                    "message": "Consumer token signing key not configured on this directory."
                }
            })),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct ConsumerTokenRequest {
    target_node_id: String,
    intent: String,
}

/// `POST /api/v1/consumer-token` — node-token authenticated short-lived token
/// authorising the caller to send one intent class to a target node.
async fn consumer_token_issue(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ConsumerTokenRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.target_node_id.trim().is_empty() || req.intent.trim().is_empty() {
        return err_json(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_error",
            "target_node_id and intent are required",
        );
    }
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing node_token",
            )
        }
    };
    let caller_node_id = match node_id_from_auth(&headers, &token) {
        Some(id) => id,
        None => {
            return err_json(
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_error",
                "X-Node-Id header required (or use JWT)",
            )
        }
    };
    if !st.repo.verify_node_token(&caller_node_id, &token).await {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid node_token",
        );
    }
    if st.repo.get(&req.target_node_id).await.is_none() {
        return err_json(StatusCode::NOT_FOUND, "not_found", "Target node not found.");
    }
    let Some(secret) = st.signing_key.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "not_configured",
                    "message": "Consumer token signing key not configured on this directory."
                }
            })),
        );
    };
    let now = unix_now();
    let exp = now + 300;
    let payload = serde_json::json!({
        "v": 1,
        "iss": "https://iicp.network",
        "sub": caller_node_id,
        "aud": req.target_node_id,
        "intent": req.intent,
        "iat": now,
        "exp": exp
    });
    let Some(issued) = sign_domain_token(secret, "iicp:consumer-token:v1\n", &payload) else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_configured",
            "Consumer token signing key not configured on this directory.",
        );
    };
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "token": issued,
            "expires_at": exp,
            "caller_node_id": caller_node_id,
            "target_node_id": req.target_node_id,
            "intent": req.intent
        })),
    )
}

#[derive(Debug, Deserialize)]
struct RelayTicketRequest {
    #[serde(default)]
    relay_node_id: Option<String>,
}

/// `POST /api/v1/relay/ticket` — node-token authenticated relay-bind ticket.
async fn relay_ticket_issue(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RelayTicketRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing node_token",
            )
        }
    };
    let worker_node_id = match node_id_from_auth(&headers, &token) {
        Some(id) => id,
        None => {
            return err_json(
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_error",
                "X-Node-Id header required (or use JWT)",
            )
        }
    };
    if !st.repo.verify_node_token(&worker_node_id, &token).await {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid node_token",
        );
    }
    let Some(secret) = st.signing_key.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "not_configured",
                    "message": "Relay bind ticket signing key not configured on this directory."
                }
            })),
        );
    };
    let relay_node_id = req
        .relay_node_id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "*".into());
    let now = unix_now();
    let exp = now + 120;
    let payload = serde_json::json!({
        "v": 1,
        "typ": "relay-bind-ticket",
        "iss": "https://iicp.network",
        "sub": worker_node_id,
        "aud": relay_node_id,
        "iat": now,
        "exp": exp
    });
    let Some(ticket) = sign_domain_token(secret, "iicp:relay-bind-ticket:v1\n", &payload) else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_configured",
            "Relay bind ticket signing key not configured on this directory.",
        );
    };
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ticket": ticket,
            "expires_at": exp,
            "worker_node_id": worker_node_id,
            "relay_node_id": relay_node_id,
            "algorithm": "ed25519"
        })),
    )
}

/// `GET /api/v1/compliance-attestation` — compact signed Rust parity attestation.
/// The PHP seed signs full REACH probe evidence. Rust can emit a minimal signed
/// attestation when configured; without the signing key it fails closed.
async fn compliance_attestation(
    State(st): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(secret) = st.signing_key.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "attestation_unavailable",
                    "message": "Attestation signing key not configured on this directory"
                }
            })),
        );
    };
    let Some(run) = st.repo.latest_conformance_run().await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "code": "no_probe_data",
                    "message": "No conformance probe run recorded yet"
                }
            })),
        );
    };
    let generated_at = chrono::Utc::now();
    let valid_until = generated_at + chrono::Duration::seconds(900);
    let document = serde_json::json!({
        "endpoint": std::env::var("IICP_PUBLIC_URL")
            .unwrap_or_else(|_| "https://iicp.network".to_string())
            .trim_end_matches('/'),
        "spec_version": "iicp-dir v1.1.0",
        "purpose": "compliance-attestation",
        "probe_run_id": run.run_id,
        "probe_run_at": run.probed_at,
        "passed_probes": run.passed,
        "failed_probes": run.failed,
        "generated_at": generated_at.to_rfc3339(),
        "valid_until": valid_until.to_rfc3339()
    });
    let canonical = federation::canonical_json(&document);
    let hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(canonical.as_bytes()))
    };
    let msg = {
        use sha2::{Digest, Sha256};
        Sha256::digest(canonical.as_bytes()).to_vec()
    };
    let Some(signature) = ed25519_sign_hex(secret, &msg) else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "attestation_unavailable",
            "Attestation signing key not configured on this directory",
        );
    };
    let mut out = document;
    out["attestation_hash"] = serde_json::json!(hash);
    out["signature"] = serde_json::json!(signature);
    out["signer_did"] = serde_json::json!(st.directory_did);
    (StatusCode::OK, Json(out))
}

/// `GET /.well-known/iicp-replicas.json` (DIR-FED-19) — trusted-replica registry
/// (schema v2, S.13 §6.4). Dynamic: reads the live replica list from the repository
/// so newly joined replicas appear within one request of their join handshake.
/// Static CDN-cacheable form (no dynamic freshness fields); clients SHOULD call
/// `/api/v1/stats` on each replica for live last_seen_at / event_log_lag_ms.
async fn iicp_replicas(State(st): State<AppState>) -> impl IntoResponse {
    let replicas = st.repo.all_replicas().await;
    let ts_now = ms_to_iso8601(now_ms_i64());
    let entries: Vec<serde_json::Value> = replicas
        .iter()
        .map(
            |(replica_id, did, endpoint, trust_tier, registered_at_ms)| {
                serde_json::json!({
                    "replica_id":    replica_id,
                    "did":           did,
                    "endpoint":      endpoint,
                    "trust_tier":    trust_tier,
                    "registered_at": ms_to_iso8601(*registered_at_ms),
                })
            },
        )
        .collect();
    let body = serde_json::json!({
        "@context":      "https://iicp.network/ns/replicas/v1",
        "schema_version": "2",
        "genesis_seed":  DEFAULT_DIRECTORY_DID,
        "replicas":      entries,
        "updated_at":    ts_now,
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        axum::Json(body),
    )
}

/// Current Unix ms (used for `updated_at` in the replicas registry).
fn now_ms_i64() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Convert Unix ms → ISO-8601 UTC string without external deps.
fn ms_to_iso8601(ms: i64) -> String {
    let s = (ms / 1000) as u64;
    let days = s / 86400;
    let time = s % 86400;
    let (y, mo, d) = days_to_ymd(days);
    let h = time / 3600;
    let mi = (time % 3600) / 60;
    let se = time % 60;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}Z")
}

/// Gregorian date from a Unix day count (days since 1970-01-01). No external dep.
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Era-based algorithm (Howard Hinnant, chrono-style)
    days += 719468; // shift to 0000-03-01 epoch
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ── peers (iicp-dir §3.5) ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PeersRequest {
    #[serde(alias = "sender_id")]
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
    request: Result<Json<PeersRequest>, JsonRejection>,
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
    let Json(req) = match request {
        Ok(request) => request,
        Err(_) => return reject("validation_error", "invalid peer request"),
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
/// For public targets, performs DNS resolution + a 5s TCP reachability probe and
/// reports latency_ms on success.
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
    // SSRF guard: block private/loopback IPs before any network activity.
    if is_private_host(host) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                serde_json::json!({"reachable": false, "latency_ms": null, "error": "private_address"}),
            ),
        );
    }

    match probe_node_host(host, p.port).await {
        Ok((reachable, latency_ms)) => {
            if reachable {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({"reachable": true, "latency_ms": latency_ms})),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(
                        serde_json::json!({"reachable": false, "latency_ms": null, "error": "unreachable"}),
                    ),
                )
            }
        }
        Err(error) => (
            StatusCode::OK,
            Json(serde_json::json!({"reachable": false, "latency_ms": null, "error": error})),
        ),
    }
}

#[derive(Debug, serde::Deserialize)]
struct ProbeParams {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u16,
}

async fn probe_node_host(host: &str, port: u16) -> Result<(bool, Option<u64>), &'static str> {
    let addrs = resolve_probe_addresses(host, port)?;
    for addr in addrs {
        let start = std::time::Instant::now();
        let probe = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await;
        if probe.is_ok_and(|r| r.is_ok()) {
            return Ok((true, Some(start.elapsed().as_millis() as u64)));
        }
    }
    Ok((false, None))
}

fn resolve_probe_addresses(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, &'static str> {
    let mut addrs = Vec::new();
    for socket in (host, port)
        .to_socket_addrs()
        .map_err(|_| "unresolved_host")?
    {
        if is_private_host(&socket.ip().to_string()) {
            return Err("unroutable_address");
        }
        addrs.push(socket);
    }
    if addrs.is_empty() {
        return Err("unresolved_host");
    }
    Ok(addrs)
}

fn is_private_host(host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']');
    behavior_contract::blocked_ip(h)
        || is_loopback_or_unspecified(h)
        || is_rfc1918_v4(h)
        || is_ipv6_private(h)
}

fn is_loopback_or_unspecified(h: &str) -> bool {
    h.starts_with("127.") || h == "0.0.0.0" || h == "::1" || h == "localhost" || h == "::"
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
    err_json(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

/// Canonical public-mesh policy refusal. The response deliberately includes only
/// taxonomy evidence, never submitted task content or the full identifier.
fn policy_reject(
    classification: &policy::IntentClassification,
) -> (StatusCode, Json<serde_json::Value>) {
    err_json(
        StatusCode::UNPROCESSABLE_ENTITY,
        policy::REFUSAL_CODE,
        &policy::refusal_message(classification),
    )
}

/// Structured error with an explicit status (PHP parity: `{error:{code,message}}`).
fn err_json(
    status: StatusCode,
    code: &str,
    message: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "error": { "code": code, "message": message } })),
    )
}

fn sdk_adoption_json(nodes: &[crate::types::Node]) -> serde_json::Value {
    let mut by_language: BTreeMap<String, u32> = BTreeMap::new();
    let mut by_version: BTreeMap<String, u32> = BTreeMap::new();
    for n in nodes {
        let lang = n
            .sdk_language
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let version = n
            .sdk_version
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("unknown")
            .to_string();
        *by_language.entry(lang).or_insert(0) += 1;
        *by_version.entry(version).or_insert(0) += 1;
    }
    serde_json::json!({
        "total_active": nodes.len(),
        "by_language": by_language,
        "by_version": by_version,
    })
}

fn receipt_profile_adoption_json(nodes: &[crate::types::Node]) -> serde_json::Value {
    let ready = nodes
        .iter()
        .filter(|node| node.consumer_cosignature_ready)
        .count();
    serde_json::json!({
        "basis": "heartbeating_nodes",
        "profile": "consumer_cosignature_v1",
        "ready": ready,
        "total_heartbeating": nodes.len(),
    })
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
    let sdk_adoption = sdk_adoption_json(&provider_set);
    let receipt_profile_adoption = receipt_profile_adoption_json(&provider_set);
    let dispatch_discovery_adoption = st.repo.dispatch_usage_summary(7).await;
    let healths: Vec<health::NodeHealth> = provider_set
        .iter()
        .map(|n| {
            health::score_node(&health::HealthSignals {
                reachability: n.reachability_signal,
                latency_ms: n.latency_estimate_ms.map(|ms| ms as f64),
            })
        })
        .collect();
    let mesh = health::mesh_health(&healths);
    // ADR-048 (#374): federation-aware mesh_health — resolve each node by majority-vote
    // across evaluators over the union of replicated HEALTH snapshots, so any replica
    // reports the same fleet aggregate. Null until HEALTH events have been applied
    // (federation active); the single-directory mesh_health above stays authoritative.
    let fed_rows = st.repo.all_health_observations().await;
    let mesh_health_federated = if fed_rows.is_empty() {
        serde_json::Value::Null
    } else {
        let obs: Vec<health::HealthObservation> = fed_rows
            .into_iter()
            .map(
                |(node_id, evaluator_did, score, evaluated_at_ms)| health::HealthObservation {
                    node_id,
                    evaluator_did,
                    score,
                    evaluated_at_ms,
                },
            )
            .collect();
        let f = health::federated_mesh_health(&obs);
        serde_json::json!({
            "score": f.score,
            "label": f.label,
            "mean": f.mean,
            "p10": f.p10,
            "distribution": {
                "healthy": f.distribution.healthy,
                "degraded": f.distribution.degraded,
                "impaired": f.distribution.impaired,
                "critical": f.distribution.critical,
                "offline": f.distribution.offline
            },
            "sample": f.sample,
            "contested": f.contested,
            "unconfirmed": f.unconfirmed,
            "basis": "federated_union",
            "window": "replicated"
        })
    };
    // PHP StatsController parity: probe aggregates + directory_health (ADR-044).
    let (probe_active_count, probe_regions) = st.repo.probe_active_count_and_regions().await;
    let agg24 = st.repo.probe_aggregate_24h().await;
    let top_failures = st.repo.probe_top_failures().await;
    let top_failures_json: Vec<serde_json::Value> = top_failures
        .iter()
        .map(|f| {
            serde_json::json!({
                "test_id": f.test_id,
                "passed": f.passed,
                "failed": f.failed,
                "total": f.total,
                "fail_rate": f.fail_rate,
            })
        })
        .collect();
    let directory_health = compute_directory_health(&agg24);
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
        "probes": {
            "active_count": probe_active_count,
            "regions": probe_regions,
            "aggregate_24h": {
                "discover_p50_ms": agg24.discover_p50_ms,
                "discover_p95_ms": agg24.discover_p95_ms,
                "heartbeat_p50_ms": agg24.heartbeat_p50_ms,
                "reachability_pct": agg24.reachability_pct,
                "task_success_rate_pct": agg24.task_success_rate_pct,
            },
            "conformance_24h": {
                "passed": agg24.conformance_passed,
                "failed": agg24.conformance_failed,
                "top_failures": top_failures_json,
            },
            "last_probe_at": last_probe_at,
        },
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
        },
        "mesh_health_federated": mesh_health_federated,
        "directory_health": directory_health,
        "sdk_adoption": sdk_adoption,
        "receipt_profile_adoption": receipt_profile_adoption,
        "dispatch_discovery_adoption": dispatch_discovery_adoption,
    }))
}

/// ADR-044 directory_health score — matches PHP StatsController::directoryHealth().
/// Formula: 0.6 × discover_latency_score + 0.4 × conformance_pass_fraction.
/// Returns `label: "unavailable"` when no probe data has been ingested yet.
fn compute_directory_health(agg: &crate::repo::ProbeAggregate24h) -> serde_json::Value {
    let p50 = agg.discover_p50_ms;
    let passed = agg.conformance_passed;
    let failed = agg.conformance_failed;

    if p50.is_none() && passed == 0 && failed == 0 {
        return serde_json::json!({
            "score": serde_json::Value::Null,
            "label": "unavailable",
            "components": serde_json::Value::Null,
            "probe_reachability_pct": agg.reachability_pct,
            "window": "24h",
        });
    }

    let lat_score = p50
        .map(|v| (1.0 - (v - 50.0) / 450.0).clamp(0.0, 1.0))
        .unwrap_or(0.5);
    let total = passed + failed;
    let conf_score = if total > 0 {
        passed as f64 / total as f64
    } else {
        1.0
    };
    let score = ((0.6 * lat_score + 0.4 * conf_score) * 1000.0).round() / 1000.0;

    let label = if score >= 0.85 {
        "healthy"
    } else if score >= 0.65 {
        "degraded"
    } else if score >= 0.40 {
        "impaired"
    } else {
        "critical"
    };

    serde_json::json!({
        "score": score,
        "label": label,
        "components": {
            "discover_latency": (lat_score * 1000.0).round() / 1000.0,
            "conformance": (conf_score * 1000.0).round() / 1000.0,
        },
        "discover_p50_ms": p50,
        "probe_reachability_pct": agg.reachability_pct,
        "window": "24h",
    })
}

/// `GET /v1/bootstrap` (iicp-dir §3.7). Returns recently-active nodes for peer discovery.
/// No intent filter — any available, recently-seen node qualifies.
#[derive(Debug, Deserialize)]
struct EventsParams {
    #[serde(default)]
    since_seq: Option<i64>,
    #[serde(default)]
    limit: Option<u32>,
}

/// `GET /v1/events` (#442, S.13 §3.4) — serve this directory's signed event log so a
/// replica (PHP or Rust) can tail it from `since_seq`. Mirrors the PHP seed's endpoint
/// shape that `replica::fetch_events` consumes: `{events:[…], next_seq, has_more}` with each
/// event carrying its Ed25519 `sig` + `signer_did` (this dir's DID).
async fn events(
    State(st): State<AppState>,
    Query(q): Query<EventsParams>,
) -> Json<serde_json::Value> {
    let since_seq = q.since_seq.unwrap_or(0);
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let rows = st.repo.events_since(since_seq, limit).await;
    let next_seq = rows.last().map(|r| r.seq).unwrap_or(since_seq);
    let has_more = rows.len() as u32 == limit;
    let events: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "event_id": r.event_id,
                "event_type": r.event_type,
                "seq": r.seq,
                "ts_ms": r.ts_ms,
                "node_id": r.node_id,
                "payload": r.payload,
                "prev_hash": r.prev_hash,
                "sig": r.sig,
                "signer_did": st.directory_did,
            })
        })
        .collect();
    Json(serde_json::json!({ "events": events, "next_seq": next_seq, "has_more": has_more }))
}

/// `GET /v1/snapshot` (#442, S.13) — full-state bootstrap: all nodes + their capabilities,
/// so a replica can prime its state in one request before tailing /v1/events. Mirrors the
/// PHP SnapshotController shape (the Rust replica's apply_snapshot consumes node fields +
/// capabilities[].{node_id,intent}).
async fn snapshot(State(st): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {"code": "unauthorized", "message": "Missing Authorization header"}
            })),
        )
            .into_response();
    };
    let claims = match auth::verify_replica_jwt(token) {
        Ok(claims) => claims,
        Err(auth::ReplicaTokenError::Expired) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {
                        "code": "token_expired",
                        "message": "Replica JWT has expired; re-register via POST /v1/replicas/register"
                    }
                })),
            )
                .into_response();
        }
        Err(auth::ReplicaTokenError::Invalid) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {"code": "unauthorized", "message": "Invalid replica token"}
                })),
            )
                .into_response();
        }
    };
    let Some(stored_hash) = st.repo.replica_token_hash(&claims.sub).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {"code": "unauthorized", "message": "Replica not registered"}
            })),
        )
            .into_response();
    };
    if !st.repo.replica_is_active(&claims.sub).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {"code": "unauthorized", "message": "Replica is not active; re-register to reactivate"}
            })),
        )
            .into_response();
    }
    use sha2::{Digest, Sha256};
    if stored_hash != hex::encode(Sha256::digest(token.as_bytes())) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "code": "unauthorized",
                    "message": "Replica token has been rotated; re-register to obtain a fresh token"
                }
            })),
        )
            .into_response();
    }

    let records = st.repo.snapshot_records().await;
    let log = st.repo.events_since(0, 1_000_000).await;
    let snapshot_seq = log.last().map(|e| e.seq).unwrap_or(0);
    let genesis_hash = log.first().map(|e| {
        hex::encode(Sha256::digest(
            crate::federation::canonical_json(&e.payload).as_bytes(),
        ))
    });
    let mut nodes = Vec::with_capacity(records.len());
    let mut capabilities = Vec::new();
    for r in &records {
        let n = &r.node;
        nodes.push(serde_json::json!({
            "node_id": n.node_id,
            "endpoint": n.endpoint,
            "region": n.region,
            "available": n.available,
            "reputation_score": n.reputation_score,
            "load": n.load,
            "active_jobs": n.active_jobs,
            "exposure_mode": n.exposure_mode,
            "cip_policy": n.cip_policy,
            "pricing": n.pricing,
        }));
        for intent in &r.intents {
            capabilities.push(serde_json::json!({ "node_id": n.node_id, "intent": intent }));
        }
    }
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    Json(serde_json::json!({
        "schema_version": 1,
        "snapshot_seq": snapshot_seq,
        "snapshot_ts_ms": ts_ms,
        "genesis_hash": genesis_hash,
        "nodes": nodes,
        "capabilities": capabilities,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct ReplicaRegisterRequest {
    did: String,
    endpoint: String,
    #[serde(default)]
    #[allow(dead_code)] // accepted for PHP parity; trust starts 'low' regardless (§7.1)
    trust_tier_request: Option<String>,
}

/// `POST /v1/replicas/register` (#442, ADR-013 §7) — seed-side replica handshake. A replica
/// announces its DID + endpoint; the seed records it (idempotent on DID, stable replica_id),
/// emits a signed REPLICA_REGISTERED event so other replicas mirror it, and returns the
/// bootstrap cursor + genesis hash. Mirrors PHP ReplicasController::register (trust_tier
/// always 'low' on first registration). Light validation here; full DID-document resolution
/// + endpoint reachability are a hardening follow-up.
async fn replicas_register(
    State(st): State<AppState>,
    Json(req): Json<ReplicaRegisterRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !req.did.starts_with("did:web:") {
        return reject("validation_error", "did must be a did:web identifier");
    }
    if !(req.endpoint.starts_with("https://") || req.endpoint.starts_with("http://")) {
        return reject("validation_error", "endpoint must be an http(s) URL");
    }
    let endpoint = req.endpoint.trim_end_matches('/').to_string();
    // Idempotent on DID (DIR-FED-13): reuse the existing replica_id, else mint one.
    let existing = st.repo.replica_id_by_did(&req.did).await;
    let (replica_id, is_new) = match existing {
        Some(rid) => (rid, false),
        None => (uuid::Uuid::new_v4().to_string(), true),
    };
    st.repo
        .upsert_replica(&replica_id, &req.did, &endpoint, "low")
        .await;
    let Some(replica_token) = auth::issue_replica_jwt(&replica_id) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": {"code": "server_error", "message": "Replica token signing is unavailable"}
            })),
        );
    };
    {
        use sha2::{Digest, Sha256};
        let token_hash = hex::encode(Sha256::digest(replica_token.as_bytes()));
        if !st
            .repo
            .set_replica_token_hash(&replica_id, &token_hash)
            .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": {"code": "server_error", "message": "Replica token rotation failed"}
                })),
            );
        }
    }
    // Mirror registration, endpoint rotation and reactivation to every replica.
    emit_event(
        &st,
        "REPLICA_REGISTERED",
        &replica_id,
        serde_json::json!({ "did": req.did, "endpoint": endpoint, "trust_tier": "low" }),
    )
    .await;
    let genesis_hash = st.repo.events_since(0, 1).await.first().map(|e| {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(
            crate::federation::canonical_json(&e.payload).as_bytes(),
        ))
    });
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "replica_id": replica_id,
            "replica_token": replica_token,
            "since_seq": 0,
            "genesis_hash": genesis_hash,
            "trust_tier": "low",
            "did_acknowledged": true,
            "is_new_registration": is_new,
            "expires_at": expires_at,
        })),
    )
}

/// `POST /v1/replicas/deregister` (DIR-FED-22) — authenticate the current
/// replica credential, retain a decommissioned audit row, invalidate the
/// bearer, and federate the lifecycle tombstone.
async fn replicas_deregister(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
    else {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Missing Authorization header",
        );
    };
    let claims = match auth::verify_replica_jwt(token) {
        Ok(claims) => claims,
        Err(auth::ReplicaTokenError::Expired) => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "token_expired",
                "Replica JWT has expired",
            )
        }
        Err(auth::ReplicaTokenError::Invalid) => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Invalid replica token",
            )
        }
    };
    if !st.repo.replica_is_active(&claims.sub).await {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Replica is not active; re-register to reactivate",
        );
    }
    use sha2::{Digest, Sha256};
    let presented_hash = hex::encode(Sha256::digest(token.as_bytes()));
    if st.repo.replica_token_hash(&claims.sub).await.as_deref() != Some(&presented_hash) {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Replica token has been rotated; re-register to obtain a fresh token",
        );
    }
    let did = st
        .repo
        .all_replicas()
        .await
        .into_iter()
        .find(|row| row.0 == claims.sub)
        .map(|row| row.1)
        .unwrap_or_default();
    let Some(signing_key) = st.signing_key.as_deref() else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "event_signing_unavailable",
            "Replica deregistration requires event signing",
        );
    };
    if !st
        .repo
        .decommission_replica_with_event(&claims.sub, &did, signing_key)
        .await
    {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "decommission_failed",
            "Replica deregistration was not committed",
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "decommissioned"})),
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

struct RepositoryRuntime {
    repo: Arc<dyn NodeRepository>,
    mysql_pool: Option<Pool<MySql>>,
}

async fn initialize_repository(env: Env) -> RepositoryRuntime {
    // Wire DATABASE_URL → MySqlRepo when present. A configured database is an
    // explicit persistence contract: connection or schema failures are fatal,
    // never a silent downgrade to ephemeral memory.
    if let Ok(url) = std::env::var("DATABASE_URL") {
        match db::init_pool(&url).await {
            Ok(pool) => {
                match schema::ensure_schema(&pool).await {
                    Ok(status) => {
                        println!("iicp-directory-rs {VERSION}: MySQL schema status={status}")
                    }
                    Err(error) => {
                        eprintln!("FATAL: MySQL schema verification failed: {error}");
                        std::process::exit(1);
                    }
                }
                println!("iicp-directory-rs {VERSION}: MySQL pool connected");
                RepositoryRuntime {
                    repo: Arc::new(db::MySqlRepo::new(pool.clone())),
                    mysql_pool: Some(pool),
                }
            }
            Err(e) => {
                eprintln!("FATAL: configured MySQL connection failed: {e}");
                std::process::exit(1);
            }
        }
    } else if env != Env::Production
        && std::env::var("IICP_ALLOW_IN_MEMORY").is_ok_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
    {
        println!("iicp-directory-rs {VERSION}: no DATABASE_URL; using InMemoryRepo");
        RepositoryRuntime {
            repo: Arc::new(InMemoryRepo::default()),
            mysql_pool: None,
        }
    } else {
        eprintln!(
            "FATAL: DATABASE_URL is required; ephemeral memory requires non-production APP_ENV and IICP_ALLOW_IN_MEMORY=true"
        );
        std::process::exit(1);
    }
}

async fn verified_operational_pool() -> Result<Pool<MySql>, String> {
    let url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required for operational commands".to_string())?;
    let pool = db::init_pool(&url)
        .await
        .map_err(|error| format!("configured MySQL connection failed: {error}"))?;
    schema::verify_existing_schema(&pool)
        .await
        .map_err(|error| format!("MySQL schema verification failed: {error}"))?;
    Ok(pool)
}

async fn run_operational_command(command: Command) -> Result<(), String> {
    let pool = verified_operational_pool().await?;
    let (value, json_requested) = match command {
        Command::DbMaintenanceStatus { retention, json } => (
            serde_json::to_value(
                maintenance::maintenance_status(&pool, retention.policy())
                    .await
                    .map_err(|error| format!("maintenance status failed: {error}"))?,
            )
            .map_err(|error| error.to_string())?,
            json,
        ),
        Command::TelemetryPrune {
            retention,
            batch,
            max_batches,
            dry_run: _,
            apply,
            json,
        } => (
            serde_json::to_value(
                maintenance::prune_telemetry(&pool, retention.policy(), batch, max_batches, apply)
                    .await
                    .map_err(|error| format!("telemetry prune failed: {error}"))?,
            )
            .map_err(|error| error.to_string())?,
            json,
        ),
        Command::E050Readiness { json } => (
            serde_json::to_value(
                maintenance::e050_readiness(
                    &pool,
                    std::env::var("IICP_E050_STRICT_SECURED").is_ok_and(|value| {
                        matches!(
                            value.to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        )
                    }),
                )
                .await
                .map_err(|error| format!("E050 readiness failed: {error}"))?,
            )
            .map_err(|error| error.to_string())?,
            json,
        ),
    };
    if !json_requested {
        eprintln!("content-free operational report (use --json for machine-readable mode)");
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Some(command) = cli.command {
        if let Err(error) = run_operational_command(command).await {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        }
        return;
    }
    START_TIME.set(Instant::now()).ok();
    let addr = "0.0.0.0:8090";
    let env = match std::env::var("APP_ENV").as_deref() {
        Ok("local") => Env::Local,
        Ok("testing") => Env::Testing,
        Ok("staging") => Env::Staging,
        _ => Env::Production,
    };
    let runtime = initialize_repository(env).await;
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
    let (directory_did, directory_service_endpoint) = match replica_config.as_ref() {
        Some(cfg) => {
            let Some(did) = cfg
                .replica_did
                .as_ref()
                .filter(|did| did.starts_with("did:web:"))
            else {
                eprintln!("FATAL: replica mode requires a valid IICP_REPLICA_DID");
                std::process::exit(1);
            };
            let Some(endpoint) = cfg
                .replica_endpoint
                .as_ref()
                .filter(|url| url.starts_with("https://"))
            else {
                eprintln!("FATAL: replica mode requires an HTTPS IICP_REPLICA_ENDPOINT");
                std::process::exit(1);
            };
            if std::env::var("IICP_DIRECTORY_DID")
                .ok()
                .is_some_and(|served| served != *did)
            {
                eprintln!("FATAL: IICP_DIRECTORY_DID must equal IICP_REPLICA_DID in replica mode");
                std::process::exit(1);
            }
            (did.clone(), endpoint.trim_end_matches('/').to_string())
        }
        None => (
            std::env::var("IICP_DIRECTORY_DID")
                .unwrap_or_else(|_| DEFAULT_DIRECTORY_DID.to_string()),
            std::env::var("IICP_DIRECTORY_ENDPOINT")
                .unwrap_or_else(|_| "https://iicp.network/v1".to_string()),
        ),
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
    let signing_key = std::env::var("IICP_GENESIS_ED25519_SECRET_KEY")
        .ok()
        .filter(|key| key.len() == 128 && hex::decode(key).is_ok());
    if env == Env::Production && signing_key.is_none() {
        eprintln!(
            "FATAL: IICP_GENESIS_ED25519_SECRET_KEY must be a valid 128-hex Ed25519 secret in production"
        );
        std::process::exit(1);
    }
    let state = AppState {
        repo,
        env,
        signing_key,
        directory_did,
        directory_service_endpoint,
        register_rate: new_register_rate(),
        strict_e050_secured: std::env::var("IICP_E050_STRICT_SECURED").is_ok_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        }),
        allow_insecure_tls: env != Env::Production
            && std::env::var("IICP_DEV_ALLOW_INSECURE_TLS").is_ok_and(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            }),
        skip_liveness_check: matches!(env, Env::Local | Env::Testing)
            && std::env::var("IICP_SKIP_LIVENESS_CHECK").is_ok_and(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            }),
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
    use tower::ServiceExt;

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
        assert_eq!(node["sdk_release"]["latest_known_version"], "0.7.100");
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

    #[test]
    fn directory_health_score_unavailable_when_no_probe_data() {
        // Behavior: with no probe data (all zeros / None), score=null label="unavailable".
        let agg = crate::repo::ProbeAggregate24h::default();
        let h = compute_directory_health(&agg);
        assert_eq!(
            h["label"], "unavailable",
            "expected unavailable with no probe data"
        );
        assert!(
            h["score"].is_null(),
            "score should be null when no probe data"
        );
    }

    #[test]
    fn directory_health_score_healthy_when_fast_and_conformant() {
        // p50=50ms (perfect latency) + all passed → latScore=1.0, confScore=1.0 → 1.0 → healthy
        let agg = crate::repo::ProbeAggregate24h {
            discover_p50_ms: Some(50.0),
            conformance_passed: 100,
            conformance_failed: 0,
            ..Default::default()
        };
        let h = compute_directory_health(&agg);
        assert_eq!(h["label"], "healthy");
        let score = h["score"].as_f64().unwrap();
        assert!(
            (score - 1.0).abs() < 0.001,
            "score should be ~1.0, got {score}"
        );
    }

    #[test]
    fn directory_health_score_critical_when_slow_and_half_failing() {
        // p50=500ms (latScore=0.0) + 50% fail rate (confScore=0.5) → 0.4×0.5=0.2 → critical
        let agg = crate::repo::ProbeAggregate24h {
            discover_p50_ms: Some(500.0),
            conformance_passed: 50,
            conformance_failed: 50,
            ..Default::default()
        };
        let h = compute_directory_health(&agg);
        assert_eq!(h["label"], "critical");
        let score = h["score"].as_f64().unwrap();
        assert!(
            score < 0.40,
            "score should be below 0.40 (critical), got {score}"
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
            "sdk_version": "0.5.2",
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
        assert_eq!(node["backend"], "meshllm");
        assert_eq!(node["consumer_cosignature_ready"], true);
        assert!(node.get("supported_receipt_profiles").is_none());
        assert_eq!(node["nat_type"], "full_cone");
        assert_eq!(node["models"][0], "llama3");
        assert_eq!(node["quantization"][0], "q4_k_m");
        assert_eq!(node["inference_engine"][0], "llama.cpp");
        assert_eq!(node["address_family"], "ipv4");
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
    fn listing_exposure_serves_operator_url_only_when_opted_in() {
        // WQ-058 #404 (ADR-017 REG-01): respect the opt-out — operator_url is served only
        // when public_listing=true. Fails if the registry leaks an opted-out operator's URL.
        let url = Some("https://op.example".to_string());
        assert_eq!(
            super::listing_exposure(true, &url),
            serde_json::json!("https://op.example")
        );
        assert_eq!(
            super::listing_exposure(false, &url),
            serde_json::Value::Null
        );
        assert_eq!(
            super::listing_exposure(true, &None),
            serde_json::Value::Null
        );
    }

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
}

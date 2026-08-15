// SPDX-License-Identifier: Apache-2.0
//! Discovery, route-disclosure and public-node projections.
//!
//! This module intentionally owns only read-path and prompt-free dispatch-ticket
//! behaviour. Registration, persistence, signing primitives and router
//! composition remain elsewhere so this extraction preserves the existing
//! directory contract while shrinking the binary composition root (#38).

use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::discovery_policy;
use crate::operator::{operator_display_name_for, operator_fingerprint_for};
use crate::repo::DiscoverQuery;
use crate::state::AppState;
use crate::{
    err_json, policy, policy_manifest, policy_reject, reject, sign_domain_token, types, unix_now,
    validate_intent,
};

pub(crate) const SDK_BASELINE_VERSION: &str = "0.7.68";
const SDK_LATEST_KNOWN_VERSION: &str = "0.7.105";
const PROFILE_ID: &str = "iicp.profile.compatibility.v0";
const PROFILE_VERSION: &str = "0.4.0-draft";
pub(crate) const PROFILE_FIXTURE_SHA256: &str =
    "d039eaf52afca6866832779261db7bdd2ffd818a36bc8ba9aea1db0c9c115012";
const PREVIOUS_PROFILE_VERSION: &str = "0.3.0-draft";
const PREVIOUS_PROFILE_FIXTURE_SHA256: &str =
    "4137ecf91b4748a2b368cf4428b4604c6947f8879d77402cc7937d11d24b2aaf";

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
pub(crate) fn transport_methods(endpoint: &str, transport: Option<&str>) -> Vec<String> {
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

/// Raw query string for `GET /v1/discover` (iicp-dir §3.3).
#[derive(Debug, Deserialize)]
pub(crate) struct DiscoverParams {
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
    pub(crate) profile_fixture_sha256: Option<String>,
    #[serde(default)]
    profile_required: Option<bool>,
    /// Public presentation strips endpoints, full node IDs and key material.
    #[serde(default)]
    view: Option<String>,
}

pub(crate) fn profile_negotiation(p: &DiscoverParams) -> Option<serde_json::Value> {
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
pub(crate) async fn discover(
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
        "implementation_name",
        "implementation_version",
        "sdk_compatibility_version",
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
        "supported_profiles",
        "capabilities",
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
pub(crate) struct DispatchTicketRequest {
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
pub(crate) const DISPATCH_TICKET_AUDIENCE: &str = "iicp.directory.dispatch";
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

pub(crate) async fn dispatch_ticket_issue(
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
pub(crate) async fn node_detail(
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

    let sdk_status = sdk_status(n.effective_sdk_compatibility_version());
    obj.insert("sdk_status".into(), serde_json::json!(sdk_status));
    obj.insert(
        "sdk_baseline_version".into(),
        serde_json::json!(SDK_BASELINE_VERSION),
    );
    obj.insert(
        "upgrade_required".into(),
        serde_json::json!(sdk_status != "current"),
    );
    let sdk_relation = match n.effective_sdk_compatibility_version() {
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
            "latest_seen": n.effective_sdk_compatibility_version(),
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

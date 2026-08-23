//! HTTP route inventory and cross-cutting request middleware.

use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    middleware::{self, Next},
    routing::{get, post},
    Json, Router,
};
use std::sync::atomic::Ordering;

use crate::observability::{health, stats};
use crate::probe::probe_node;
use crate::registry::{registry_intents, registry_node_detail, registry_nodes, registry_stats};
use crate::restricted_domain_auth::restricted_domain_gate;
use crate::{
    audit_report, badge_svg, badges_list, bootstrap, compliance_attestation, conformance_submit,
    conformance_verify, consumer_token_issue, credits_award, credits_balance, credits_quote,
    credits_summary, credits_transactions, deployment_record, deregister, did_document,
    directory_descriptor, directory_key, discover, dispatch_ticket_issue, events, heartbeat,
    iicp_replicas, leaderboard, me, metrics, node_detail, operator_acceptance, operator_challenge,
    operator_dsr_anonymize, operator_dsr_export, operator_dsr_restrict, operator_key_revoke,
    operator_key_rotate, operator_rename, peers, register, relay_ticket_issue, replicas_deregister,
    replicas_register, root_info, snapshot, telemetry_probe, telemetry_proxy, AppState,
};

pub(crate) fn app(state: AppState) -> Router {
    let middleware_state = state.clone();
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
        .route(
            "/.well-known/iicp-directory.json",
            get(directory_descriptor),
        )
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
        .layer(middleware::from_fn_with_state(
            middleware_state.clone(),
            replica_readiness_gate,
        ))
        .layer(middleware::from_fn_with_state(
            middleware_state,
            restricted_domain_gate,
        ))
        .with_state(state)
}

async fn replica_readiness_gate(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let discovery = matches!(req.uri().path(), "/v1/discover" | "/api/v1/discover");
    let ready = state
        .replica_ready
        .as_ref()
        .is_none_or(|ready| ready.load(Ordering::Acquire));
    if discovery && !ready {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "10")],
            Json(serde_json::json!({
                "error": {
                    "code": "replica_not_ready",
                    "message": "replica has not completed verified synchronization"
                }
            })),
        )
            .into_response();
    }
    next.run(req).await
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
pub(crate) async fn replica_write_gate(
    State(seed_url): State<String>,
    req: Request,
    next: Next,
) -> Response {
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

// SPDX-License-Identifier: Apache-2.0
//! Public metadata, metrics and conformance-certificate handlers.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::repo::ConformanceBadge;
use crate::state::AppState;
use crate::VERSION;

/// `GET /v1/metrics` — Prometheus text exposition (iicp-dir §3.9c).
pub(crate) async fn metrics(State(st): State<AppState>) -> (StatusCode, axum::response::Response) {
    let active = st.repo.active_count().await;
    let body = format!(
        "# HELP iicp_active_nodes Number of currently active IICP directory nodes\n\
         # TYPE iicp_active_nodes gauge\n\
         iicp_active_nodes {active}\n\
         # HELP iicp_directory_info IICP directory version metadata\n\
         # TYPE iicp_directory_info gauge\n\
         iicp_directory_info{{version=\"{VERSION}\"}} 1\n"
    );
    let response = axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap();
    (StatusCode::OK, response)
}

#[derive(Debug, Deserialize)]
pub(crate) struct BadgesParams {
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifyParams {
    tier: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConformanceSubmitRequest {
    tier: String,
    #[serde(default)]
    subject_did: Option<String>,
}

/// `GET /v1/badges` — list conformance certificates (all or filtered by ?tier=).
pub(crate) async fn badges_list(
    State(st): State<AppState>,
    Query(params): Query<BadgesParams>,
) -> Json<serde_json::Value> {
    let badges: Vec<ConformanceBadge> = st.repo.list_badges(params.tier.as_deref()).await;
    let count = badges.len() as u32;
    Json(serde_json::json!({ "badges": badges, "count": count }))
}

/// `GET /v1/badge/:tier` — SVG shield badge (Shields.io format).
pub(crate) async fn badge_svg(
    State(st): State<AppState>,
    Path(tier): Path<String>,
) -> axum::response::Response {
    let status = st
        .repo
        .get_badge(&tier)
        .await
        .map(|badge| badge.status)
        .unwrap_or_else(|| "unknown".to_string());
    let message_color = match status.as_str() {
        "passed" => "#4c1",
        "pending" => "#e7b416",
        _ => "#9f9f9f",
    };
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="150" height="20">
  <rect width="60" height="20" fill="#555"/>
  <rect x="60" width="90" height="20" fill="{message_color}"/>
  <text x="30" y="14" fill="#fff" font-size="11" text-anchor="middle">iicp</text>
  <text x="105" y="14" fill="#fff" font-size="11" text-anchor="middle">{tier} {status}</text>
</svg>"##
    );
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "image/svg+xml")
        .header("cache-control", "max-age=3600")
        .body(axum::body::Body::from(svg))
        .unwrap()
}

/// `POST /v1/submit` — submit for conformance evaluation.
pub(crate) async fn conformance_submit(
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
pub(crate) async fn conformance_verify(
    State(st): State<AppState>,
    Query(params): Query<VerifyParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    match st.repo.get_badge(&params.tier).await {
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

/// `GET /` — root info (version, spec, links).
pub(crate) async fn root_info() -> Json<serde_json::Value> {
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

// SPDX-License-Identifier: Apache-2.0
//! Public metadata, metrics and conformance-certificate handlers.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::repo::ConformanceBadge;
use crate::repo::DbPoolMetrics;
use crate::state::AppState;
use crate::VERSION;

/// `GET /v1/metrics` — Prometheus text exposition (iicp-dir §3.9c).
pub(crate) async fn metrics(State(st): State<AppState>) -> (StatusCode, axum::response::Response) {
    let active = st.repo.active_count().await;
    let mut body = format!(
        "# HELP iicp_active_nodes Number of currently active IICP directory nodes\n\
         # TYPE iicp_active_nodes gauge\n\
         iicp_active_nodes {active}\n\
         # HELP iicp_directory_info IICP directory version metadata\n\
         # TYPE iicp_directory_info gauge\n\
         iicp_directory_info{{version=\"{VERSION}\"}} 1\n"
    );
    if let Some(pool) = st.repo.db_pool_metrics().await {
        body.push_str(&render_db_pool_metrics(pool));
    }
    let response = axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(body))
        .unwrap();
    (StatusCode::OK, response)
}

fn render_db_pool_metrics(pool: DbPoolMetrics) -> String {
    format!(
        "# HELP iicp_db_pool_connections Current SQL connection count by state\n\
         # TYPE iicp_db_pool_connections gauge\n\
         iicp_db_pool_connections{{state=\"open\"}} {}\n\
         iicp_db_pool_connections{{state=\"idle\"}} {}\n\
         iicp_db_pool_connections{{state=\"in_use\"}} {}\n\
         # HELP iicp_db_pool_max_connections Configured SQL pool maximum\n\
         # TYPE iicp_db_pool_max_connections gauge\n\
         iicp_db_pool_max_connections {}\n\
         # HELP iicp_db_pool_min_connections Configured SQL pool minimum\n\
         # TYPE iicp_db_pool_min_connections gauge\n\
         iicp_db_pool_min_connections {}\n\
         # HELP iicp_db_pool_utilization_ratio In-use connections divided by configured maximum\n\
         # TYPE iicp_db_pool_utilization_ratio gauge\n\
         iicp_db_pool_utilization_ratio {:.6}\n\
         # HELP iicp_db_pool_acquire_probe_seconds Time spent by the bounded acquisition probe\n\
         # TYPE iicp_db_pool_acquire_probe_seconds gauge\n\
         iicp_db_pool_acquire_probe_seconds {:.6}\n\
         # HELP iicp_db_pool_acquire_probe_success Whether the bounded acquisition probe obtained a connection\n\
         # TYPE iicp_db_pool_acquire_probe_success gauge\n\
         iicp_db_pool_acquire_probe_success {}\n\
         # HELP iicp_db_pool_acquire_probe_timeout_seconds Acquisition probe timeout bound\n\
         # TYPE iicp_db_pool_acquire_probe_timeout_seconds gauge\n\
         iicp_db_pool_acquire_probe_timeout_seconds {:.6}\n",
        pool.open_connections,
        pool.idle_connections,
        pool.in_use_connections,
        pool.max_connections,
        pool.min_connections,
        pool.utilization_ratio,
        pool.acquire_probe_seconds,
        u8::from(pool.acquire_probe_success),
        pool.acquire_probe_timeout_seconds,
    )
}

#[cfg(test)]
mod tests {
    use super::render_db_pool_metrics;
    use crate::repo::DbPoolMetrics;

    #[test]
    fn db_pool_metrics_are_content_free_and_bounded() {
        let body = render_db_pool_metrics(DbPoolMetrics {
            max_connections: 10,
            min_connections: 1,
            open_connections: 7,
            idle_connections: 2,
            in_use_connections: 5,
            utilization_ratio: 0.5,
            acquire_probe_seconds: 0.012_345,
            acquire_probe_success: true,
            acquire_probe_timeout_seconds: 0.25,
        });

        for expected in [
            "iicp_db_pool_connections{state=\"open\"} 7",
            "iicp_db_pool_connections{state=\"idle\"} 2",
            "iicp_db_pool_connections{state=\"in_use\"} 5",
            "iicp_db_pool_max_connections 10",
            "iicp_db_pool_min_connections 1",
            "iicp_db_pool_utilization_ratio 0.500000",
            "iicp_db_pool_acquire_probe_seconds 0.012345",
            "iicp_db_pool_acquire_probe_success 1",
            "iicp_db_pool_acquire_probe_timeout_seconds 0.250000",
        ] {
            assert!(body.contains(expected), "missing metric: {expected}");
        }
        for forbidden in ["node_id", "endpoint", "intent", "payload", "credential"] {
            assert!(!body.contains(forbidden), "metric leaked {forbidden}");
        }
    }
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

// SPDX-License-Identifier: Apache-2.0
//! Authenticated peer exchange and node self-inspection handlers.

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::state::AppState;
use crate::{bearer_token, node_id_from_auth, reject};

#[derive(Debug, Deserialize)]
pub(crate) struct PeersRequest {
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
pub(crate) async fn peers(
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
    let known: Vec<String> = req.known_peers.into_iter().take(20).collect();
    let limit = req.limit.unwrap_or(10);
    let found = st.repo.peers_excluding(&known, limit).await;
    let count = found.len() as u32;
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
pub(crate) async fn me(
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

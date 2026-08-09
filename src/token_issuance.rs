// SPDX-License-Identifier: Apache-2.0
//! Short-lived consumer and relay authorization material.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::state::AppState;
use crate::{bearer_token, err_json, node_id_from_auth, sign_domain_token, unix_now};

#[derive(Debug, Deserialize)]
pub(crate) struct ConsumerTokenRequest {
    target_node_id: String,
    intent: String,
}

/// `POST /api/v1/consumer-token` — node-token authenticated short-lived token
/// authorising the caller to send one intent class to a target node.
pub(crate) async fn consumer_token_issue(
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
pub(crate) struct RelayTicketRequest {
    #[serde(default)]
    relay_node_id: Option<String>,
}

/// `POST /api/v1/relay/ticket` — node-token authenticated relay-bind ticket.
pub(crate) async fn relay_ticket_issue(
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

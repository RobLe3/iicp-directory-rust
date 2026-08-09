// SPDX-License-Identifier: Apache-2.0
//! Credit-ledger HTTP handlers for the Rust IICP directory operator preview.
//!
//! This module owns the iicp-dir section 6 surface only. It preserves the
//! existing router contract and delegates persistence to the shared repository.

use axum::{
    extract::{rejection::JsonRejection, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;

use crate::repo::CreditError;
use crate::state::AppState;
use crate::{bearer_token, emit_event, node_id_from_auth, reject};

// ── credits (iicp-dir §6) ────────────────────────────────────────────────────

/// `GET /v1/credits/balance` (iicp-dir §6.1). Returns the node's credit balance.
/// `GET /v1/credits/balance` — auth via JWT (sub) or X-Node-Id header fallback.
pub(crate) async fn credits_balance(
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
pub(crate) async fn credits_summary(
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
pub(crate) fn verify_cip_receipt(req: &CreditAwardRequest, hmac_key: &str) -> bool {
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
pub(crate) struct CreditAwardRequest {
    pub(crate) node_id: String,
    pub(crate) task_id: String,
    pub(crate) tokens_used: u64,
    #[serde(default)]
    pub(crate) cip_parent_task_id: String,
    #[serde(default)]
    pub(crate) cip_session_key: String,
    pub(crate) nonce: String,
    pub(crate) response_hash: String,
    /// HMAC-SHA256 hex (W-009) — must match PHP field name `signature` (size:64).
    pub(crate) signature: String,
    /// Credit amount to award. Capped at tokens_used/1000 × 1.1 on the server side.
    pub(crate) amount: f64,
    /// Optional querying node identity. When present, it is included in the receipt HMAC
    /// and lets the directory exclude self-dealing credit/reputation loops.
    #[serde(default)]
    pub(crate) querying_node_id: Option<String>,
}

/// `POST /v1/credits/award` (iicp-dir §6.2). Verifies the CIP receipt HMAC before
/// crediting the node. RT-02 nonce replay protection is enforced in record_credit_award.
pub(crate) async fn credits_award(
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

#[derive(Debug, Deserialize)]
pub(crate) struct LedgerPageParams {
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    per_page: Option<usize>,
}

/// `GET /v1/credits/transactions` (iicp-dir §6.3). Paginated ledger history.
pub(crate) async fn credits_transactions(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(p): Query<LedgerPageParams>,
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

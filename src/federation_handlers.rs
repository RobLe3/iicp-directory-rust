// SPDX-License-Identifier: Apache-2.0
//! Seed-side federation HTTP handlers.
//!
//! Owns the event-tail, snapshot, replica registration and replica
//! decommissioning routes. This is a behavior-preserving module boundary:
//! signing, persistence, authentication and public route shapes remain shared
//! with the released directory contract.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crate::state::AppState;
use crate::{auth, emit_event, err_json, reject};

/// `GET /v1/bootstrap` (iicp-dir §3.7). Returns recently-active nodes for peer discovery.
/// No intent filter — any available, recently-seen node qualifies.
#[derive(Debug, Deserialize)]
pub(crate) struct EventsParams {
    #[serde(default)]
    since_seq: Option<i64>,
    #[serde(default)]
    limit: Option<u32>,
}

/// `GET /v1/events` (#442, S.13 §3.4) — serve this directory's signed event log so a
/// replica (PHP or Rust) can tail it from `since_seq`. Mirrors the PHP seed's endpoint
/// shape that `replica::fetch_events` consumes: `{events:[…], next_seq, has_more}` with each
/// event carrying its Ed25519 `sig` + `signer_did` (this dir's DID).
pub(crate) async fn events(
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
pub(crate) async fn snapshot(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
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
pub(crate) struct ReplicaRegisterRequest {
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
pub(crate) async fn replicas_register(
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
pub(crate) async fn replicas_deregister(
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

//! Operator identity, governance acceptance, and data-subject self-service handlers.
//!
//! These handlers preserve the directory boundary: they operate on signed operator
//! metadata and never receive task payloads or private operator key material.

use std::collections::{BTreeMap, HashMap};

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::delegation;
use crate::repo::OperatorSelfServiceError;
use crate::state::AppState;
use crate::{err_json, reject};

const OPERATOR_CHALLENGE_TTL_SECS: u64 = 300;
const OPERATOR_TS_WINDOW_SECS: i64 = 300;
const RENAME_TS_WINDOW: i64 = 300;

/// One-use, process-local operator challenges. They are intentionally short
/// lived and contain no task content, credentials or private key material.
static OPERATOR_CHALLENGES: std::sync::OnceLock<std::sync::Mutex<HashMap<String, u64>>> =
    std::sync::OnceLock::new();

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
pub(crate) fn public_operator_fingerprint(operator_pubkey: &str) -> String {
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
pub(crate) async fn operator_display_name_for(
    st: &AppState,
    operator_pubkey: Option<&str>,
) -> Option<String> {
    match operator_pubkey {
        Some(p) => st.repo.operator_display_name(p).await,
        None => None,
    }
}

pub(crate) fn operator_fingerprint_for(operator_pubkey: Option<&str>) -> Option<String> {
    operator_pubkey
        .filter(|p| !p.is_empty())
        .map(public_operator_fingerprint)
}

/// #463/#310/#464 — upsert the operator-identity record (keyed by operator_id ==
/// operator_pubkey) when a delegation verified. display_name is public + mutable; contact is
/// never accepted; integrity_hash + first_seen_ms are pinned on first insert (PHP parity #385).
pub(crate) async fn upsert_operator_from_register(
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
pub(crate) struct RenameRequest {
    operator_pub: String,
    display_name: String,
    ts: i64,
    sig: String,
}

/// `POST /v1/operator/rename` (#460, PHP `OperatorController::rename` parity #385). Changes
/// the public, mutable `display_name` over the immutable operator_id (== operator_pubkey).
/// Only the operator key-holder may rename — authenticated by their ed25519 signature over
/// the canonical bytes, replay-protected by a ±300s timestamp window. One signed call
/// updates the single operator-keyed record, reflected on every node + the leaderboard;
/// the operator_id and any earned founder ordinal stay bound to the key.
pub(crate) async fn operator_rename(
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
pub(crate) struct OperatorChallengeRequest {
    operator_pub: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OperatorKeyRequest {
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

pub(crate) fn operator_terms_version() -> String {
    std::env::var("IICP_OPERATOR_TERMS_VERSION").unwrap_or_else(|_| "2026-07-09".to_string())
}

pub(crate) fn operator_dpa_version() -> String {
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

pub(crate) async fn operator_challenge(
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

// Keep the complete no-store HTTP refusal so every caller returns the same
// security headers and structured error without reconstructing it.
#[allow(clippy::result_large_err)]
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

pub(crate) async fn operator_acceptance(
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

pub(crate) async fn operator_dsr_export(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    operator_dsr_action(st, req, "export").await
}

pub(crate) async fn operator_dsr_restrict(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    operator_dsr_action(st, req, "restrict").await
}

pub(crate) async fn operator_dsr_anonymize(
    State(st): State<AppState>,
    Json(req): Json<OperatorKeyRequest>,
) -> Response {
    operator_dsr_action(st, req, "anonymize").await
}

pub(crate) async fn operator_key_rotate(
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

pub(crate) async fn operator_key_revoke(
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

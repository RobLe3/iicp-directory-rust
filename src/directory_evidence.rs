// SPDX-License-Identifier: Apache-2.0
//! Public directory identity, deployment and compliance evidence handlers.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use crate::config::DEFAULT_DIRECTORY_DID;
use crate::state::AppState;
use crate::{deployment_provenance, err_json, federation, VERSION};

/// `GET /.well-known/did.json` — DID document for `did:web:iicp.network` (iicp-dir §3.11).
///
/// #442: when this directory has a signing key (IICP_GENESIS_ED25519_SECRET_KEY), it
/// publishes the matching Ed25519 public key in verificationMethod[].publicKeyJwk — so a
/// replica can resolve it (replica::seed_pubkey_hex_from_did) and VERIFY this seed's signed
/// events. Without that, the seed signs but no replica could verify (empty doc → unsigned
/// trust-poll mode). Empty verificationMethod when no key is configured.
pub(crate) async fn did_document(State(st): State<AppState>) -> Json<serde_json::Value> {
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

pub(crate) async fn deployment_record(
    State(st): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
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

pub(crate) fn unix_now() -> i64 {
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

pub(crate) fn sign_domain_token(
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
pub(crate) async fn directory_key(
    State(st): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
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

/// `GET /api/v1/compliance-attestation` — compact signed Rust parity attestation.
/// The PHP seed signs full REACH probe evidence. Rust can emit a minimal signed
/// attestation when configured; without the signing key it fails closed.
pub(crate) async fn compliance_attestation(
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
pub(crate) async fn iicp_replicas(State(st): State<AppState>) -> impl IntoResponse {
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

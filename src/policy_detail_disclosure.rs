// SPDX-License-Identifier: Apache-2.0
//! Pre-normative provider-detail authorization/redaction policy.
//!
//! This is an implementation/parity helper, not a mounted Directory endpoint.

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use ed25519_compact::{PublicKey, Signature};
use serde_json::{json, Map, Value};

const CONSUMER_TOKEN_DOMAIN: &[u8] = b"iicp:consumer-token:v1\n";

pub const ALLOWED_DETAIL_FIELDS: [&str; 4] = [
    "retention_intervals",
    "subprocessor_references",
    "approval_evidence_references",
    "operational_evidence_references",
];

pub fn evaluate(context: &Value) -> Value {
    let auth = context["consumer_auth"].as_str();
    if auth == Some("missing") {
        return json!({"status":401,"reason":"consumer_auth_required"});
    }
    if !matches!(auth, Some("valid" | "expired" | "revoked")) {
        return json!({"status":401,"reason":"consumer_auth_invalid"});
    }
    if auth == Some("expired") {
        return json!({"status":401,"reason":"consumer_auth_expired"});
    }
    if auth == Some("revoked") {
        return json!({"status":401,"reason":"consumer_auth_revoked"});
    }
    match context["dispatch_ticket"].as_str() {
        Some("expired") => return json!({"status":401,"reason":"dispatch_ticket_expired"}),
        Some("revoked") => return json!({"status":401,"reason":"dispatch_ticket_revoked"}),
        Some("valid") | None => {}
        _ => return json!({"status":401,"reason":"dispatch_ticket_invalid"}),
    }
    if context["disclosure_allowed"].as_bool() != Some(true) {
        return json!({"status":403,"reason":"disclosure_forbidden"});
    }

    let provider = context["provider_node_id"]
        .as_str()
        .filter(|value| !value.is_empty());
    let intent = context["consumer_intent"]
        .as_str()
        .filter(|value| !value.is_empty());
    let digest = context["manifest_sha256"]
        .as_str()
        .filter(|value| !value.is_empty());
    let bound = provider.is_some()
        && provider == context["consumer_target_node_id"].as_str()
        && provider == context["ticket_target_node_id"].as_str()
        && intent.is_some()
        && intent == context["ticket_intent"].as_str()
        && digest.is_some()
        && digest == context["ticket_manifest_sha256"].as_str();
    if !bound {
        return json!({"status":404,"reason":"resource_concealed"});
    }

    let mut details = Map::new();
    if let Some(source) = context["details"].as_object() {
        for field in ALLOWED_DETAIL_FIELDS {
            if let Some(value) = source.get(field) {
                details.insert(field.into(), value.clone());
            }
        }
    }
    json!({"status":200,"reason":"compatible","body":{
        "profile":"urn:iicp:profile:policy-detail-disclosure:v0",
        "manifest_sha256":digest.expect("checked above"),
        "details":details,
        "claim_status":"provider_declared"
    }})
}

pub fn verify_consumer_token(
    token: &str,
    public_key_hex: &str,
    target: &str,
    intent: &str,
    now: i64,
) -> Value {
    let invalid = || json!({"status":"invalid"});
    let Some((payload, signature_hex)) = token.split_once('.') else {
        return invalid();
    };
    if signature_hex.len() != 128 {
        return invalid();
    }
    let Ok(key_raw) = hex::decode(public_key_hex) else {
        return invalid();
    };
    let Ok(sig_raw) = hex::decode(signature_hex) else {
        return invalid();
    };
    let Ok(key) = PublicKey::from_slice(&key_raw) else {
        return invalid();
    };
    let Ok(signature) = Signature::from_slice(&sig_raw) else {
        return invalid();
    };
    let message = [CONSUMER_TOKEN_DOMAIN, payload.as_bytes()].concat();
    if key.verify(&message, &signature).is_err() {
        return invalid();
    }
    let Ok(decoded) = Base64UrlSafeNoPadding::decode_to_vec(payload, None) else {
        return invalid();
    };
    let Ok(claims) = serde_json::from_slice::<Value>(&decoded) else {
        return invalid();
    };
    if claims["v"] != 1
        || claims["aud"] != target
        || claims["intent"] != intent
        || claims["sub"].as_str().is_none()
    {
        return invalid();
    }
    if claims["exp"].as_i64().is_none_or(|exp| exp <= now) {
        return json!({"status":"expired","claims":claims});
    }
    json!({"status":"valid","claims":claims})
}

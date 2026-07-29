// SPDX-License-Identifier: Apache-2.0
//! Public node-policy manifest verification (PHP `NodePolicyManifestVerifier` parity).
//!
//! This is deliberately a capability-evidence layer, not legal certification.
//! Unsigned manifests remain self-attested; a present but invalid, expired or
//! revoked signature fails registration closed.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    pub status: &'static str,
    pub evidence: &'static str,
    pub algorithm: Option<String>,
    pub key_id: Option<String>,
    pub signed_at: Option<String>,
    pub expires_at: Option<String>,
    pub canonical_sha256: String,
    pub public_key_sha256: Option<String>,
    pub manifest_identity_level: &'static str,
    pub policy_key_fingerprint: Option<String>,
    pub revoked_at: Option<String>,
    pub rotation_epoch: Option<u32>,
    pub revocation_reason_class: Option<String>,
    pub error: Option<String>,
}

impl Verification {
    pub fn accepted(&self) -> bool {
        matches!(self.status, "self_attested" | "signed_valid")
    }
}

pub fn verify(manifest: &Value) -> Verification {
    let canonical = canonical_payload(manifest);
    let result = base_verification(&canonical);
    let Some(signature_value) = manifest.get("signature") else {
        return result;
    };
    let Some(signature) = signature_value.as_object() else {
        return invalid(result, "signature block must be an object");
    };
    let result = with_signature_metadata(result, signature);
    let result = match verify_detached(result, signature, &canonical) {
        Ok(result) => result,
        Err(result) => return result,
    };
    apply_signature_time(result)
}

fn base_verification(canonical: &[u8]) -> Verification {
    Verification {
        status: "self_attested",
        evidence: "self_attested",
        algorithm: None,
        key_id: None,
        signed_at: None,
        expires_at: None,
        canonical_sha256: hex::encode(Sha256::digest(canonical)),
        public_key_sha256: None,
        manifest_identity_level: "self_attested",
        policy_key_fingerprint: None,
        revoked_at: None,
        rotation_epoch: None,
        revocation_reason_class: None,
        error: None,
    }
}

fn with_signature_metadata(
    mut result: Verification,
    signature: &Map<String, Value>,
) -> Verification {
    result.algorithm = string_field(signature, "algorithm");
    result.key_id = string_field(signature, "key_id");
    result.signed_at = string_field(signature, "signed_at");
    result.expires_at = string_field(signature, "expires_at");
    result.revoked_at = string_field(signature, "revoked_at");
    result.rotation_epoch = signature
        .get("rotation_epoch")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    result.revocation_reason_class = string_field(signature, "revocation_reason_class")
        .filter(|value| valid_reason_class(value));
    result
}

#[allow(clippy::result_large_err)] // Both outcomes expose one normalized verification record.
fn verify_detached(
    mut result: Verification,
    signature: &Map<String, Value>,
    canonical: &[u8],
) -> Result<Verification, Verification> {
    if result.algorithm.as_deref() != Some("Ed25519") {
        return Err(invalid(result, "unsupported signature algorithm"));
    }
    let Some(public_key) = decode_base64(string_field(signature, "public_key").as_deref()) else {
        return Err(invalid(result, "invalid Ed25519 public key"));
    };
    let Some(detached) = decode_base64(string_field(signature, "signature").as_deref()) else {
        return Err(invalid(result, "invalid Ed25519 signature"));
    };
    if public_key.len() != 32 || detached.len() != 64 {
        return Err(invalid(result, "invalid Ed25519 signature material"));
    }
    let public_key_sha = hex::encode(Sha256::digest(&public_key));
    result.policy_key_fingerprint = Some(public_key_sha[..12].to_string());
    result.public_key_sha256 = Some(public_key_sha);
    let Ok(key) = ed25519_compact::PublicKey::from_slice(&public_key) else {
        return Err(invalid(result, "invalid Ed25519 public key"));
    };
    let Ok(signature_value) = ed25519_compact::Signature::from_slice(&detached) else {
        return Err(invalid(result, "invalid Ed25519 signature"));
    };
    if key.verify(canonical, &signature_value).is_err() {
        return Err(invalid(result, "signature verification failed"));
    }
    Ok(result)
}

fn apply_signature_time(mut result: Verification) -> Verification {
    if timestamp_is_past(result.revoked_at.as_deref()) == Some(true) {
        result.status = "signed_revoked";
        result.evidence = "signed_revoked";
        result.manifest_identity_level = "revoked";
        result.error = Some("policy key revoked".to_string());
        return result;
    }
    if result.expires_at.is_some() && timestamp_is_past(result.expires_at.as_deref()) != Some(false)
    {
        result.status = if timestamp_is_past(result.expires_at.as_deref()) == Some(true) {
            "signed_expired"
        } else {
            "signed_invalid"
        };
        result.evidence = result.status;
        result.error = Some("signature expiry is invalid or elapsed".to_string());
        return result;
    }
    result.status = "signed_valid";
    result.evidence = "signed_verified";
    result.manifest_identity_level = "signed_valid";
    result
}

pub fn validate_shape(manifest: &Value) -> Result<(), &'static str> {
    let Some(object) = manifest.as_object() else {
        return Err("policy_manifest must be an object");
    };
    if ["version", "jurisdiction"]
        .iter()
        .any(|field| invalid_short_text(object.get(*field)))
    {
        return Err("policy_manifest contains an invalid text field");
    }
    if object.get("training_use").is_some_and(|value| {
        !matches!(value.as_str(), Some("none" | "opt_in" | "provider_defined"))
    }) {
        return Err("policy_manifest training_use is invalid");
    }
    if manifest
        .pointer("/retention/task_payload")
        .is_some_and(|value| {
            !matches!(
                value.as_str(),
                Some("none" | "transient" | "provider_defined")
            )
        })
    {
        return Err("policy_manifest retention.task_payload is invalid");
    }
    if manifest
        .pointer("/retention/logs_days")
        .and_then(Value::as_u64)
        .is_some_and(|days| days > 3650)
    {
        return Err("policy_manifest retention.logs_days is invalid");
    }
    if ["subprocessors", "unsupported_intents"]
        .iter()
        .any(|field| invalid_list(object.get(*field)))
    {
        return Err("policy_manifest list field is invalid");
    }
    Ok(())
}

fn invalid_short_text(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.as_str().is_none_or(|text| text.len() > 64))
}

fn invalid_list(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.as_array().is_none_or(|items| items.len() > 100))
}

pub fn canonical_payload(manifest: &Value) -> Vec<u8> {
    let mut value = manifest.clone();
    if let Some(signature) = value.get_mut("signature").and_then(Value::as_object_mut) {
        signature.remove("signature");
    } else if let Some(object) = value.as_object_mut() {
        object.remove("signature");
    }
    serde_json::to_vec(&sort_recursive(value)).unwrap_or_else(|_| b"{}".to_vec())
}

fn sort_recursive(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut pairs: Vec<_> = object.into_iter().collect();
            pairs.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(Map::from_iter(
                pairs
                    .into_iter()
                    .map(|(key, value)| (key, sort_recursive(value))),
            ))
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_recursive).collect()),
        other => other,
    }
}

fn invalid(mut result: Verification, message: &str) -> Verification {
    result.status = "signed_invalid";
    result.evidence = "signed_invalid";
    result.error = Some(message.to_string());
    result
}

fn string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    map.get(field).and_then(Value::as_str).map(str::to_string)
}

fn decode_base64(value: Option<&str>) -> Option<Vec<u8>> {
    use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder};
    let value = value?.trim();
    Base64::decode_to_vec(value, None)
        .or_else(|_| Base64UrlSafeNoPadding::decode_to_vec(value, None))
        .ok()
}

fn timestamp_is_past(value: Option<&str>) -> Option<bool> {
    let value = chrono::DateTime::parse_from_rfc3339(value?).ok()?;
    Some(value.with_timezone(&chrono::Utc) < chrono::Utc::now())
}

fn valid_reason_class(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Base64, Encoder};
    use ed25519_compact::{KeyPair, Seed};

    #[test]
    fn unsigned_is_self_attested_and_signed_tampering_fails_closed() {
        let unsigned = serde_json::json!({"version":"1","retention":{"logs_days":0}});
        assert_eq!(verify(&unsigned).status, "self_attested");
        let keypair = KeyPair::from_seed(Seed::new([7; 32]));
        let mut signed = serde_json::json!({
            "version":"1",
            "retention":{"logs_days":0},
            "signature":{"algorithm":"Ed25519","public_key":Base64::encode_to_string(&keypair.pk[..]).unwrap()}
        });
        let signature = keypair.sk.sign(canonical_payload(&signed), None);
        signed["signature"]["signature"] =
            Value::String(Base64::encode_to_string(&signature[..]).unwrap());
        assert_eq!(verify(&signed).status, "signed_valid");
        signed["retention"]["logs_days"] = Value::from(1);
        assert_eq!(verify(&signed).status, "signed_invalid");
    }
}

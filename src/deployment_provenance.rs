// SPDX-License-Identifier: Apache-2.0

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use serde_json::{json, Value};

pub const DOMAIN: &[u8] = b"IICP-DEPLOYMENT-RECORD-V1\0";
pub const PURPOSE: &str = "iicp-deployment-record-v1";

#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    pub kind: String,
    pub flavor: String,
    pub runtime_version: String,
    pub release_tag: String,
    pub source_commit: String,
    pub build_digest: String,
    pub image_digest: Option<String>,
    pub sbom_digest: Option<String>,
    pub openapi_version: String,
    pub protocol_min: String,
    pub protocol_max: String,
    pub deployed_at: String,
    pub root_key_id: String,
}

impl DeploymentConfig {
    pub fn from_env(runtime_version: &str) -> Option<Self> {
        Some(Self {
            kind: required("IICP_DEPLOYMENT_KIND")?,
            flavor: "rust".to_string(),
            runtime_version: runtime_version.to_string(),
            release_tag: required("IICP_RELEASE_TAG")?,
            source_commit: required("IICP_SOURCE_COMMIT")?,
            build_digest: required("IICP_BUILD_ID")?,
            image_digest: digest_env("IICP_IMAGE_DIGEST"),
            sbom_digest: digest_env("IICP_SBOM_DIGEST"),
            openapi_version: env_default("IICP_OPENAPI_VERSION", "1.7.0"),
            protocol_min: env_default("IICP_PROTOCOL_MIN", "1.9.0"),
            protocol_max: env_default("IICP_PROTOCOL_MAX", "1.9.0"),
            deployed_at: required("IICP_DEPLOYED_AT")?,
            root_key_id: required("IICP_ROOT_KEY_ID")?,
        })
        .filter(Self::valid)
    }

    fn valid(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "shared_hosting" | "container" | "native" | "other"
        ) && matches!(self.flavor.as_str(), "php" | "rust" | "other")
            && is_hex(&self.source_commit, 40)
            && is_digest(&self.build_digest)
    }

    fn unsigned_record(&self) -> Value {
        json!({
            "schema": "iicp.deployment-record.v1",
            "deployment_kind": self.kind,
            "directory": {
                "flavor": self.flavor,
                "runtime_version": self.runtime_version,
                "release_tag": self.release_tag,
                "source_commit": self.source_commit.to_ascii_lowercase()
            },
            "artifact": {
                "build_digest": self.build_digest,
                "image_digest": self.image_digest,
                "sbom_digest": self.sbom_digest
            },
            "compatibility": {
                "openapi_version": self.openapi_version,
                "protocol_min": self.protocol_min,
                "protocol_max": self.protocol_max
            },
            "deployed_at": self.deployed_at,
            "root_key_id": self.root_key_id
        })
    }
}

pub fn sign(config: &DeploymentConfig, secret_key_hex: &str) -> Option<Value> {
    if !config.valid() {
        return None;
    }
    let secret = hex::decode(secret_key_hex).ok()?;
    if secret.len() != 64 {
        return None;
    }
    let seed: [u8; 32] = secret.get(..32)?.try_into().ok()?;
    let keypair = KeyPair::from_seed(Seed::new(seed));
    let mut record = config.unsigned_record();
    let canonical = serde_jcs::to_vec(&record).ok()?;
    let mut message = Vec::with_capacity(DOMAIN.len() + canonical.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&canonical);
    let signature = keypair.sk.sign(&message, None);
    let encoded = Base64UrlSafeNoPadding::encode_to_string(signature.as_ref()).ok()?;
    record.as_object_mut()?.insert(
        "signature".to_string(),
        json!({
            "algorithm": "Ed25519",
            "purpose": PURPOSE,
            "key_id": config.root_key_id,
            "value": encoded
        }),
    );
    Some(record)
}

#[allow(dead_code)] // Shared verifier is exercised by fixtures and available for operator tooling.
pub fn verify(
    record: &Value,
    public_key: &[u8],
    observed_at: Option<i64>,
    max_age: Option<i64>,
) -> bool {
    let Some(signature) = record.get("signature") else {
        return false;
    };
    if signature.get("algorithm").and_then(Value::as_str) != Some("Ed25519")
        || signature.get("purpose").and_then(Value::as_str) != Some(PURPOSE)
        || signature.get("key_id") != record.get("root_key_id")
    {
        return false;
    }
    let Some(encoded) = signature.get("value").and_then(Value::as_str) else {
        return false;
    };
    let Ok(raw) = Base64UrlSafeNoPadding::decode_to_vec(encoded, None) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&raw) else {
        return false;
    };
    let Ok(key) = PublicKey::from_slice(public_key) else {
        return false;
    };
    let mut unsigned = record.clone();
    let Some(object) = unsigned.as_object_mut() else {
        return false;
    };
    object.remove("signature");
    let Ok(canonical) = serde_jcs::to_vec(&unsigned) else {
        return false;
    };
    let mut message = Vec::with_capacity(DOMAIN.len() + canonical.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&canonical);
    if key.verify(&message, &signature).is_err() {
        return false;
    }

    if let (Some(observed), Some(max_age)) = (observed_at, max_age) {
        let Some(deployed) = unsigned
            .get("deployed_at")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.timestamp())
        else {
            return false;
        };
        let age = observed - deployed;
        if age < 0 || age > max_age {
            return false;
        }
    }
    true
}

fn required(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_default(name: &str, default: &str) -> String {
    required(name).unwrap_or_else(|| default.to_string())
}

fn digest_env(name: &str) -> Option<String> {
    required(name).filter(|value| is_digest(value))
}

fn is_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| is_hex(digest, 64))
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_config() -> DeploymentConfig {
        DeploymentConfig {
            kind: "shared_hosting".into(),
            flavor: "php".into(),
            runtime_version: "v1.10.81.2".into(),
            release_tag: "v1.10.81.2".into(),
            source_commit: "a".repeat(40),
            build_digest: format!("sha256:{}", "b".repeat(64)),
            image_digest: None,
            sbom_digest: None,
            openapi_version: "1.6.0".into(),
            protocol_min: "1.9.0".into(),
            protocol_max: "1.9.0".into(),
            deployed_at: "2026-07-29T16:54:13Z".into(),
            root_key_id: "did:web:iicp.network#key-1".into(),
        }
    }

    fn fixture_keypair() -> KeyPair {
        KeyPair::from_seed(Seed::new([0x42; 32]))
    }

    #[test]
    fn shared_fixture_signature_matches_and_verifies() {
        let config = fixture_config();
        let keypair = fixture_keypair();
        let secret = format!(
            "{}{}",
            hex::encode([0x42; 32]),
            hex::encode(keypair.pk.as_ref())
        );
        let record = sign(&config, &secret).unwrap();
        assert!(verify(&record, keypair.pk.as_ref(), None, None));

        let fixture: Value =
            serde_json::from_str(include_str!("../parity/iicp-deployment-record-v1.json")).unwrap();
        assert_eq!(record, fixture["valid_record"]);
    }

    #[test]
    fn tamper_wrong_purpose_rotation_and_stale_policy_fail() {
        let config = fixture_config();
        let keypair = fixture_keypair();
        let secret = format!(
            "{}{}",
            hex::encode([0x42; 32]),
            hex::encode(keypair.pk.as_ref())
        );
        let record = sign(&config, &secret).unwrap();

        let mut tampered = record.clone();
        tampered["artifact"]["build_digest"] = Value::String(format!("sha256:{}", "c".repeat(64)));
        assert!(!verify(&tampered, keypair.pk.as_ref(), None, None));

        let mut wrong = record.clone();
        wrong["signature"]["purpose"] = Value::String("iicp-event-v1".into());
        assert!(!verify(&wrong, keypair.pk.as_ref(), None, None));

        let mut rotated = record.clone();
        rotated["signature"]["key_id"] = Value::String("did:web:iicp.network#key-2".into());
        assert!(!verify(&rotated, keypair.pk.as_ref(), None, None));

        let observed = chrono::DateTime::parse_from_rfc3339("2026-08-05T16:54:14Z")
            .unwrap()
            .timestamp();
        assert!(!verify(
            &record,
            keypair.pk.as_ref(),
            Some(observed),
            Some(604_800)
        ));
    }
}

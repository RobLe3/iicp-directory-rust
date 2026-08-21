//! Signed restricted trust-domain membership assertions.

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use serde::{Deserialize, Serialize};

pub(crate) const MEMBERSHIP_DOMAIN: &[u8] = b"IICP-RTD-MEMBERSHIP-V0\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MembershipSubject {
    pub(crate) kind: String,
    pub(crate) id: String,
    pub(crate) key_id: String,
    pub(crate) public_key_ed25519: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MembershipIssuer {
    pub(crate) id: String,
    pub(crate) key_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MembershipAssertion {
    pub(crate) schema: String,
    pub(crate) profile: String,
    pub(crate) assertion_id: String,
    pub(crate) domain_id: String,
    pub(crate) subject: MembershipSubject,
    pub(crate) issuer: MembershipIssuer,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) generation: u64,
    pub(crate) scopes: Vec<String>,
    pub(crate) audience: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MembershipSignature {
    pub(crate) algorithm: String,
    pub(crate) value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MembershipEnvelope {
    pub(crate) assertion: MembershipAssertion,
    pub(crate) signature: MembershipSignature,
}

pub(crate) struct MembershipInput<'a> {
    pub(crate) domain_id: &'a str,
    pub(crate) authority_id: &'a str,
    pub(crate) authority_key_id: &'a str,
    pub(crate) subject_kind: &'a str,
    pub(crate) subject_id: &'a str,
    pub(crate) subject_key_id: &'a str,
    pub(crate) subject_public_key: &'a str,
    pub(crate) generation: u64,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) scopes: Vec<String>,
}

pub(crate) fn sign(
    input: MembershipInput<'_>,
    secret_key_hex: &str,
) -> Result<MembershipEnvelope, String> {
    let key = validate_signing_inputs(input.subject_public_key, secret_key_hex, &input.scopes)?;
    let assertion = assertion(input);
    let signature = key.sign(&signing_input(&assertion)?, None);
    Ok(MembershipEnvelope {
        assertion,
        signature: MembershipSignature {
            algorithm: "Ed25519".into(),
            value: Base64UrlSafeNoPadding::encode_to_string(signature.as_ref())
                .map_err(|_| "membership signature encoding failed")?,
        },
    })
}

pub(crate) fn validate_signing_inputs(
    subject_public_key: &str,
    secret_key_hex: &str,
    scopes: &[String],
) -> Result<ed25519_compact::SecretKey, String> {
    decode_public_key(subject_public_key)?;
    if scopes.is_empty() {
        return Err(
            "a peer-verifiable assertion requires at least one peer operation scope".into(),
        );
    }
    signing_key(secret_key_hex)
}

#[allow(dead_code)] // runtime peer verification is owned by the client; this directory consumes the shared KAT
pub(crate) fn verify(envelope: &MembershipEnvelope, authority_public_key: &str) -> bool {
    let Ok(public_key) = decode_public_key(authority_public_key) else {
        return false;
    };
    let Ok(raw) = Base64UrlSafeNoPadding::decode_to_vec(envelope.signature.value.as_bytes(), None)
    else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&raw) else {
        return false;
    };
    let Ok(input) = signing_input(&envelope.assertion) else {
        return false;
    };
    public_key.verify(&input, &signature).is_ok()
}

fn assertion(input: MembershipInput<'_>) -> MembershipAssertion {
    MembershipAssertion {
        schema: "iicp.restricted-trust-domain.membership-assertion.v0".into(),
        profile: "urn:iicp:profile:restricted-trust-domain:v1".into(),
        assertion_id: uuid::Uuid::new_v4().to_string(),
        domain_id: input.domain_id.into(),
        subject: MembershipSubject {
            kind: input.subject_kind.into(),
            id: input.subject_id.into(),
            key_id: input.subject_key_id.into(),
            public_key_ed25519: input.subject_public_key.into(),
        },
        issuer: MembershipIssuer {
            id: input.authority_id.into(),
            key_id: input.authority_key_id.into(),
        },
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        generation: input.generation,
        scopes: input.scopes,
        audience: vec![input.domain_id.into()],
    }
}

fn signing_input(assertion: &MembershipAssertion) -> Result<Vec<u8>, String> {
    let mut bytes = MEMBERSHIP_DOMAIN.to_vec();
    bytes.extend(serde_jcs::to_vec(assertion).map_err(|_| "membership canonicalization failed")?);
    Ok(bytes)
}

fn signing_key(secret_key_hex: &str) -> Result<ed25519_compact::SecretKey, String> {
    let bytes = hex::decode(secret_key_hex).map_err(|_| "invalid directory signing key")?;
    let seed: [u8; 32] = bytes
        .get(..32)
        .ok_or("invalid directory signing key")?
        .try_into()
        .map_err(|_| "invalid directory signing key")?;
    Ok(KeyPair::from_seed(Seed::new(seed)).sk)
}

fn decode_public_key(value: &str) -> Result<PublicKey, String> {
    let raw = Base64UrlSafeNoPadding::decode_to_vec(value.as_bytes(), None)
        .map_err(|_| "invalid Ed25519 public key")?;
    PublicKey::from_slice(&raw).map_err(|_| "invalid Ed25519 public key".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_membership_signatures_verify_without_translation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../parity/restricted-trust-domain-membership-v0.json"
        ))
        .unwrap();
        let authority = fixture["authority_public_key_ed25519"].as_str().unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let envelope: MembershipEnvelope =
                serde_json::from_value(vector["envelope"].clone()).unwrap();
            assert_eq!(
                verify(&envelope, authority),
                vector["expected"] == "valid",
                "{}",
                vector["id"]
            );
        }
    }

    #[test]
    fn restricted_bootstrap_fixture_keeps_public_and_revocation_boundaries() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../parity/restricted-trust-domain-bootstrap-v0.json"
        ))
        .unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        let public = vectors
            .iter()
            .find(|vector| vector["id"] == "public-legacy-peer-remains-compatible")
            .unwrap();
        assert!(public["response"]["peers"][0]
            .get("membership_vector")
            .is_none());
        let partial = vectors
            .iter()
            .find(|vector| vector["id"] == "restricted-partial-response-does-not-evict")
            .unwrap();
        assert_eq!(partial["expected"]["evicted"], serde_json::json!([]));
        assert_eq!(
            partial["expected"]["reason"],
            "partial_absence_is_not_revocation"
        );
    }

    #[test]
    fn issued_assertion_binds_subject_domain_generation_and_scope() {
        let authority = KeyPair::from_seed(Seed::new([7_u8; 32]));
        let subject = KeyPair::from_seed(Seed::new([9_u8; 32]));
        let authority_secret = hex::encode(authority.sk.as_ref());
        let authority_public =
            Base64UrlSafeNoPadding::encode_to_string(authority.pk.as_ref()).unwrap();
        let subject_public = Base64UrlSafeNoPadding::encode_to_string(subject.pk.as_ref()).unwrap();
        let envelope = sign(
            MembershipInput {
                domain_id: "domain-a",
                authority_id: "did:iicp:directory-a",
                authority_key_id: "did:iicp:directory-a#key-1",
                subject_kind: "node",
                subject_id: "did:iicp:node-a",
                subject_key_id: "did:iicp:node-a#key-1",
                subject_public_key: &subject_public,
                generation: 3,
                issued_at: 1_800_000_000,
                expires_at: 1_800_000_300,
                scopes: vec!["peers".into()],
            },
            &authority_secret,
        )
        .unwrap();

        assert!(verify(&envelope, &authority_public));
        assert_eq!(envelope.assertion.domain_id, "domain-a");
        assert_eq!(envelope.assertion.generation, 3);
        assert_eq!(envelope.assertion.scopes, ["peers"]);
        assert_eq!(
            envelope.assertion.subject.public_key_ed25519,
            subject_public
        );
    }
}

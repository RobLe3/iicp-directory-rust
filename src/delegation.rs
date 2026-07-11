// SPDX-License-Identifier: Apache-2.0
//! ADR-045 Phase A — verify an operator→node delegation OFFLINE (#407 / #2).
//!
//! Cross-flavour parity with the PHP `OperatorDelegationVerifier` (#385): a fleet
//! operator signs a compact ed25519 token asserting `<node_id>` is operated by
//! `<operator_pub>` until `<not_after>`. Any federated directory verifies it
//! locally — no phone-home — against its set of trusted operator public keys.
//! Proven in research #406 (correct on all 6 attack cases).
//!
//! Token shape (compact, ~205 B):
//!   { node_id, operator_pub: base64(ed25519 pubkey, 32B),
//!     not_after: unix-seconds, sig: base64(ed25519 sig, 64B) }
//!
//! The signed bytes are byte-identical across the PHP verifier and every SDK
//! signer (Python/TS/Rust) — pinned by the cross-language KAT in the tests below.

use serde::Deserialize;

/// The compact operator→node delegation token carried (optionally) at register.
#[derive(Debug, Clone, Deserialize)]
pub struct OperatorDelegation {
    pub node_id: String,
    pub operator_pub: String,
    pub not_after: u64,
    pub sig: String,
}

/// Canonical signing bytes: key-sorted (`node_id` < `not_after` < `operator_pub`),
/// no whitespace, unescaped slashes/unicode. MUST be byte-identical to PHP
/// `OperatorDelegationVerifier::canonicalBytes` and every SDK signer. Built
/// explicitly (not via a serde Map) so it is independent of serde_json's
/// `preserve_order` feature.
pub fn canonical_bytes(node_id: &str, operator_pub: &str, not_after: u64) -> Vec<u8> {
    format!(
        r#"{{"node_id":{},"not_after":{},"operator_pub":{}}}"#,
        serde_json::to_string(node_id).unwrap_or_default(),
        not_after,
        serde_json::to_string(operator_pub).unwrap_or_default(),
    )
    .into_bytes()
}

/// Verify a delegation token offline. Reason codes mirror the PHP verifier:
/// `ok` | `untrusted_operator` | `node_id_mismatch` | `revoked` | `expired`
/// | `malformed` | `bad_signature`.
pub fn verify(
    token: &OperatorDelegation,
    claimed_node_id: &str,
    trusted_operator_pubs: &[String],
    revoked_node_ids: &[String],
    now: u64,
) -> (bool, &'static str) {
    if !trusted_operator_pubs
        .iter()
        .any(|p| p == &token.operator_pub)
    {
        return (false, "untrusted_operator");
    }
    if token.node_id != claimed_node_id {
        return (false, "node_id_mismatch");
    }
    if revoked_node_ids.iter().any(|n| n == &token.node_id) {
        return (false, "revoked");
    }
    if now >= token.not_after {
        return (false, "expired");
    }

    use ct_codecs::{Base64, Decoder};
    let pub_raw = match Base64::decode_to_vec(&token.operator_pub, None) {
        Ok(b) if b.len() == 32 => b,
        _ => return (false, "malformed"),
    };
    let sig_raw = match Base64::decode_to_vec(&token.sig, None) {
        Ok(b) if b.len() == 64 => b,
        _ => return (false, "malformed"),
    };

    use ed25519_compact::{PublicKey, Signature};
    let Ok(pk) = PublicKey::from_slice(&pub_raw) else {
        return (false, "malformed");
    };
    let Ok(sig) = Signature::from_slice(&sig_raw) else {
        return (false, "malformed");
    };
    let msg = canonical_bytes(&token.node_id, &token.operator_pub, token.not_after);
    match pk.verify(&msg, &sig) {
        Ok(()) => (true, "ok"),
        Err(_) => (false, "bad_signature"),
    }
}

/// Register-time evaluation (PHP `NodeRegistry` parity, #385): self-asserted trust
/// set (did:key tier; the did:web higher-tier set layers on later, OPEN-2). Lenient
/// and fail-safe — a valid delegation binds the operator identity; an invalid or
/// absent one leaves the node unverified and NEVER aborts the registration (no false
/// binding is possible without the operator's signature). Returns the fields the
/// directory records: `(operator_pubkey, operator_verified, operator_trust_tier)`.
pub fn evaluate(
    delegation: Option<&OperatorDelegation>,
    claimed_node_id: &str,
    now: u64,
) -> (Option<String>, bool, Option<String>) {
    let Some(del) = delegation else {
        return (None, false, None);
    };
    let trusted = [del.operator_pub.clone()];
    let (ok, _reason) = verify(del, claimed_node_id, &trusted, &[], now);
    if ok {
        (
            Some(del.operator_pub.clone()),
            true,
            Some("did_key".to_string()),
        )
    } else {
        (None, false, None)
    }
}

/// #460 — canonical bytes the operator signs for a `display_name` rename. Key-sorted
/// (`display_name` < `operator_pub` < `ts`), no whitespace, slashes/unicode unescaped —
/// MUST be byte-identical to PHP `OperatorController::canonicalBytes` and every SDK
/// `operator rename` signer (cross-impl). Built explicitly (not via a serde Map) so it
/// is independent of serde_json's `preserve_order` feature.
pub fn canonical_rename_bytes(display_name: &str, operator_pub: &str, ts: i64) -> Vec<u8> {
    format!(
        r#"{{"display_name":{},"operator_pub":{},"ts":{}}}"#,
        serde_json::to_string(display_name).unwrap_or_default(),
        serde_json::to_string(operator_pub).unwrap_or_default(),
        ts,
    )
    .into_bytes()
}

/// #460 — verify an operator-signed rename. The operator (holder of `operator_pub`'s
/// secret) is the ONLY party that may change their record, so the signature over the
/// canonical rename bytes IS the authentication (no node token). Reason codes mirror the
/// PHP controller: `ok` | `malformed` (bad base64 / wrong key|sig length) | `bad_signature`.
pub fn verify_rename(
    operator_pub: &str,
    display_name: &str,
    ts: i64,
    sig: &str,
) -> (bool, &'static str) {
    use ct_codecs::{Base64, Decoder};
    let pub_raw = match Base64::decode_to_vec(operator_pub, None) {
        Ok(b) if b.len() == 32 => b,
        _ => return (false, "malformed"),
    };
    let sig_raw = match Base64::decode_to_vec(sig, None) {
        Ok(b) if b.len() == 64 => b,
        _ => return (false, "malformed"),
    };
    use ed25519_compact::{PublicKey, Signature};
    let Ok(pk) = PublicKey::from_slice(&pub_raw) else {
        return (false, "malformed");
    };
    let Ok(s) = Signature::from_slice(&sig_raw) else {
        return (false, "malformed");
    };
    match pk.verify(canonical_rename_bytes(display_name, operator_pub, ts), &s) {
        Ok(()) => (true, "ok"),
        Err(_) => (false, "bad_signature"),
    }
}

/// Current unix time in seconds (delegation expiry is coarse; sub-second precision
/// is irrelevant). Clamped to 0 on the impossible pre-epoch error.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_codecs::{Base64, Decoder, Encoder};
    use ed25519_compact::{KeyPair, Seed};

    // Cross-language KAT — MUST equal the PHP OperatorDelegationVerifier::canonicalBytes
    // and the SDK signers (iicp-client-{python,typescript,rust}). Byte-for-byte identical
    // signing input is what makes a Rust-directory verify a token any SDK signed (#385).
    const KAT: &str =
        r#"{"node_id":"node-kat-1","not_after":1893456000,"operator_pub":"T3BQdWJLZXlCYXNlNjQ="}"#;

    #[test]
    fn canonical_bytes_match_cross_language_kat() {
        let b = canonical_bytes("node-kat-1", "T3BQdWJLZXlCYXNlNjQ=", 1_893_456_000);
        assert_eq!(String::from_utf8(b).unwrap(), KAT);
    }

    /// Sign a token with a deterministic test key (seed 0x07*32).
    fn signed_token(node_id: &str, not_after: u64) -> (OperatorDelegation, String) {
        let kp = KeyPair::from_seed(Seed::new([7u8; 32]));
        let op_pub = Base64::encode_to_string(&kp.pk[..]).unwrap();
        let msg = canonical_bytes(node_id, &op_pub, not_after);
        let sig = kp.sk.sign(&msg, None);
        let sig_b64 = Base64::encode_to_string(&sig[..]).unwrap();
        (
            OperatorDelegation {
                node_id: node_id.into(),
                operator_pub: op_pub.clone(),
                not_after,
                sig: sig_b64,
            },
            op_pub,
        )
    }

    #[test]
    fn verify_accepts_valid_and_evaluate_records_binding() {
        let (tok, op_pub) = signed_token("node-1", 4_000_000_000);
        assert_eq!(
            verify(&tok, "node-1", std::slice::from_ref(&op_pub), &[], 1_000),
            (true, "ok")
        );
        let (pubk, ver, tier) = evaluate(Some(&tok), "node-1", 1_000);
        assert_eq!(
            (pubk.as_deref(), ver, tier.as_deref()),
            (Some(op_pub.as_str()), true, Some("did_key"))
        );
    }

    #[test]
    fn verify_rejects_each_failure_case_with_php_reason_codes() {
        let (tok, op_pub) = signed_token("node-1", 4_000_000_000);
        assert_eq!(
            verify(&tok, "node-1", &["other".into()], &[], 1_000).1,
            "untrusted_operator"
        );
        assert_eq!(
            verify(&tok, "node-2", std::slice::from_ref(&op_pub), &[], 1_000).1,
            "node_id_mismatch"
        );
        assert_eq!(
            verify(
                &tok,
                "node-1",
                std::slice::from_ref(&op_pub),
                &["node-1".into()],
                1_000
            )
            .1,
            "revoked"
        );
        assert_eq!(
            verify(
                &tok,
                "node-1",
                std::slice::from_ref(&op_pub),
                &[],
                5_000_000_000
            )
            .1,
            "expired"
        );

        // Tamper the signature → bad_signature (not malformed: still 64 valid bytes).
        let mut tampered = tok.clone();
        let mut raw = Base64::decode_to_vec(&tok.sig, None).unwrap();
        raw[0] ^= 0xff;
        tampered.sig = Base64::encode_to_string(&raw[..]).unwrap();
        assert_eq!(
            verify(
                &tampered,
                "node-1",
                std::slice::from_ref(&op_pub),
                &[],
                1_000
            )
            .1,
            "bad_signature"
        );

        // Wrong-length pubkey → malformed.
        let mut bad_pub = tok.clone();
        bad_pub.operator_pub = Base64::encode_to_string(b"short").unwrap();
        assert_eq!(
            verify(
                &bad_pub,
                "node-1",
                &[bad_pub.operator_pub.clone()],
                &[],
                1_000
            )
            .1,
            "malformed"
        );
    }

    #[test]
    fn evaluate_absent_or_invalid_leaves_unverified() {
        assert_eq!(evaluate(None, "node-1", 1_000), (None, false, None));
        let (tok, _op_pub) = signed_token("node-1", 4_000_000_000);
        // Expired delegation → not recorded (operator_verified=false, no pubkey bound).
        assert_eq!(
            evaluate(Some(&tok), "node-1", 5_000_000_000),
            (None, false, None)
        );
    }
}

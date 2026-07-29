// SPDX-License-Identifier: Apache-2.0
//! Federation event-log verification (ADR-013 / S.13 / #385).
//!
//! Wire-compatible with the PHP Genesis Seed's `NodeEventLogger` signing scheme so a
//! Rust replica can verify the PHP seed's signed event log (DIR-FED-01):
//! ```text
//!   payload_hash = sha256_hex(canonical_json(payload))
//!   prev_hash    = sha256_hex(ascii(predecessor signature)) | GENESIS_ROOT   (#458)
//!   message      = sha256_raw("{event_id}:{event_type}:{seq}:{ts_ms}:{payload_hash}:{prev_hash}")
//!   sig          = hex(ed25519_detached_sign(message, genesis_seed_secret_key))
//! ```
//! `canonical_json` mirrors PHP `ksort` + `json_encode(JSON_UNESCAPED_SLASHES|UNICODE)`
//! (spec §3.4 canonical form — full RFC 8785 is Phase 6B, matching the PHP caveat).
//! Verification uses `ed25519-compact` (jedisct1 / libsodium lineage) against the
//! Genesis Seed's Ed25519 public key resolved from its DID document.

// These are the crypto keystone; the replica event-applier (next #385 federation
// step) is their caller. Allow until that lands so the build stays warning-clean.
#![allow(dead_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Canonical JSON: recursively key-sorted, compact (no whitespace), with forward
/// slashes and unicode left unescaped — byte-identical to the PHP seed's
/// `canonicalJson()` (`ksort` + `json_encode(JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)`).
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort(); // lexicographic by key bytes — matches PHP ksort on string keys
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        // Scalars: serde_json's compact repr does not escape `/` or non-ASCII by
        // default, matching PHP's UNESCAPED flags.
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Hash-chain genesis root (#458): `SHA256_hex("iicp:dir:event-log:genesis:v1")`. The
/// `prev_hash` of the first signed event (or the first after an unsigned span) is this.
pub const GENESIS_ROOT: &str = "c44802bedf3e63b5a3f1634c5d19263634f92f26dd15401b09b06dd53a80cf9d";

/// `prev_hash` for an event whose predecessor's signature is `prev_sig` (#458): the
/// SHA-256 (hex) of the predecessor's 128-hex Ed25519 signature ASCII bytes. When there
/// is no signed predecessor (`None`, or an unsigned/null prior signature) the chain
/// (re)starts from [`GENESIS_ROOT`]. Chaining on the signature — a hex string that
/// survives the wire identically on every implementation — keeps `prev_hash` reproducible
/// regardless of cross-language number canonicalization (see spec §5.1).
pub fn prev_hash_from(prev_sig: Option<&str>) -> String {
    match prev_sig.filter(|s| !s.is_empty()) {
        Some(sig) => hex::encode(Sha256::digest(sig.as_bytes())),
        None => GENESIS_ROOT.to_string(),
    }
}

/// The 32-byte Ed25519 message the Genesis Seed signs for an event. `prev_hash` binds the
/// event into the tamper-evident chain (#458) — see [`prev_hash_from`].
pub fn event_message(
    event_id: &str,
    event_type: &str,
    seq: i64,
    ts_ms: i64,
    payload: &Value,
    prev_hash: &str,
) -> [u8; 32] {
    let payload_hash = hex::encode(Sha256::digest(canonical_json(payload).as_bytes()));
    let input = format!("{event_id}:{event_type}:{seq}:{ts_ms}:{payload_hash}:{prev_hash}");
    Sha256::digest(input.as_bytes()).into()
}

/// Domain-separated signing message for an event carrying optional service-origin
/// metadata. Legacy events MUST continue to use [`event_message`]. A present service ID
/// selects V2 and is bound to the signature; it is metadata, never authorization.
pub fn event_message_with_service_id(
    service_id: &str,
    event_id: &str,
    event_type: &str,
    seq: i64,
    ts_ms: i64,
    payload: &Value,
    prev_hash: &str,
) -> Option<[u8; 32]> {
    if !valid_service_id(service_id) {
        return None;
    }
    let payload_hash = hex::encode(Sha256::digest(canonical_json(payload).as_bytes()));
    let input = format!(
        "iicp-event-v2:{service_id}:{event_id}:{event_type}:{seq}:{ts_ms}:{payload_hash}:{prev_hash}"
    );
    Some(Sha256::digest(input.as_bytes()).into())
}

pub fn valid_service_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Verify a hex Ed25519 detached signature over `message` against the seed's hex
/// public key (64 hex chars = 32 bytes). Returns false on any malformed input or a
/// bad signature — the replica MUST NOT apply an event that fails this (DIR-FED-01).
pub fn verify_event(pubkey_hex: &str, sig_hex: &str, message: &[u8; 32]) -> bool {
    use ed25519_compact::{PublicKey, Signature};
    let pk_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk = match PublicKey::from_slice(&pk_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    pk.verify(message, &sig).is_ok()
}

/// Sign an event with the directory's own Ed25519 key — the seed side of #442 (a Rust
/// directory emitting + signing its own `/v1/events` log, not just verifying the PHP
/// seed's). Byte-for-byte wire-compatible with PHP `NodeEventLogger::sign`
/// (`sodium_crypto_sign_detached`): deterministic RFC-8032 Ed25519 over the same
/// `event_message`, hex-encoded.
///
/// `secret_key_hex` is the libsodium 64-byte secret key (128 hex = seed[32]‖pubkey[32]),
/// matching PHP's `IICP_GENESIS_ED25519_SECRET_KEY`. Returns `None` if the key is
/// malformed (mirrors PHP returning null when no/invalid key is configured).
#[allow(dead_code)] // consumed by the emit path + GET /v1/events endpoint (next #442 slice)
pub fn sign_event(
    secret_key_hex: &str,
    event_id: &str,
    event_type: &str,
    seq: i64,
    ts_ms: i64,
    payload: &Value,
    prev_hash: &str,
) -> Option<String> {
    use ed25519_compact::{KeyPair, Seed};
    // libsodium's secret key is seed(32) ‖ pubkey(32); ed25519-compact derives the keypair
    // from the 32-byte seed (same standard Ed25519 → same key as crypto_sign_seed_keypair).
    let sk_bytes = hex::decode(secret_key_hex).ok()?;
    if sk_bytes.len() != 64 {
        return None;
    }
    let seed_bytes: [u8; 32] = sk_bytes.get(..32)?.try_into().ok()?;
    let kp = KeyPair::from_seed(Seed::new(seed_bytes));
    let message = event_message(event_id, event_type, seq, ts_ms, payload, prev_hash);
    // Noise=None → deterministic signature, matching libsodium's crypto_sign_detached.
    let sig = kp.sk.sign(message, None);
    Some(hex::encode(sig.as_ref()))
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)] // Protocol transcript has eight fixed signed fields.
pub fn sign_event_with_service_id(
    secret_key_hex: &str,
    service_id: &str,
    event_id: &str,
    event_type: &str,
    seq: i64,
    ts_ms: i64,
    payload: &Value,
    prev_hash: &str,
) -> Option<String> {
    use ed25519_compact::{KeyPair, Seed};
    let sk_bytes = hex::decode(secret_key_hex).ok()?;
    if sk_bytes.len() != 64 {
        return None;
    }
    let seed_bytes: [u8; 32] = sk_bytes.get(..32)?.try_into().ok()?;
    let kp = KeyPair::from_seed(Seed::new(seed_bytes));
    let message = event_message_with_service_id(
        service_id, event_id, event_type, seq, ts_ms, payload, prev_hash,
    )?;
    Some(hex::encode(kp.sk.sign(message, None).as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Known-Answer Test: signature produced by the PHP seed's exact libsodium scheme
    // (sodium_crypto_sign_detached) with a fixed 32-byte seed (0x11*32). Proves the
    // Rust verifier is byte-for-byte wire-compatible with the PHP Genesis Seed.
    const KAT_PUBKEY: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    // #458: KAT recomputed for the prev_hash-chained signing input (prev_hash = GENESIS_ROOT,
    // the genesis case). Standard RFC-8032 Ed25519 over the new SHA256 message → byte-identical
    // across ed25519-compact (here), PHP libsodium (NodeEventLoggerSignatureTest), and node:crypto.
    const KAT_SIG: &str = "dab46d8578fd741b4d6109351968dacc7560caf78cd0df7e9573c3a0537acdbe6f36be9e7280a60ea49dcc8020470471b1f01828e1ab5c820762d08849032a03";
    const KAT_MSG_HEX: &str = "bdb2183b5aa7d75cc90dcea5dcf950c04a50d0f5f3b96ef44fe230dc53e6f443";
    const SERVICE_V2_KAT_MSG_HEX: &str =
        "87d84d6cd402c45816355250169e37d2b5067846e440ae4fdb00c8cc3302e18d";
    const SERVICE_V2_KAT_SIG: &str = "d845a788503adff672f2d74e50eee3f23c86e7cfb1a041d4607765cafbcbcf78d8d7e10583c79263a573a1e48b05b679cc727016161aabe8a69f00101dba7d03";

    fn kat_payload() -> Value {
        json!({"endpoint": "http://localhost:8090", "region": "eu-central"})
    }

    #[test]
    fn canonical_json_matches_php() {
        assert_eq!(
            canonical_json(&kat_payload()),
            r#"{"endpoint":"http://localhost:8090","region":"eu-central"}"#
        );
        // nested + key reordering
        assert_eq!(
            canonical_json(&json!({"b": 2, "a": {"y": 1, "x": 0}})),
            r#"{"a":{"x":0,"y":1},"b":2}"#
        );
    }

    #[test]
    fn event_message_matches_php() {
        let msg = event_message(
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "REGISTER",
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        );
        assert_eq!(hex::encode(msg), KAT_MSG_HEX);
    }

    #[test]
    fn service_event_v2_is_domain_separated_and_validated() {
        let msg = event_message_with_service_id(
            "directory-monolith",
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "REGISTER",
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        )
        .expect("portable service id");
        assert_eq!(hex::encode(msg), SERVICE_V2_KAT_MSG_HEX);
        assert_ne!(
            msg,
            event_message(
                "474a7713-85c8-4d61-bea5-0ab16f3825a0",
                "REGISTER",
                1080,
                1779195794150,
                &kat_payload(),
                GENESIS_ROOT,
            )
        );
        assert!(event_message_with_service_id(
            "invalid:service",
            "event",
            "REGISTER",
            1,
            1,
            &json!({}),
            GENESIS_ROOT,
        )
        .is_none());
    }

    #[test]
    fn service_event_v2_signature_round_trips() {
        let secret_key_hex = format!("{}{}", "11".repeat(32), KAT_PUBKEY);
        let sig = sign_event_with_service_id(
            &secret_key_hex,
            "directory-monolith",
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "REGISTER",
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        )
        .expect("valid service event");
        assert_eq!(sig, SERVICE_V2_KAT_SIG);
        let msg = event_message_with_service_id(
            "directory-monolith",
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "REGISTER",
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        )
        .unwrap();
        assert!(verify_event(KAT_PUBKEY, &sig, &msg));
    }

    #[test]
    fn kat_php_libsodium_signature_verifies() {
        let msg = event_message(
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "REGISTER",
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        );
        assert!(
            verify_event(KAT_PUBKEY, KAT_SIG, &msg),
            "PHP/libsodium-signed event must verify in Rust (DIR-FED-01 cross-impl)"
        );
    }

    #[test]
    fn sign_event_matches_php_libsodium_kat() {
        // #442 seed side: the Rust signer must produce the BYTE-IDENTICAL signature the PHP
        // seed's sodium_crypto_sign_detached produced for the same key+event — so a PHP
        // replica can federate from a Rust seed. libsodium secret key = seed(0x11*32) ‖ pubkey.
        let secret_key_hex = format!("{}{}", "11".repeat(32), KAT_PUBKEY);
        let sig = sign_event(
            &secret_key_hex,
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "REGISTER",
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        )
        .expect("valid 64-byte key signs");
        assert_eq!(
            sig, KAT_SIG,
            "Rust sign_event must match the PHP libsodium signature byte-for-byte"
        );
        // Round-trip: the produced signature verifies under the KAT pubkey.
        let msg = event_message(
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "REGISTER",
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        );
        assert!(verify_event(KAT_PUBKEY, &sig, &msg));
    }

    #[test]
    fn sign_event_rejects_malformed_key() {
        assert!(sign_event("dead", "e", "REGISTER", 1, 1, &kat_payload(), GENESIS_ROOT).is_none());
    }

    #[test]
    fn capabilities_payload_kat_verifies() {
        // #438: REGISTER events now carry a capabilities array-of-objects. This KAT
        // (same fixed PHP/libsodium key) proves the Rust canonical_json + verify handle
        // that real federation-event shape — nested arrays + per-object key sorting —
        // byte-for-byte with the seed.
        let payload = json!({
            "endpoint": "https://n.test",
            "region": "eu-central",
            "capabilities": [
                {"intent": "urn:iicp:intent:llm:chat:v1", "models": ["llama-3-8b"], "max_tokens": 4096, "input_modalities": ["text"]},
                {"intent": "urn:iicp:intent:audio:transcribe:v1", "models": ["whisper-1"], "max_tokens": 1, "input_modalities": ["audio"]}
            ]
        });
        assert_eq!(
            canonical_json(&payload),
            r#"{"capabilities":[{"input_modalities":["text"],"intent":"urn:iicp:intent:llm:chat:v1","max_tokens":4096,"models":["llama-3-8b"]},{"input_modalities":["audio"],"intent":"urn:iicp:intent:audio:transcribe:v1","max_tokens":1,"models":["whisper-1"]}],"endpoint":"https://n.test","region":"eu-central"}"#
        );
        let msg = event_message(
            "cap-evt-1",
            "REGISTER",
            2000,
            1779200000000,
            &payload,
            GENESIS_ROOT,
        );
        assert_eq!(
            hex::encode(msg),
            "ab51e5d131f0d897692a44a5f77086f852c0747bd88bddd43501be58b58ea0f6"
        );
        let sig = "0fe4bfc8eaddb1c0f7e44a067ae33fe77851d9da45f152836f6d315e1116b934cf19b1e23ebbbf290095250e5bcd30302a8df36c13ddd93c2b869ebf8d0d2f04";
        assert!(
            verify_event(KAT_PUBKEY, sig, &msg),
            "capabilities-bearing REGISTER event (array-of-objects) must verify cross-impl"
        );
    }

    #[test]
    fn tampered_event_is_rejected() {
        // Any change to id/type/seq/ts/payload → different message → sig fails.
        let tampered = event_message(
            "474a7713-85c8-4d61-bea5-0ab16f3825a0",
            "DEREGISTER", // was REGISTER
            1080,
            1779195794150,
            &kat_payload(),
            GENESIS_ROOT,
        );
        assert!(!verify_event(KAT_PUBKEY, KAT_SIG, &tampered));
        // garbage inputs are rejected, not panicked
        assert!(!verify_event("zz", KAT_SIG, &tampered));
        assert!(!verify_event(KAT_PUBKEY, "zz", &tampered));
    }

    #[test]
    fn prev_hash_genesis_and_link() {
        // No predecessor (or empty/null sig) → chain seeds from GENESIS_ROOT.
        assert_eq!(prev_hash_from(None), GENESIS_ROOT);
        assert_eq!(prev_hash_from(Some("")), GENESIS_ROOT);
        // Otherwise prev_hash = sha256_hex(ascii(prev_sig)).
        let sig = "ab".repeat(64);
        assert_eq!(
            prev_hash_from(Some(&sig)),
            hex::encode(Sha256::digest(sig.as_bytes()))
        );
    }

    #[test]
    fn tampering_an_event_breaks_the_chain_link(/* #458 / #404 */) {
        // Genesis event #1, then event #2 chained on #1's signature.
        let key = format!("{}{}", "11".repeat(32), KAT_PUBKEY);
        let p1 = json!({"amount": 5.0, "task_id": "t1"});
        let sig1 = sign_event(&key, "evt-1", "CREDIT_AWARD", 1, 1000, &p1, GENESIS_ROOT).unwrap();
        let prev2 = prev_hash_from(Some(&sig1));
        let p2 = json!({"amount": 7.0, "task_id": "t2"});
        let sig2 = sign_event(&key, "evt-2", "CREDIT_AWARD", 2, 2000, &p2, &prev2).unwrap();
        // #2 verifies against the honest chain.
        let msg2 = event_message("evt-2", "CREDIT_AWARD", 2, 2000, &p2, &prev2);
        assert!(verify_event(KAT_PUBKEY, &sig2, &msg2));

        // Now the directory tampers with event #1's payload and re-signs it. Its NEW
        // signature differs → the prev_hash that #2 was signed against no longer matches
        // the recomputed link → #2's signature fails to verify (cascade detected).
        let p1_tampered = json!({"amount": 9999.0, "task_id": "t1"});
        let sig1_tampered = sign_event(
            &key,
            "evt-1",
            "CREDIT_AWARD",
            1,
            1000,
            &p1_tampered,
            GENESIS_ROOT,
        )
        .unwrap();
        assert_ne!(
            sig1, sig1_tampered,
            "tampering must change event #1's signature"
        );
        let prev2_recomputed = prev_hash_from(Some(&sig1_tampered));
        assert_ne!(prev2, prev2_recomputed, "the chain link must change");
        let msg2_recomputed =
            event_message("evt-2", "CREDIT_AWARD", 2, 2000, &p2, &prev2_recomputed);
        assert!(
            !verify_event(KAT_PUBKEY, &sig2, &msg2_recomputed),
            "event #2 must NOT verify against the rewritten chain (tamper-evident)"
        );
    }
}

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use ed25519_compact::{PublicKey, Signature};
use serde_json::{json, Number, Value};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"IICP-CIP-CONSUMER-COSIGNATURE-V1\0";

fn normalize(value: &mut Value) {
    match value {
        Value::Number(number) if number.as_f64() == Some(-0.0) => {
            *number = Number::from(0);
        }
        Value::Array(values) => values.iter_mut().for_each(normalize),
        Value::Object(values) => values.values_mut().for_each(normalize),
        _ => {}
    }
}

fn pre_signature_refusal(v: &Value) -> Option<Value> {
    let s = |key: &str| v[key].as_str().unwrap();
    if s("binding") != "match" {
        let reason = match s("binding") {
            "response_hash_mismatch" => "response_hash_mismatch",
            "cost_mismatch" => "cost_mismatch",
            _ => "receipt_binding_mismatch",
        };
        return Some(json!({"action":"refuse_signing","reason":reason,"trust_weight":"0.0"}));
    }
    if s("consumer_key") == "revoked" {
        return Some(
            json!({"action":"reject","reason":"consumer_key_revoked","trust_weight":"0.0"}),
        );
    }
    if s("consumer_key") == "rotated_outside_validity" {
        return Some(
            json!({"action":"reject","reason":"consumer_key_not_valid_at_completion","trust_weight":"0.0"}),
        );
    }
    if s("time") != "valid" {
        return Some(json!({"action":"reject","reason":"receipt_expired","trust_weight":"0.0"}));
    }
    if s("nonce") != "fresh" {
        return Some(
            json!({"action":"reject","reason":"dispatch_nonce_replayed","trust_weight":"0.0"}),
        );
    }
    None
}

fn signature_refusal(v: &Value) -> Option<Value> {
    let s = |key: &str| v[key].as_str().unwrap();
    if s("provider_signature") != "valid" {
        return Some(
            json!({"action":"reject","reason":"provider_signature_invalid","trust_weight":"0.0"}),
        );
    }
    if s("consumer_signature") != "valid" {
        if s("consumer_signature") == "missing" && s("mode") == "optional" {
            return Some(
                json!({"action":"accept_legacy","reason":"consumer_signature_missing_optional","trust_weight":"0.0"}),
            );
        }
        let reason = if s("consumer_signature") == "missing" {
            "consumer_signature_required"
        } else {
            "consumer_signature_invalid"
        };
        return Some(json!({"action":"reject","reason":reason,"trust_weight":"0.0"}));
    }
    None
}

fn evaluate(v: &Value) -> Value {
    if let Some(refusal) = pre_signature_refusal(v).or_else(|| signature_refusal(v)) {
        return refusal;
    }
    let s = |key: &str| v[key].as_str().unwrap();
    if s("relationship") == "same_node" {
        return json!({"action":"exclude","reason":"self_node","trust_weight":"0.0"});
    }
    if s("relationship") == "same_operator" {
        return json!({"action":"exclude","reason":"self_operator","trust_weight":"0.0"});
    }
    json!({"action":"accept","reason":"cosignature_verified","trust_weight":"1.0"})
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../parity/cip-consumer-cosignature-v1.json")).unwrap()
}

fn verify_canonical_vector(vector: &Value) {
    let mut receipt = vector["receipt"].clone();
    normalize(&mut receipt);
    let canonical = serde_json::to_string(&receipt).unwrap();
    assert_eq!(canonical, vector["canonical_json_utf8"]);
    assert_eq!(
        format!("{:x}", Sha256::digest(canonical.as_bytes())),
        vector["canonical_json_sha256"]
    );
    let digest = Sha256::digest([DOMAIN, canonical.as_bytes()].concat());
    assert_eq!(format!("{digest:x}"), vector["receipt_digest_hex"]);

    for role in ["provider", "consumer"] {
        let public = Base64UrlSafeNoPadding::decode_to_vec(
            vector[format!("{role}_public_key_b64url")]
                .as_str()
                .unwrap(),
            None,
        )
        .unwrap();
        let signature = Base64UrlSafeNoPadding::decode_to_vec(
            vector[format!("{role}_signature_b64url")].as_str().unwrap(),
            None,
        )
        .unwrap();
        PublicKey::from_slice(&public)
            .unwrap()
            .verify(&digest, &Signature::from_slice(&signature).unwrap())
            .unwrap();
    }
}

fn verify_semantic_cases(data: &Value) {
    for case in data["conformance_cases"].as_array().unwrap() {
        assert_eq!(
            evaluate(&case["input"]),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

fn verify_settlement_cases(data: &Value) {
    for case in data["settlement_cases"].as_array().unwrap() {
        let input = &case["input"];
        let actual = if input["reservation"] != "held" {
            json!({"action":"refuse_dispatch","awards":0,"debits":0})
        } else if matches!(
            input["outcome"].as_str(),
            Some("timeout" | "cancelled" | "partial")
        ) {
            json!({"action":"release","awards":0,"debits":0})
        } else {
            json!({"action":"settle_once","awards":1,"debits":1})
        };
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn canonical_digest_dual_signatures_and_semantics_are_portable() {
    let data = fixture();
    verify_canonical_vector(&data["canonical_vector"]);
    verify_semantic_cases(&data);
    verify_settlement_cases(&data);
}

#[test]
fn receipt_privacy_contract_is_data_minimal() {
    let data = fixture();
    let receipt = data["canonical_vector"]["receipt"].as_object().unwrap();
    for forbidden in data["privacy_contract"]["forbidden_fields"]
        .as_array()
        .unwrap()
    {
        assert!(!receipt.contains_key(forbidden.as_str().unwrap()));
    }
    assert_eq!(
        data["privacy_contract"]["self_reported_metrics_have_authority"],
        false
    );
}

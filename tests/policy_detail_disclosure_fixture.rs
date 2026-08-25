#[path = "../src/policy_detail_disclosure.rs"]
mod policy_detail_disclosure;
use policy_detail_disclosure::{evaluate, verify_consumer_token, ALLOWED_DETAIL_FIELDS};
use serde_json::Value;

#[test]
fn policy_detail_disclosure_fixture() {
    let fixtures: Vec<Value> = [
        include_str!("../parity/policy-detail-disclosure-v0.json"),
        include_str!("../parity/policy-detail-disclosure-authority-v0.json"),
    ]
    .into_iter()
    .map(|raw| serde_json::from_str(raw).unwrap())
    .collect();
    for fixture in fixtures {
        assert_eq!(
            fixture["allowed_detail_fields"],
            serde_json::json!(ALLOWED_DETAIL_FIELDS)
        );
        for case in fixture["cases"].as_array().unwrap() {
            let decision = evaluate(&case["context"]);
            assert_eq!(
                decision["status"], case["expected"]["status"],
                "{}",
                case["id"]
            );
            assert_eq!(
                decision["reason"], case["expected"]["reason"],
                "{}",
                case["id"]
            );
            if decision["status"] == 200 {
                let encoded = serde_json::to_string(&decision["body"]).unwrap();
                for forbidden in [
                    "must-not-leak",
                    "private.example",
                    "backend_topology",
                    "natural_person_contact",
                ] {
                    assert!(!encoded.contains(forbidden));
                }
            }
        }
    }
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/policy-detail-disclosure-v0.json")).unwrap();
    let vector = &fixture["crypto_vectors"];
    let verify = |token: &str| {
        verify_consumer_token(
            token,
            vector["public_key_hex"].as_str().unwrap(),
            vector["expected_target_node_id"].as_str().unwrap(),
            vector["expected_intent"].as_str().unwrap(),
            vector["evaluated_at_unix"].as_i64().unwrap(),
        )
    };
    let valid = verify(vector["valid_consumer_token"].as_str().unwrap());
    assert_eq!(valid["status"], "valid");
    assert_eq!(valid["claims"]["sub"], vector["expected_subject"]);
    assert_eq!(
        verify(vector["expired_consumer_token"].as_str().unwrap())["status"],
        "expired"
    );
    assert_eq!(
        verify(vector["tampered_consumer_token"].as_str().unwrap())["status"],
        "invalid"
    );
}

// SPDX-License-Identifier: Apache-2.0

#[test]
fn discovery_evidence_fixture_is_content_free_and_pins_parity_values() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../parity/discovery-evidence-v1.json")).unwrap();
    assert_eq!(fixture["content_free"], true);
    assert_eq!(fixture["invariants"]["gold_min_tasks"], 100);
    assert_eq!(
        fixture["invariants"]["sdk_compatibility_baseline"],
        "0.7.68"
    );
    assert_eq!(fixture["invariants"]["sdk_latest_known_version"], "0.7.100");
    assert_eq!(
        fixture["invariants"]["failure_domain_basis"],
        "not_attested"
    );
    assert_eq!(fixture["invariants"]["identity_material_exposed"], false);
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 5);
    let rendered = include_str!("../parity/discovery-evidence-v1.json");
    for forbidden in [
        "operator_pubkey",
        "endpoint",
        "node_id",
        "credential",
        "payload",
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

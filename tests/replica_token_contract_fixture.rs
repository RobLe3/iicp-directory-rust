// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

#[test]
fn replica_token_fixture_pins_the_php_rust_security_boundary() {
    let fixture: Value = serde_json::from_str(include_str!("../parity/federation-profile-v1.json"))
        .expect("replica token fixture must be valid JSON");

    assert_eq!(fixture["schema"], "iicp.replica-token-contract.v1");
    assert_eq!(fixture["current_scope"], "GET /v1/snapshot");
    assert_eq!(fixture["legacy_scope"], "GET /v1/events");
    assert_eq!(fixture["registration"]["success_status"], 200);
    assert_eq!(fixture["registration"]["rotates_token"], true);
    assert_eq!(fixture["registration"]["plaintext_token_persisted"], false);
    assert_eq!(fixture["snapshot"]["bearer_required"], true);
    assert_eq!(fixture["snapshot"]["missing_status"], 401);
    assert_eq!(fixture["events"]["bearer_required"], false);
    assert_eq!(fixture["events"]["signed"], true);
}

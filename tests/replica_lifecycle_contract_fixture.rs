// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};

#[test]
fn normative_replica_lifecycle_fixture_is_consumed() {
    let raw = include_bytes!("../parity/replica-lifecycle-contract-v1.json");
    assert_eq!(
        hex::encode(Sha256::digest(raw)),
        "9ae2e3536891c3488a2b4d04e543364359a2b9a2c389203ece0eaca1a341b541"
    );
    let fixture: serde_json::Value = serde_json::from_slice(raw).expect("valid lifecycle fixture");
    assert_eq!(fixture["deregister"]["path"], "/v1/replicas/deregister");
    assert_eq!(fixture["deregister"]["event_type"], "REPLICA_DEREGISTERED");
    assert_eq!(
        fixture["persistent_auth_rejections"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(fixture["same_did_reregistration"]["status"], "active");
    assert_eq!(fixture["same_did_reregistration"]["trust_tier"], "low");
    assert_eq!(fixture["privacy"]["contains_credentials"], false);
}

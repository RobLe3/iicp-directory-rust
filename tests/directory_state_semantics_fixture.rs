use serde_json::Value;
use sha2::{Digest, Sha256};

const BYTES: &[u8] = include_bytes!("../parity/directory-state-semantics-v1.json");
const EXPECTED_SHA256: &str = "45c5328611249b5346924e8603803b08db26db0af1fafba15d0a1774454db030";

#[test]
fn canonical_directory_state_fixture_is_pinned_and_rust_parity_is_current() {
    assert_eq!(format!("{:x}", Sha256::digest(BYTES)), EXPECTED_SHA256);
    let fixture: Value = serde_json::from_slice(BYTES).expect("fixture must be valid JSON");
    let review = &fixture["implementation_review"];
    assert_eq!(
        review["parity_status"],
        "implemented_pending_release_evidence"
    );
    assert_eq!(review["confirmed_rust_gaps"], serde_json::json!([]));
    let scenarios = fixture["scenarios"].as_array().expect("scenario array");
    for required in [
        "heartbeat_recovery",
        "confirmed_active_probe_failure",
        "valid_but_offline",
        "external_tunnel_created_not_serving",
    ] {
        assert!(
            scenarios
                .iter()
                .any(|scenario| scenario["name"] == required),
            "missing required scenario {required}"
        );
    }
}

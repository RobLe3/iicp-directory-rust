use serde_json::Value;
use sha2::{Digest, Sha256};

const BYTES: &[u8] = include_bytes!("../parity/directory-state-semantics-v1.json");
const EXPECTED_SHA256: &str = "586c242f2ddee13b81def73743f1dd47658359e8d35c09d99327e8f7dabd38e5";

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
    ] {
        assert!(
            scenarios
                .iter()
                .any(|scenario| scenario["name"] == required),
            "missing required scenario {required}"
        );
    }
}

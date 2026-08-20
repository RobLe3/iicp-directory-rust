use iicp_directory_rs::restricted_domain::{evaluate, Decision, DecisionInput};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const BYTES: &[u8] = include_bytes!("../parity/restricted-trust-domain-v0.json");
const EXPECTED_SHA256: &str = "0b23cc925dd3409d1c39d788e54281e60255b16dcd83fe5e4be84720ddd6039f";

#[derive(Deserialize)]
struct Fixture {
    fixture_version: String,
    status: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    input: DecisionInput,
    expected: Decision,
}

#[test]
fn canonical_restricted_domain_fixture_is_pinned_and_every_decision_matches() {
    assert_eq!(format!("{:x}", Sha256::digest(BYTES)), EXPECTED_SHA256);
    let fixture: Fixture = serde_json::from_slice(BYTES).expect("fixture must be valid JSON");
    assert_eq!(fixture.fixture_version, "0.1.0-draft");
    assert_eq!(fixture.status, "pre-normative");
    assert_eq!(fixture.vectors.len(), 30);

    for vector in fixture.vectors {
        assert_eq!(evaluate(&vector.input), vector.expected, "{}", vector.id);
    }
}

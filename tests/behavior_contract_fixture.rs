// SPDX-License-Identifier: Apache-2.0

#[path = "../src/behavior_contract.rs"]
mod behavior_contract;

use behavior_contract::{EligibilityInput, RankingInput};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const BYTES: &[u8] = include_bytes!("../parity/behavior-contract-v1.json");
const MANIFEST_BYTES: &[u8] = include_bytes!("../parity/contract-v1.10.80.json");
const CURRENT_MANIFEST_BYTES: &[u8] = include_bytes!("../parity/contract-v1.10.81.json");
const EXPECTED_SHA256: &str = "61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f";

#[derive(Deserialize)]
struct Contract {
    schema: String,
    ranking_cases: Vec<RankingCase>,
    eligibility_cases: Vec<EligibilityCase>,
    pricing_cases: Vec<PricingCase>,
    endpoint_cases: Vec<EndpointCase>,
    registration_cases: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct RankingCase {
    expected: f64,
    node: RankingNode,
    requested_model: Option<String>,
    requested_region: Option<String>,
}

#[derive(Deserialize)]
struct RankingNode {
    active_jobs: u32,
    cx_key: bool,
    load: f64,
    max_concurrent: u32,
    models: Vec<String>,
    pricing: Option<f64>,
    region: String,
    reputation: Option<f64>,
    sdk_current: bool,
}

#[derive(Deserialize)]
struct EligibilityCase {
    candidates: Vec<EligibilityNode>,
    expected_ids: Vec<String>,
    min_reputation: f64,
    model: Option<String>,
    qos: Option<String>,
}

#[derive(Deserialize)]
struct EligibilityNode {
    id: String,
    #[serde(default)]
    health_models: Option<Vec<String>>,
    models: Vec<String>,
    #[serde(default)]
    backend_state: Option<String>,
    reputation: f64,
    tasks: u64,
}

#[derive(Deserialize)]
struct PricingCase {
    declared: f64,
    expected: f64,
    models: Vec<String>,
}

#[derive(Deserialize)]
struct EndpointCase {
    blocked: bool,
    ip: String,
}

#[test]
fn rust_policy_primitives_execute_the_php_behavior_fixture() {
    assert_eq!(format!("{:x}", Sha256::digest(BYTES)), EXPECTED_SHA256);
    let contract: Contract = serde_json::from_slice(BYTES).expect("valid behavior contract");
    assert_eq!(contract.schema, "iicp.directory.behavior-contract.v1");

    for case in contract.ranking_cases {
        let input = RankingInput {
            availability: 1.0,
            load: case.node.load,
            active_jobs: case.node.active_jobs,
            max_concurrent: case.node.max_concurrent,
            region: &case.node.region,
            reputation: case.node.reputation,
            models: &case.node.models,
            pricing: case.node.pricing,
            sdk_current: case.node.sdk_current,
            cx_key: case.node.cx_key,
        };
        let actual = behavior_contract::ranking_score(
            &input,
            case.requested_region.as_deref(),
            case.requested_model.as_deref(),
        );
        assert!((actual - case.expected).abs() < 0.000_001);
    }

    for case in contract.eligibility_cases {
        let actual = case
            .candidates
            .iter()
            .filter(|node| {
                behavior_contract::eligible(
                    &EligibilityInput {
                        health_models: node.health_models.as_deref(),
                        models: &node.models,
                        backend_state: node.backend_state.as_deref(),
                        reputation: node.reputation,
                        tasks: node.tasks,
                    },
                    case.model.as_deref(),
                    case.qos.as_deref(),
                    case.min_reputation,
                )
            })
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual, case.expected_ids);
    }
    for case in contract.pricing_cases {
        let actual = behavior_contract::pricing_multiplier(&case.models, case.declared);
        assert!((actual - case.expected).abs() < 0.000_001);
    }
    for case in contract.endpoint_cases {
        assert_eq!(behavior_contract::blocked_ip(&case.ip), case.blocked);
    }

    // Transactional registration behavior is exercised by the disposable
    // dual-MySQL gate; keep the two shared case names present in this fixture.
    assert_eq!(contract.registration_cases.len(), 2);
}

#[test]
fn v1_10_80_manifest_pins_both_shared_fixtures() {
    let manifest: serde_json::Value =
        serde_json::from_slice(MANIFEST_BYTES).expect("valid parity manifest");
    assert_eq!(manifest["contract_version"], "v1.10.80");
    assert_eq!(
        manifest["fixtures"]["behavior-contract-v1.json"],
        EXPECTED_SHA256
    );
    assert_eq!(
        manifest["fixtures"]["http-contract-v1.json"],
        "62fad592a33305a754353c43f6476d257f01ccf6e3cfdbf391d03717ce4796b5"
    );
}

#[test]
fn v1_10_81_manifest_preserves_wire_and_behavior_contracts() {
    let manifest: serde_json::Value =
        serde_json::from_slice(CURRENT_MANIFEST_BYTES).expect("valid current parity manifest");
    assert_eq!(manifest["contract_version"], "v1.10.81");
    assert_eq!(manifest["authority"]["runtime_version"], "v1.10.81.1");
    assert_eq!(
        manifest["fixtures"]["behavior-contract-v1.json"],
        EXPECTED_SHA256
    );
    assert_eq!(
        manifest["fixtures"]["http-contract-v1.json"],
        "62fad592a33305a754353c43f6476d257f01ccf6e3cfdbf391d03717ce4796b5"
    );
}

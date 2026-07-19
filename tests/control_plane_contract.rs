// SPDX-License-Identifier: Apache-2.0
//! Executable consumption of the seed/Rust control-plane parity contract.
//!
//! This complements behavior tests: adding a seed-required route or capability
//! marker now fails Rust CI until the dedicated implementation acknowledges it.

use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    contract_version: String,
    rust: RustContract,
}

#[derive(Deserialize)]
struct RustContract {
    required_route_fragments: Vec<String>,
    required_capability_markers: Vec<String>,
}

#[test]
fn rust_source_consumes_current_control_plane_contract() {
    let contract: Contract = serde_json::from_str(include_str!("../parity/contract-v1.10.75.json"))
        .expect("valid control-plane contract");
    assert_eq!(contract.contract_version, "v1.10.75");
    let source = [
        include_str!("../src/main.rs"),
        include_str!("../src/repo.rs"),
        include_str!("../src/db.rs"),
        include_str!("../src/policy_manifest.rs"),
        include_str!("../src/background.rs"),
    ]
    .join("\n");
    for route in contract.rust.required_route_fragments {
        assert!(source.contains(&route), "missing required route {route}");
    }
    for marker in contract.rust.required_capability_markers {
        assert!(
            source.contains(&marker),
            "missing capability marker {marker}"
        );
    }
}

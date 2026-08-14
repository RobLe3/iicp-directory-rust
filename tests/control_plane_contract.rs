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
    let contract: Contract = serde_json::from_str(include_str!("../parity/contract-v1.10.76.json"))
        .expect("valid control-plane contract");
    assert_eq!(contract.contract_version, "v1.10.76");
    let source = [
        include_str!("../src/main.rs"),
        include_str!("../src/discovery.rs"),
        include_str!("../src/node_lifecycle.rs"),
        include_str!("../src/router.rs"),
        include_str!("../src/observability.rs"),
        include_str!("../src/repo.rs"),
        include_str!("../src/db.rs"),
        include_str!("../src/policy_manifest.rs"),
        include_str!("../src/background.rs"),
        include_str!("../parity/dsr-related-records-v1.json"),
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
    let dsr: serde_json::Value =
        serde_json::from_str(include_str!("../parity/dsr-related-records-v1.json")).unwrap();
    assert_eq!(
        dsr["schema"],
        "iicp.directory.dsr-related-records-parity.v1"
    );
    assert_eq!(dsr["record_limit_per_family"], 500);
    assert_eq!(dsr["record_families"].as_object().unwrap().len(), 11);

    let expanded: serde_json::Value =
        serde_json::from_str(include_str!("../parity/dsr-related-records-v2.json")).unwrap();
    assert_eq!(
        expanded["schema"],
        "iicp.directory.dsr-related-records-parity.v2"
    );
    let capability_fields = expanded["record_families"]["capabilities"]
        .as_array()
        .expect("capability field contract");
    for required in [
        "version",
        "variant_id",
        "output_modalities",
        "features",
        "execution_capabilities",
        "limits",
        "supported_profiles",
        "claim_provenance",
        "extensions",
    ] {
        assert!(
            capability_fields.iter().any(|field| field == required),
            "missing effective-capability DSR field {required}"
        );
    }
}

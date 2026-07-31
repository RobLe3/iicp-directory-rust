// SPDX-License-Identifier: Apache-2.0
//! Consumption gate for the PHP authority's normalized HTTP contract.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const FIXTURE_BYTES: &[u8] = include_bytes!("../parity/http-contract-v2.json");
const EXPECTED_SHA256: &str = "bc6633af2d64b6c9a74155b06259a253c1e982edce9f70f0abfd6187ae1dfb14";

#[derive(Debug, Deserialize)]
struct Contract {
    schema: String,
    authority: Authority,
    canonical_prefix: String,
    routes: Vec<Route>,
}

#[derive(Debug, Deserialize)]
struct Authority {
    runtime_version: String,
    php_commit: String,
}

#[derive(Debug, Deserialize)]
struct Route {
    method: String,
    path: String,
    auth: String,
    success_status: Option<u16>,
}

#[test]
fn php_http_contract_is_the_reviewed_immutable_fixture() {
    assert_eq!(
        format!("{:x}", Sha256::digest(FIXTURE_BYTES)),
        EXPECTED_SHA256
    );
    let contract: Contract = serde_json::from_slice(FIXTURE_BYTES).expect("valid HTTP contract");
    assert_eq!(contract.schema, "iicp.directory.http-contract.v2");
    assert_eq!(contract.authority.runtime_version, "v1.10.80.1");
    assert_eq!(contract.authority.php_commit, "08fa5f9");
    assert_eq!(contract.canonical_prefix, "/api/v1");
    assert_eq!(contract.routes.len(), 44);
}

#[test]
fn every_authoritative_route_is_acknowledged_by_the_rust_router() {
    let contract: Contract = serde_json::from_slice(FIXTURE_BYTES).expect("valid HTTP contract");
    let source = include_str!("../src/main.rs");
    let allowed_auth = BTreeSet::from([
        "public",
        "node_token",
        "proxy_token",
        "probe_token",
        "replica_token",
        "signed_operator_request",
    ]);
    let allowed_success = BTreeSet::from([200_u16, 201_u16]);

    for route in contract.routes {
        assert!(
            allowed_auth.contains(route.auth.as_str()),
            "unreviewed auth class for {} {}: {}",
            route.method,
            route.path,
            route.auth
        );
        if let Some(status) = route.success_status {
            assert!(
                allowed_success.contains(&status),
                "unreviewed success status for {} {}: {status}",
                route.method,
                route.path
            );
        }

        let rust_path = route
            .path
            .replace("{board_id}", ":board_id")
            .replace("{tier}", ":tier")
            .replace("{prefix}", ":id")
            .replace("{id}", ":id");
        let canonical = format!("\"/api/v1{rust_path}\"");
        let offset = source
            .find(&canonical)
            .unwrap_or_else(|| panic!("Rust router is missing {} {}", route.method, route.path));
        let declaration = &source[offset..source.len().min(offset + 180)];
        let method_fragment = match route.method.as_str() {
            "GET" => "get(",
            "POST" => "post(",
            "DELETE" => "delete(",
            other => panic!("unreviewed HTTP method {other}"),
        };
        assert!(
            declaration.contains(method_fragment),
            "Rust router has no {} handler for {}",
            route.method,
            route.path
        );
    }
}

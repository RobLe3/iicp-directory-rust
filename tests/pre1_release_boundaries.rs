use semver::Version;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

const CURRENT: &str = include_str!("../compatibility/v0.1.15.json");
const PREVIOUS: &str = include_str!("../compatibility/v0.1.14.json");
const CARGO_TOML: &str = include_str!("../Cargo.toml");
const UPDATER: &str = include_str!("../scripts/directory_self_update.sh");

fn manifest(raw: &str) -> Value {
    serde_json::from_str(raw).expect("valid compatibility manifest")
}

#[test]
fn offline_candidate_contract_pins_every_release_input() {
    let current = manifest(CURRENT);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (name, contract) in current["contracts"].as_object().expect("contract map") {
        let relative = contract["path"].as_str().expect("contract path");
        let expected = contract["sha256"].as_str().expect("contract digest");
        let path = root.join(relative);
        assert!(path.is_file(), "missing release input {name}");
        let observed = format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()));
        assert_eq!(observed, expected, "release input drift: {name}");
    }
}

#[test]
fn package_version_self_report_matches_candidate_contract() {
    let current = manifest(CURRENT);
    assert_eq!(current["implementation"]["flavor"], "rust");
    assert_eq!(current["implementation"]["status"], "operator_preview");
    assert_eq!(
        current["implementation"]["version"],
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn minimum_rust_version_is_declared_and_candidate_remains_pre1() {
    let declared = CARGO_TOML
        .lines()
        .find(|line| line.trim_start().starts_with("rust-version = "))
        .expect("rust-version declaration");
    assert_eq!(declared.trim(), "rust-version = \"1.88\"");
    let version = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    assert_eq!(version.major, 0);
}

#[test]
fn last_supported_generation_is_pinned_for_bounded_rollback() {
    let current = manifest(CURRENT);
    let previous = manifest(PREVIOUS);
    assert_eq!(previous["implementation"]["version"], "0.1.14");
    assert_eq!(current["implementation"]["version"], "0.1.15");
    assert_eq!(previous["contracts"], current["contracts"]);
    assert!(UPDATER.contains("candidate verification failed; rolling back"));
    assert!(UPDATER.contains("ln -sfn \"$previous\" \"$STABLE_BIN\""));
    assert!(UPDATER.contains("systemctl --user restart \"$SERVICE\""));
}

#[test]
fn preview_contract_never_authorizes_dual_genesis() {
    for value in [manifest(PREVIOUS), manifest(CURRENT)] {
        assert_eq!(value["production_authority"], false);
        assert_eq!(value["genesis_cutover_authorized"], false);
        assert_eq!(value["php_deprecation_authorized"], false);
    }
}

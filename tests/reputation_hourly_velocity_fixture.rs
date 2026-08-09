// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

fn numeric(fixture: &Value, path: &[&str]) -> f64 {
    let mut value = fixture;
    for key in path {
        value = &value[*key];
    }
    value.as_f64().expect("fixture numeric field")
}

#[test]
fn shared_rt01b_hourly_velocity_fixture_is_content_free_and_well_formed() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/reputation-hourly-velocity-v0.json"))
            .expect("shared RT-01b fixture must be valid JSON");

    assert_eq!(fixture["fixture_version"], "0.1.0-draft");
    assert_eq!(fixture["status"], "pre-normative");
    assert_eq!(
        fixture["scope"]["implementation_flavors"],
        serde_json::json!(["php", "rust"])
    );
    assert_eq!(fixture["scope"]["database_mode"], "disposable_mysql");
    assert!((numeric(&fixture, &["inputs", "maximum_hourly_positive_gain"]) - 0.20).abs() < 0.0001);
    assert_eq!(fixture["inputs"]["workers"], 4);
    assert_eq!(fixture["inputs"]["tasks_success_per_worker"], 10);
    assert!((numeric(&fixture, &["expected", "concurrent_score"]) - 0.70).abs() < 0.0001);
    assert!((numeric(&fixture, &["expected", "concurrent_hourly_gain"]) - 0.20).abs() < 0.0001);
    assert_eq!(fixture["expected"]["concurrent_tasks_total"], 40);
    assert_eq!(fixture["expected"]["same_window_age_seconds"], 3599);
    assert_eq!(fixture["expected"]["next_window_age_seconds"], 3600);
    assert!(
        (numeric(
            &fixture,
            &["expected", "final_score_after_reload_and_negative"]
        ) - 0.85)
            .abs()
            < 0.0001
    );

    let rendered =
        include_str!("../parity/reputation-hourly-velocity-v0.json").to_ascii_lowercase();
    for forbidden in ["bearer ", "api_key", "private_key", "client_secret"] {
        assert!(
            !rendered.contains(forbidden),
            "fixture contains forbidden secret material: {forbidden}"
        );
    }
}

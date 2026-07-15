use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

fn attribution(v: &Value) -> Value {
    let querying = v["querying_node_id"].as_str().unwrap_or("");
    if querying.is_empty() {
        return json!({"action":"award","attribution":"legacy_unattributed","trust_weight":0.0});
    }
    if querying == v["serving_node_id"] {
        return json!({"action":"exclude","attribution":"self_node","trust_weight":0.0});
    }
    if v["querying_exists"] != true {
        return json!({"action":"reject","attribution":"unknown_querying_node","trust_weight":0.0,"error":"IICP-E027"});
    }
    let serving = v["serving_operator"].as_str();
    let consumer = v["querying_operator"].as_str();
    if serving.is_some() && serving == consumer {
        return json!({"action":"exclude","attribution":"self_operator","trust_weight":0.0});
    }
    if serving.is_some() && consumer.is_some() {
        return json!({"action":"award","attribution":"attributed_cross_operator","trust_weight":1.0});
    }
    json!({"action":"award","attribution":"attributed_cross_node_unverified_operator","trust_weight":0.5})
}

fn receipt_time(v: &Value) -> Value {
    let parse = |key: &str| {
        v[key]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&Utc))
    };
    let (Some(completed), Some(observed), Some(expires)) = (
        parse("completed_at"),
        parse("observed_at"),
        parse("expires_at"),
    ) else {
        return json!({"action":"reject","error":"IICP-E027"});
    };
    if expires > completed + Duration::seconds(300) || observed > expires {
        json!({"action":"reject","error":"IICP-E027"})
    } else {
        json!({"action":"accept"})
    }
}

#[test]
fn economic_fixture_is_portable() {
    let data: Value =
        serde_json::from_str(include_str!("../parity/cip-economic-attribution-v0.json")).unwrap();
    for c in data["attribution_cases"].as_array().unwrap() {
        assert_eq!(attribution(&c["input"]), c["expected"], "{}", c["name"]);
    }
    for c in data["heartbeat_cases"].as_array().unwrap() {
        let success = c["input"]["tasks_success"].as_i64().unwrap().clamp(0, 300);
        let failed = c["input"]["tasks_failed"].as_i64().unwrap().max(0);
        assert_eq!(
            json!({"counted_success":success,"completed_increment":success,"lifetime_jobs_increment":success+failed}),
            c["expected"],
            "{}",
            c["name"]
        );
    }
    for c in data["receipt_time_cases"].as_array().unwrap() {
        assert_eq!(receipt_time(&c["input"]), c["expected"], "{}", c["name"]);
    }
    for c in data["selection_tie_cases"].as_array().unwrap() {
        let mut eligible: Vec<&Value> = c["input"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["eligible"] == true)
            .collect();
        eligible.sort_by(|a, b| {
            b["score"]
                .as_f64()
                .unwrap()
                .total_cmp(&a["score"].as_f64().unwrap())
                .then_with(|| {
                    a["node_id"]
                        .as_str()
                        .unwrap()
                        .cmp(b["node_id"].as_str().unwrap())
                })
        });
        assert_eq!(
            json!({"selected_node_id":eligible.first().and_then(|n| n["node_id"].as_str())}),
            c["expected"],
            "{}",
            c["name"]
        );
    }
}

use serde_json::{json, Map, Value};

fn validate_envelope(value: &Value) -> Result<(i64, Option<i64>), Value> {
    let replicas = value["replicas"].as_i64().unwrap_or(-1);
    if !(1..=10).contains(&replicas) {
        return Err(json!({"envelope":"reject","execution":"reject","error":"IICP-E028"}));
    }
    let quorum = value.get("quorum").and_then(Value::as_i64);
    if value.get("quorum").is_some_and(|v| !v.is_null())
        && quorum.is_none_or(|q| q < 1 || q > replicas)
    {
        return Err(json!({"envelope":"reject","execution":"reject","error":"IICP-E028"}));
    }
    Ok((replicas, quorum))
}

fn hard_gate(value: &Value) -> Option<Value> {
    let mut out = Map::from_iter([("envelope".into(), json!("accept"))]);
    if value["sensitivity"] == "high" && value["send_sensitive_prompts"] != true {
        out.extend([
            ("execution".into(), json!("local")),
            ("remote_eligible".into(), json!(false)),
        ]);
        return Some(Value::Object(out));
    }
    let intent = value["intent"].as_str().unwrap_or("");
    if intent.starts_with("urn:iicp:intent:mcp:") || intent.starts_with("urn:iicp:intent:tool:") {
        out.extend([
            ("execution".into(), json!("reject")),
            ("remote_eligible".into(), json!(false)),
        ]);
        return Some(Value::Object(out));
    }
    None
}

fn evaluate_mode(value: &Value, replicas: i64, quorum: Option<i64>) -> Value {
    let mut out = Map::from_iter([("envelope".into(), json!("accept"))]);
    let operator_max = value["operator_max_replicas"]
        .as_i64()
        .unwrap_or(10)
        .clamp(1, 10);
    match value["policy"].as_str().unwrap_or("") {
        "" if replicas == 1 => out.extend([
            ("execution".into(), json!("accept")),
            ("quorum".into(), Value::Null),
        ]),
        "" | "best_of_n" if replicas < 2 || replicas > operator_max => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E028")),
        ]),
        "best_of_n" => out.extend([
            ("execution".into(), json!("accept")),
            ("quorum".into(), Value::Null),
        ]),
        "majority_vote" if replicas < 3 || replicas % 2 == 0 => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E025")),
        ]),
        "majority_vote" if replicas > operator_max => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E028")),
        ]),
        "majority_vote" => out.extend([
            ("execution".into(), json!("accept")),
            ("quorum".into(), json!(quorum.unwrap_or(replicas / 2 + 1))),
        ]),
        "map_reduce"
            if !value["implemented_modes"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "map_reduce")) =>
        {
            out.extend([
                ("execution".into(), json!("unsupported")),
                ("advertise".into(), json!(false)),
            ])
        }
        _ => out.extend([
            ("execution".into(), json!("reject")),
            ("error".into(), json!("IICP-E028")),
        ]),
    }
    Value::Object(out)
}

fn evaluate(value: &Value) -> Value {
    let (replicas, quorum) = match validate_envelope(value) {
        Ok(envelope) => envelope,
        Err(error) => return error,
    };
    if let Some(result) = hard_gate(value) {
        return result;
    }
    evaluate_mode(value, replicas, quorum)
}

#[test]
fn canonical_cip_fixture_matches_directory_contract() {
    let fixture: Value =
        serde_json::from_str(include_str!("../parity/cip-conformance-v0.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        assert_eq!(
            evaluate(&case["input"]),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

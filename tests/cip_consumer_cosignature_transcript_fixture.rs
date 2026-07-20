use serde_json::Value;
use std::collections::HashSet;

#[test]
fn consumer_cosignature_transcript_is_content_free_and_fail_closed() {
    let data: Value = serde_json::from_str(include_str!(
        "../parity/cip-consumer-cosignature-transcript-v1.json"
    ))
    .unwrap();
    let messages: Vec<&Value> = data["transcript"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| &step["message"])
        .collect();
    assert_eq!(
        messages
            .iter()
            .map(|message| message["type"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["receipt_offer", "receipt_acceptance", "settlement_request"]
    );
    assert_eq!(
        messages
            .iter()
            .map(|message| message["receipt_digest_hex"].as_str().unwrap())
            .collect::<HashSet<_>>()
            .len(),
        1
    );
    assert_eq!(data["privacy_contract"]["content_free"], true);
    assert!(data["transition_modes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|mode| mode["strict_enforcement_authorized"] == false));
}

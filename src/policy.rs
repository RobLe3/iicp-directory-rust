// SPDX-License-Identifier: Apache-2.0
//! Public-mesh intent-risk policy guard.
//!
//! The directory applies this to declared capabilities at registration and to
//! discovery queries before they reach the repository. It intentionally classifies
//! *intent identifiers*, never task prompts or response content. The taxonomy is
//! mirrored from the seed directory's shared contract so implementations cannot
//! silently diverge on the public-mesh refusal boundary.

use serde::Deserialize;
use std::sync::OnceLock;

/// Stable public error code shared with the Laravel seed implementation.
pub const REFUSAL_CODE: &str = "IICP-POLICY-001";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentClassification {
    pub category: String,
    pub rule_id: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Taxonomy {
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    category: String,
    rule_id: String,
    label: String,
    fragments: Vec<String>,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            serde_json::from_str::<Taxonomy>(include_str!("../parity/intent-risk-taxonomy.json"))
                .expect("mirrored intent risk taxonomy must be valid JSON")
                .rules
        })
        .as_slice()
}

/// Public policy boundary shared by discovery and registration handlers.
pub struct IntentPolicyGuard;

impl IntentPolicyGuard {
    /// Classify an IICP intent using the canonical, mirrored taxonomy.
    pub fn classify(intent: &str) -> IntentClassification {
        let normalized = intent.trim().to_ascii_lowercase();
        for rule in rules() {
            if rule
                .fragments
                .iter()
                .any(|fragment| normalized.contains(fragment))
            {
                return IntentClassification {
                    category: rule.category.clone(),
                    rule_id: Some(rule.rule_id.clone()),
                    label: Some(rule.label.clone()),
                };
            }
        }
        IntentClassification {
            category: "minimal_or_general".into(),
            rule_id: None,
            label: None,
        }
    }

    /// Returns a policy classification only where public-mesh discovery and
    /// registration must fail closed. Transparency-risk and unknown/general intents
    /// remain routable; their downstream disclosure/handling lives in their profiles.
    pub fn public_mesh_refusal(intent: &str) -> Option<IntentClassification> {
        let classification = Self::classify(intent);
        matches!(classification.category.as_str(), "prohibited" | "high_risk")
            .then_some(classification)
    }
}

/// Stable, payload-free public error text. Do not include the caller's prompt,
/// task payload, endpoint, identity, or the submitted intent itself.
pub fn refusal_message(classification: &IntentClassification) -> String {
    let label = classification
        .label
        .as_deref()
        .unwrap_or("restricted intent");
    let rule_id = classification.rule_id.as_deref().unwrap_or("policy");
    format!(
        "Intent refused by IICP directory policy before discovery/routing: {label} ({rule_id}, {}). Use a lawful, documented, human-reviewed compliance path outside the public mesh for restricted/high-risk workflows.",
        classification.category
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_taxonomy_is_present_and_has_expected_rules() {
        let taxonomy: Taxonomy =
            serde_json::from_str(include_str!("../parity/intent-risk-taxonomy.json"))
                .expect("taxonomy fixture must parse");
        assert_eq!(taxonomy.rules.len(), 14);
        assert!(taxonomy
            .rules
            .iter()
            .any(|rule| rule.rule_id == "eu-ai-act-social-scoring"));
        assert!(taxonomy
            .rules
            .iter()
            .any(|rule| rule.rule_id == "eu-ai-act-ai-interaction"));
    }

    #[test]
    fn prohibited_intents_are_refused() {
        let c = IntentPolicyGuard::public_mesh_refusal("urn:iicp:intent:social-scoring:rank:v1")
            .unwrap();
        assert_eq!(c.category, "prohibited");
        assert_eq!(c.rule_id.as_deref(), Some("eu-ai-act-social-scoring"));
        let message = refusal_message(&c);
        assert!(message.contains("social scoring"));
        assert!(!message.contains("urn:iicp:"));
    }

    #[test]
    fn high_risk_intents_are_refused() {
        let c =
            IntentPolicyGuard::public_mesh_refusal("urn:iicp:intent:medical:diagnosis:v1").unwrap();
        assert_eq!(c.category, "high_risk");
        assert_eq!(
            c.rule_id.as_deref(),
            Some("eu-ai-act-healthcare-critical-infrastructure")
        );
    }

    #[test]
    fn transparency_general_and_custom_intents_remain_routable() {
        assert_eq!(
            IntentPolicyGuard::classify("urn:iicp:intent:ai-assistant:chat:v1").category,
            "transparency_risk"
        );
        assert!(
            IntentPolicyGuard::public_mesh_refusal("urn:iicp:intent:ai-assistant:chat:v1")
                .is_none()
        );
        assert!(IntentPolicyGuard::public_mesh_refusal("urn:iicp:intent:llm:chat:v1").is_none());
        assert!(
            IntentPolicyGuard::public_mesh_refusal("urn:iicp:intent:acme:custom-task:v1").is_none()
        );
    }
}

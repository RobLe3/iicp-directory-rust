// SPDX-License-Identifier: Apache-2.0
//! Binding-neutral matching for `urn:iicp:profile:effective-capability:v1`.

use crate::types::EffectiveCapability;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const FIXTURE_SHA256: &str =
    "e6e3c32aa7c4cf814e639d3a97cd1c1cb49ac020ed6ebe7e1e16bc2314e14761";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Requirement {
    pub class: String,
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LimitRequirement {
    pub id: String,
    pub operator: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Requirements {
    pub intent: String,
    #[serde(default)]
    pub requires: Vec<Requirement>,
    #[serde(default)]
    pub prefers: Vec<Requirement>,
    #[serde(default)]
    pub limits: Vec<LimitRequirement>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MatchResult {
    pub eligible: bool,
    pub variant_ids: Vec<Option<String>>,
    pub preference_unavailable: bool,
    pub refusal: Option<&'static str>,
}

fn refusal(code: &'static str) -> MatchResult {
    MatchResult {
        eligible: false,
        variant_ids: vec![],
        preference_unavailable: false,
        refusal: Some(code),
    }
}

fn known(vocabulary: &BTreeMap<String, Vec<String>>, requirement: &Requirement) -> bool {
    requirement.class != "extension"
        && vocabulary
            .get(&requirement.class)
            .is_some_and(|values| values.contains(&requirement.id))
}

fn values<'a>(candidate: &'a EffectiveCapability, class: &str) -> Option<&'a [String]> {
    match class {
        "input_modality" => Some(&candidate.input_modalities),
        "output_modality" => Some(&candidate.output_modalities),
        "feature" => Some(&candidate.features),
        "execution_capability" => Some(&candidate.execution_capabilities),
        "profile" => Some(&candidate.supported_profiles),
        _ => None,
    }
}

fn has_every(candidate: &EffectiveCapability, requirements: &[Requirement]) -> bool {
    requirements.iter().all(|requirement| {
        values(candidate, &requirement.class).is_some_and(|items| items.contains(&requirement.id))
    })
}

fn fresh(candidate: &EffectiveCapability, evaluated_at: DateTime<Utc>) -> bool {
    candidate
        .claim_provenance
        .as_ref()
        .and_then(|claim| claim.valid_until.as_deref())
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_none_or(|until| until >= evaluated_at)
}

fn limits_match(candidate: &EffectiveCapability, requirements: &[LimitRequirement]) -> bool {
    requirements.iter().all(|required| {
        candidate.limits.get(&required.id).is_some_and(|actual| {
            actual.unit == required.unit
                && match required.operator.as_str() {
                    "gte" => actual.value >= required.value,
                    "lte" => actual.value <= required.value,
                    "eq" => actual.value == required.value,
                    _ => false,
                }
        })
    })
}

pub(crate) fn match_capabilities(
    capabilities: &[EffectiveCapability],
    request: &Requirements,
    vocabulary: &BTreeMap<String, Vec<String>>,
    evaluated_at: DateTime<Utc>,
    policy_denials: &BTreeSet<Requirement>,
) -> MatchResult {
    for requirement in &request.requires {
        if !known(vocabulary, requirement) {
            return refusal("required_capability_unknown");
        }
        if policy_denials.contains(requirement) {
            return refusal("capability_policy_denied");
        }
    }

    let candidates: Vec<_> = capabilities
        .iter()
        .filter(|candidate| {
            candidate.intent == request.intent && has_every(candidate, &request.requires)
        })
        .collect();
    if candidates.is_empty() {
        return refusal("required_capability_unsupported");
    }
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| fresh(candidate, evaluated_at))
        .collect();
    if candidates.is_empty() {
        return refusal("required_capability_stale");
    }
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| limits_match(candidate, &request.limits))
        .collect();
    if candidates.is_empty() {
        return refusal("capability_limit_unsatisfied");
    }

    MatchResult {
        eligible: true,
        variant_ids: candidates
            .iter()
            .map(|candidate| candidate.variant_id.clone())
            .collect(),
        preference_unavailable: request
            .prefers
            .iter()
            .any(|preference| !known(vocabulary, preference)),
        refusal: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    #[derive(Deserialize)]
    struct Fixture {
        profile_id: String,
        evaluation_time: String,
        vocabulary: BTreeMap<String, Vec<String>>,
        advertisement: Advertisement,
        matching_scenarios: Vec<Scenario>,
    }

    #[derive(Deserialize)]
    struct Advertisement {
        capabilities: Vec<EffectiveCapability>,
    }

    #[derive(Deserialize)]
    struct Scenario {
        name: String,
        #[serde(default)]
        evaluation_time: Option<String>,
        request: Requirements,
        #[serde(default)]
        policy_denials: BTreeSet<Requirement>,
        expected: Value,
    }

    #[test]
    fn shared_fixture_digest_and_profile_are_exactly_pinned() {
        let raw = include_bytes!("../parity/effective-capability-v1/fixture.json");
        assert_eq!(hex::encode(Sha256::digest(raw)), FIXTURE_SHA256);
        let fixture: Fixture = serde_json::from_slice(raw).unwrap();
        assert_eq!(
            fixture.profile_id,
            "urn:iicp:profile:effective-capability:v1"
        );
    }

    #[test]
    fn shared_matching_scenarios_pass_without_cross_variant_union() {
        let fixture: Fixture = serde_json::from_slice(include_bytes!(
            "../parity/effective-capability-v1/fixture.json"
        ))
        .unwrap();
        for scenario in fixture.matching_scenarios {
            let at = scenario
                .evaluation_time
                .as_deref()
                .unwrap_or(&fixture.evaluation_time);
            let actual = match_capabilities(
                &fixture.advertisement.capabilities,
                &scenario.request,
                &fixture.vocabulary,
                DateTime::parse_from_rfc3339(at)
                    .unwrap()
                    .with_timezone(&Utc),
                &scenario.policy_denials,
            );
            assert_eq!(
                actual.eligible,
                scenario.expected["eligible"].as_bool().unwrap(),
                "{}",
                scenario.name
            );
            if actual.eligible {
                let expected: Vec<Option<String>> =
                    serde_json::from_value(scenario.expected["variant_ids"].clone()).unwrap();
                assert_eq!(actual.variant_ids, expected, "{}", scenario.name);
            } else {
                assert_eq!(
                    actual.refusal,
                    scenario.expected["refusal"]["code"].as_str(),
                    "{}",
                    scenario.name
                );
            }
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Pure discovery admission and ranking policy.

use crate::behavior_contract::{self, EligibilityInput, RankingInput};
use crate::types::Node;

pub(crate) struct SelectionRequest<'a> {
    pub model: Option<&'a str>,
    pub qos: Option<&'a str>,
    pub region: Option<&'a str>,
    pub min_reputation: f64,
    pub limit: usize,
    pub cip_capable: bool,
}

pub(crate) fn validate_qos(qos: Option<&str>) -> Result<(), &'static str> {
    if qos
        .is_some_and(|value| !matches!(value, "realtime" | "interactive" | "batch" | "best-effort"))
    {
        return Err("qos must be realtime, interactive, batch, or best-effort");
    }
    Ok(())
}

pub(crate) fn validate_min_reputation(value: Option<f64>) -> Result<(), &'static str> {
    if value.is_some_and(|score| !(0.0..=1.0).contains(&score)) {
        return Err("min_reputation must be in [0, 1]");
    }
    Ok(())
}

pub(crate) fn select_and_rank(
    nodes: Vec<Node>,
    request: &SelectionRequest<'_>,
    sdk_current: impl Fn(Option<&str>) -> bool,
) -> Vec<Node> {
    let mut selected: Vec<Node> = nodes
        .into_iter()
        .filter(|node| {
            !request.cip_capable || node.cip_conformance_level.as_deref() == Some("CIP-Provider")
        })
        .filter(|node| {
            node.health_models
                .as_ref()
                .is_none_or(|models| !models.is_empty())
        })
        .filter(|node| {
            behavior_contract::eligible(
                &EligibilityInput {
                    health_models: node.health_models.as_deref(),
                    models: &node.models,
                    backend_state: node.routing_policy.backend_state.as_deref(),
                    reputation: node.reputation_score,
                    tasks: node.completed_tasks_count,
                },
                request.model,
                request.qos,
                request.min_reputation,
            )
        })
        .map(|mut node| {
            node.score = behavior_contract::ranking_score(
                &RankingInput {
                    availability: node.routing_policy.availability_score,
                    load: node.load,
                    active_jobs: node.active_jobs,
                    max_concurrent: node.max_concurrent,
                    region: &node.region,
                    reputation: Some(node.reputation_score),
                    models: node.health_models.as_deref().unwrap_or(&node.models),
                    pricing: node.routing_policy.pricing_credits_per_1000,
                    sdk_current: sdk_current(node.effective_sdk_compatibility_version()),
                    cx_key: node.public_key.is_some(),
                },
                request.region,
                request.model,
            );
            node
        })
        .collect();
    selected.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    selected.truncate(request.limit);
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_validation_is_closed_over_the_shared_vocabulary() {
        assert!(validate_qos(Some("realtime")).is_ok());
        assert!(validate_qos(Some("invented")).is_err());
        assert!(validate_min_reputation(Some(0.0)).is_ok());
        assert!(validate_min_reputation(Some(1.0)).is_ok());
        assert!(validate_min_reputation(Some(-0.01)).is_err());
        assert!(validate_min_reputation(Some(1.01)).is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Pure registration validation and preparation policy.

use std::collections::HashSet;

use crate::behavior_contract;

pub(crate) const BACKENDS: &[&str] = &[
    "ollama",
    "lmstudio",
    "vllm",
    "llamacpp",
    "meshllm",
    "anthropic",
    "custom",
];
pub(crate) const PRICING_MODELS: &[&str] = &["per_token", "per_request", "flat"];

pub(crate) fn resolve_node_id(requested: Option<&str>) -> Result<String, &'static str> {
    let Some(custom_id) = requested.filter(|value| !value.is_empty()) else {
        return Ok(uuid::Uuid::new_v4().to_string());
    };
    let valid = custom_id.len() <= 36
        && custom_id.as_bytes()[0].is_ascii_alphanumeric()
        && custom_id.chars().all(|character| {
            matches!(character, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | ':' | '-')
        });
    valid
        .then(|| custom_id.to_string())
        .ok_or("node_id must start with [a-zA-Z0-9] and contain only [a-zA-Z0-9._:-], max 36 chars")
}

pub(crate) fn valid_hhmm(value: &str) -> bool {
    let mut parts = value.split(':');
    matches!(
        (
            parts.next().and_then(|part| part.parse::<u8>().ok()),
            parts.next().and_then(|part| part.parse::<u8>().ok()),
            parts.next()
        ),
        (Some(0..=23), Some(0..=59), None)
    )
}

pub(crate) fn valid_availability<'a>(
    windows: impl IntoIterator<Item = (&'a str, &'a str, f64)>,
) -> bool {
    windows.into_iter().all(|(start, end, share)| {
        valid_hhmm(start) && valid_hhmm(end) && (0.0..=1.0).contains(&share)
    })
}

pub(crate) fn valid_pricing(multiplier: f64, model: &str) -> bool {
    (0.0..=1000.0).contains(&multiplier) && PRICING_MODELS.contains(&model)
}

pub(crate) fn advertised_models<'a>(models: impl IntoIterator<Item = &'a [String]>) -> Vec<String> {
    models
        .into_iter()
        .flatten()
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn bounded_pricing(models: &[String], declared: Option<f64>) -> f64 {
    declared.map_or(1.0, |value| {
        behavior_contract::pricing_multiplier(models, value)
    })
}

pub(crate) fn endpoint_change_allowed(
    endpoint_changed: bool,
    has_token: bool,
    old_alive: bool,
) -> bool {
    !endpoint_changed || has_token || !old_alive
}

pub(crate) fn routing_change_allowed(
    strict: bool,
    secured: bool,
    endpoint_changed: bool,
    transport_endpoint_changed: bool,
    relay_endpoint_changed: bool,
    has_token: bool,
    old_endpoint_alive: bool,
) -> bool {
    let routing_changed = endpoint_changed || transport_endpoint_changed || relay_endpoint_changed;
    if has_token {
        return true;
    }
    if strict && secured {
        return false;
    }
    if !routing_changed {
        return true;
    }
    endpoint_change_allowed(endpoint_changed, has_token, old_endpoint_alive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_primitives_keep_boundary_behavior() {
        assert!(resolve_node_id(Some("node-1")).is_ok());
        assert!(resolve_node_id(Some("bad id")).is_err());
        assert!(valid_availability([("08:00", "17:00", 1.0)]));
        assert!(!valid_availability([("24:00", "17:00", 1.0)]));
        assert!(valid_pricing(1.0, "per_token"));
        assert!(!valid_pricing(1.0, "invented"));
    }

    #[test]
    fn strict_secured_refresh_requires_ownership() {
        assert!(!routing_change_allowed(
            true, true, false, false, false, false, false,
        ));
        assert!(routing_change_allowed(
            true, true, false, false, false, true, false,
        ));
        assert!(routing_change_allowed(
            false, false, true, false, false, false, false,
        ));
        assert!(!routing_change_allowed(
            false, false, true, false, false, false, true,
        ));
    }
}

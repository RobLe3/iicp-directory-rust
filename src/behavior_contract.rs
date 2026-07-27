// SPDX-License-Identifier: Apache-2.0
//! Pure policy primitives shared by runtime code and cross-runtime fixtures.

use std::net::IpAddr;

pub(crate) struct RankingInput<'a> {
    pub availability: f64,
    pub load: f64,
    pub active_jobs: u32,
    pub max_concurrent: u32,
    pub region: &'a str,
    pub reputation: Option<f64>,
    pub models: &'a [String],
    pub pricing: Option<f64>,
    pub sdk_current: bool,
    pub cx_key: bool,
}

pub(crate) fn ranking_score(
    node: &RankingInput<'_>,
    requested_region: Option<&str>,
    requested_model: Option<&str>,
) -> f64 {
    let load = 1.0 - node.load.min(1.0);
    let capacity = if node.max_concurrent > 0 {
        (1.0 - f64::from(node.active_jobs) / f64::from(node.max_concurrent)).max(0.0)
    } else {
        0.0
    };
    let region = requested_region.map_or(0.5, |wanted| (wanted == node.region) as u8 as f64);
    let reputation = node.reputation.unwrap_or(0.5);
    let score = if let Some(model) = requested_model {
        let model_match = node.models.iter().any(|candidate| candidate == model) as u8 as f64;
        let price = node
            .pricing
            .map_or(0.5, |price| (1.0 - price / 10.0).max(0.0));
        0.25 * node.availability
            + 0.20 * load
            + 0.15 * capacity
            + 0.10 * region
            + 0.10 * reputation
            + 0.10 * price
            + 0.10 * model_match
    } else {
        0.35 * node.availability + 0.28 * load + 0.18 * capacity + 0.09 * region + 0.10 * reputation
    };
    let readiness = (1.0_f64
        - if node.sdk_current { 0.0 } else { 0.08 }
        - if node.cx_key { 0.0 } else { 0.07 })
    .max(0.75);
    score * readiness
}

pub(crate) struct EligibilityInput<'a> {
    pub health_models: Option<&'a [String]>,
    pub models: &'a [String],
    pub backend_state: Option<&'a str>,
    pub reputation: f64,
    pub tasks: u64,
}

pub(crate) fn eligible(
    node: &EligibilityInput<'_>,
    model: Option<&str>,
    qos: Option<&str>,
    min_reputation: f64,
) -> bool {
    if node.health_models.is_some_and(<[String]>::is_empty)
        || matches!(node.backend_state, Some("draining" | "unavailable"))
    {
        return false;
    }
    let models = node.health_models.unwrap_or(node.models);
    if model.is_some_and(|wanted| !models.iter().any(|candidate| candidate == wanted)) {
        return false;
    }
    if qos == Some("realtime") && (node.tasks < 1000 || node.reputation < 0.8) {
        return false;
    }
    if qos == Some("interactive") && node.tasks < 100 {
        return false;
    }
    min_reputation <= 0.0 || node.reputation >= min_reputation
}

pub(crate) fn pricing_multiplier(models: &[String], declared: f64) -> f64 {
    let mut maximum = None::<f64>;
    for model in models {
        for (end, marker) in model.char_indices() {
            if marker != 'b' && marker != 'B' {
                continue;
            }
            let prefix = &model[..end];
            let start = prefix
                .char_indices()
                .rev()
                .find(|(_, c)| !(c.is_ascii_digit() || *c == '.'))
                .map_or(0, |(index, c)| index + c.len_utf8());
            let number = &prefix[start..];
            if let Ok(value) = number.parse::<f64>() {
                maximum = Some(maximum.map_or(value, |current| current.max(value)));
            }
        }
    }
    let weight = match maximum {
        Some(value) if value < 1.0 => 0.05,
        Some(value) if value < 10.0 => 1.0,
        Some(value) if value < 20.0 => 2.0,
        Some(value) if value < 50.0 => 6.5,
        Some(value) if value < 85.0 => 32.0,
        Some(_) => 75.0,
        None => 1.0,
    };
    declared.min(weight * 3.0)
}

pub(crate) fn blocked_ip(value: &str) -> bool {
    value
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<IpAddr>()
        .is_ok_and(|ip| {
            ip.is_loopback()
                || ip.is_unspecified()
                || match ip {
                    IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
                    IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
                }
        })
}

// SPDX-License-Identifier: Apache-2.0
//! Pure restricted trust-domain decision policy shared with conformance fixtures.

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DecisionInput {
    pub mode: String,
    pub operation: String,
    #[serde(default)]
    pub external_network: bool,
    #[serde(default)]
    pub public_fallback: bool,
    #[serde(default = "supported_profile")]
    pub profile_support: String,
    pub authenticated: Option<bool>,
    #[serde(default)]
    pub replayed: bool,
    pub membership: Option<String>,
    pub federation_trusted: Option<bool>,
    pub federation_scope_allowed: Option<bool>,
    pub policy_allowed: Option<bool>,
    pub route_authorized: Option<bool>,
    #[serde(default)]
    pub cached_authority: bool,
    #[serde(default)]
    pub after_restart: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub decision: String,
    pub reason: String,
    pub network_activity_permitted: bool,
}

pub fn evaluate(input: &DecisionInput) -> Decision {
    let reason = reason(input);
    Decision {
        decision: if reason == "allowed" { "allow" } else { "deny" }.to_string(),
        reason: reason.to_string(),
        network_activity_permitted: reason == "allowed" && input.mode != "local_only",
    }
}

fn reason(input: &DecisionInput) -> &'static str {
    if !matches!(
        input.mode.as_str(),
        "public" | "private" | "federated_private" | "local_only" | "custom"
    ) {
        return "invalid_input";
    }
    if input.profile_support == "unknown_required"
        || (input.profile_support == "unknown_optional" && input.mode != "public")
    {
        return "unsupported_required_profile";
    }
    if input.mode == "local_only" && input.external_network {
        return "local_only_external_forbidden";
    }
    if matches!(input.mode.as_str(), "private" | "federated_private") && input.public_fallback {
        return "public_fallback_forbidden";
    }
    if input.mode != "public" && input.authenticated != Some(true) {
        return "authentication_required";
    }
    if input.replayed {
        return "replay_detected";
    }
    if let Some(reason) = membership_reason(input) {
        return reason;
    }
    if input.operation == "federation" {
        if input.federation_trusted != Some(true) {
            return "federation_untrusted";
        }
        if input.federation_scope_allowed != Some(true) {
            return "federation_scope_denied";
        }
    }
    if input.policy_allowed == Some(false) {
        return "policy_denied";
    }
    if matches!(
        input.operation.as_str(),
        "relay" | "execution" | "cip" | "federation"
    ) && input.route_authorized != Some(true)
    {
        return "route_authorization_required";
    }
    "allowed"
}

fn membership_reason(input: &DecisionInput) -> Option<&'static str> {
    match input.membership.as_deref() {
        Some("valid") => None,
        Some("missing") => Some("membership_missing"),
        Some("expired") => Some("membership_expired"),
        Some("revoked") => Some("membership_revoked"),
        Some("wrong_domain") => Some("wrong_trust_domain"),
        None if input.mode == "public" => None,
        None => Some("membership_missing"),
        Some(_) => Some("invalid_input"),
    }
}

fn supported_profile() -> String {
    "supported".to_string()
}

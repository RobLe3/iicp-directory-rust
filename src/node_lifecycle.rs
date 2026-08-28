// SPDX-License-Identifier: Apache-2.0
//! Node lifecycle write handlers: registration, authenticated heartbeats and
//! public recognition. The module owns request validation and state transitions
//! only; routing, repository implementations and signing primitives remain in
//! their existing modules to preserve the directory contract (#38).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth;
use crate::delegation;
use crate::health;
use crate::operator::{normalize_operator_display_name, upsert_operator_from_register};
use crate::policy;
use crate::policy_manifest;
use crate::registration;
use crate::repo;
use crate::reputation;
use crate::state::AppState;
use crate::types;
use crate::validate::{endpoint_routable, is_declared_reachable, validate_intent};
use crate::{
    bearer_token, emit_event, err_json, get_client_ip, policy_reject, reject, EXPOSURE_MODES,
};

// ── register (iicp-dir §3.1) ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterRequest {
    /// Optional (iicp-dir §3.1: directory assigns if absent). Supplying a known id
    /// is identity recovery — register() preserves the existing reputation (ADR-026).
    #[serde(default)]
    node_id: Option<String>,
    endpoint: String,
    /// IICP-E050 (#529) — the node's existing token, proving ownership when an
    /// already-registered `node_id` re-registers with a changed `endpoint`.
    #[serde(default)]
    current_node_token: Option<String>,
    #[serde(default)]
    region: Option<String>,
    capabilities: Vec<types::EffectiveCapability>,
    // ── Phase 5 NODELIST fields (ADR-040/ADR-043) ─────────────────────────────
    /// NAT traversal type (iicp-dir §3.1). Used by RT-04 declared-reachable check.
    #[serde(default)]
    nat_type: Option<String>,
    /// Transport method (iicp-dir §3.1, ADR-040). Used by RT-04 + stored in NODELIST.
    #[serde(default)]
    transport_method: Option<String>,
    /// ADR-043: network exposure mode (e.g. ipv4_public_direct, relay_required).
    #[serde(default)]
    exposure_mode: Option<String>,
    /// Whether the node can act as a relay for CGNAT-blocked peers (Phase 5).
    #[serde(default)]
    relay_capable: Option<bool>,
    /// Native binary framing endpoint (iicp:// or iicpsec://), ADR-040.
    #[serde(default)]
    transport_endpoint: Option<String>,
    /// SDK implementation language (informational, Phase 5).
    #[serde(default)]
    sdk_language: Option<String>,
    #[serde(default)]
    implementation_name: Option<String>,
    #[serde(default)]
    implementation_version: Option<String>,
    #[serde(default)]
    sdk_compatibility_version: Option<String>,
    /// Legacy SDK compatibility alias.
    #[serde(default)]
    sdk_version: Option<String>,
    /// Pre-normative receipt profiles. Unknown values are rejected.
    #[serde(default)]
    supported_receipt_profiles: Vec<String>,
    /// Informational local backend flavour. It does not alter IICP routing.
    #[serde(default)]
    backend: Option<String>,
    /// cx_public_key identity object (ADR-030 operator identity, Phase 5).
    #[serde(default)]
    cx_public_key: Option<serde_json::Value>,
    /// NAT traversal metadata blob (ADR-043).
    #[serde(default)]
    transport_metadata: Option<serde_json::Value>,
    /// Public retention/training/jurisdiction declaration. Signed manifests
    /// are verified before persistence; unsigned manifests remain explicitly
    /// self-attested.
    #[serde(default)]
    policy_manifest: Option<serde_json::Value>,
    /// ADR-045 Phase A (#407) — optional verifiable operator→node delegation (ed25519).
    #[serde(default)]
    operator_delegation: Option<delegation::OperatorDelegation>,
    /// #463/#464 — operator-identity attributes (bound only when the delegation verifies).
    /// display_name is the public handle; created_at + integrity_hash are identity-integrity.
    /// contact/email is NEVER accepted (private).
    #[serde(default)]
    operator_display_name: Option<String>,
    #[serde(default)]
    operator_created_at: Option<String>,
    #[serde(default)]
    operator_integrity_hash: Option<String>,
    /// WQ-058 / ADR-017 REG-01 — operator public-listing opt-in (PHP: `listing` object with
    /// `public_listing` bool + `operator_url`). Absent → not listed.
    #[serde(default)]
    listing: Option<ListingInput>,
    #[serde(default)]
    availability: Vec<RegistrationAvailability>,
    #[serde(default)]
    pricing: Option<RegistrationPricing>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct RegistrationAvailability {
    start: String,
    end: String,
    #[serde(default = "default_availability_share")]
    share: f64,
}

fn default_availability_share() -> f64 {
    1.0
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct RegistrationPricing {
    #[serde(default = "default_credit_multiplier")]
    credit_cost_multiplier: f64,
    #[serde(default = "default_pricing_model")]
    pricing_model: String,
}

fn default_credit_multiplier() -> f64 {
    1.0
}

fn default_pricing_model() -> String {
    "per_token".into()
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ListingInput {
    #[serde(default)]
    public_listing: bool,
    #[serde(default)]
    operator_url: Option<String>,
}

/// Normalize operator display names for uniqueness checks (PHP NodeRegistry parity):
/// trim, fold runs of whitespace to one space, lowercase. Empty becomes None.
/// `GET /v1/leaderboards/{board_id}` (#310/#463, spec iicp-recognition §6). Anonymous-read
/// public recognition view. First board `founders`: operators with a founder ordinal, best
/// (lowest) first, serving only the public display_name + recognition state — operator_pubkey
/// is directory-private and never returned. Boards needing the §5 composite rank_score are
/// deferred (not fabricated) and 404 here.
pub(crate) async fn leaderboard(
    State(st): State<AppState>,
    axum::extract::Path(board_id): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if board_id != "founders" {
        return err_json(
            StatusCode::NOT_FOUND,
            "IICP-E050",
            "unknown or not-yet-computed leaderboard",
        );
    }
    let founders = st.repo.list_founders(100).await;
    let locked_count = founders.len();
    let entries: Vec<serde_json::Value> = founders
        .into_iter()
        .enumerate()
        .map(|(i, f)| {
            serde_json::json!({
                "place": i + 1,
                "display_name": f.display_name,
                "ordinal": f.ordinal,
                "tier": f.tier,
                "badge": f.badge,
            })
        })
        .collect();

    // Additive `pending` section (spec iicp-recognition 0.6.2 §6, PHP parity): provisional
    // operators on the 30-day clock. projected_ordinal is an ESTIMATE — ordinals are only
    // assigned at lock-in (§5.4.3) and the projection shifts if a predecessor drops out.
    const LOCKIN_MIN_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let pending: Vec<serde_json::Value> = st
        .repo
        .list_pending_founders(25)
        .await
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            let elapsed = (now_ms - p.first_seen_ms).max(0);
            let remaining_ms = (LOCKIN_MIN_AGE_MS - elapsed).max(0);
            serde_json::json!({
                "display_name": p.display_name,
                "projected_ordinal": locked_count + i + 1,
                "days_remaining": (remaining_ms + 86_400_000 - 1) / 86_400_000,
                "provisional": true,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "board_id": "founders",
            "title": "Founding Cohort",
            "count": entries.len(),
            "entries": entries,
            "pending": pending,
        })),
    )
}

/// Registration rate limit (IICP-E034, W-033 PHP parity): max registrations per source IP
/// per window, to stop rapid capability cycling. Matches RegisterController's 60 / 60s.
const REGISTER_RATE_LIMIT: u32 = 60;
pub(crate) const REGISTER_RATE_TTL_MS: u64 = 60_000;

/// Per-instance per-IP registration counter (held in AppState, not a global, so tests and
/// multiple instances don't share state). Per-instance is the unit, like PHP's per-instance Cache.
/// Pure window step for the registration rate limit (so the limit/TTL rule is unit-tested,
/// #404; the handler holds the map under a Mutex). Returns the new `(count, window_start_ms)`:
/// within the live window → increment in place; expired/new → reset to `(1, now_ms)`.
pub(crate) fn register_rate_step(prev: Option<(u32, u64)>, now_ms: u64, ttl_ms: u64) -> (u32, u64) {
    match prev {
        Some((count, start_ms)) if now_ms.saturating_sub(start_ms) < ttl_ms => {
            (count + 1, start_ms)
        }
        _ => (1, now_ms),
    }
}

/// IICP-E050 (F2/#529) re-registration endpoint-ownership decision — PHP NodeRegistry
/// `applyReRegistrationUpdate` parity. When an existing node's primary `endpoint` changes
/// on re-register, the change is allowed ONLY if the caller proves ownership
/// (`current_node_token` matches the stored hash) OR the old endpoint is verifiably gone
/// (so the change can't be a live takeover). A downlevel client without a token can still
/// rotate when its old endpoint is dead (migration-safe); an attacker pointing a victim's
/// `node_id` at a live, different endpoint is rejected. Pure so the rule is unit-tested;
/// the handler supplies `old_endpoint_alive` from a liveness probe.
fn relay_endpoint(metadata: Option<&serde_json::Value>) -> Option<&str> {
    metadata
        .and_then(serde_json::Value::as_object)
        .and_then(|value| value.get("relay_endpoint"))
        .and_then(serde_json::Value::as_str)
}

/// Liveness probe for the IICP-E050 absence path — PHP `isEndpointAlive` parity. A 2xx
/// from `<endpoint>/iicp/health` within 5s means the old endpoint is still serving (so a
/// token-less endpoint change is a likely takeover → rejected). Certs are not verified
/// (operators run self-signed tunnels), matching the PHP `withoutVerifying()`. Any error
/// (timeout, refused, DNS) → not alive. NOTE: like the PHP probe, this dials a
/// node-controlled URL; the SSRF/DNS-rebind hardening tracked in #535 applies to both.
async fn probe_endpoint_alive(endpoint: &str, allow_insecure_tls: bool) -> bool {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(allow_insecure_tls)
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("{}/iicp/health", endpoint.trim_end_matches('/'));
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

pub(crate) struct PendingRegistration {
    request: RegisterRequest,
    node: types::Node,
    intents: Vec<String>,
    capability_profiles: std::collections::HashMap<String, Vec<String>>,
    availability: Vec<repo::AvailabilityWindow>,
    node_id: String,
    node_token: String,
    proxy_token: String,
    node_hmac_key: String,
    operator_pubkey_for_upsert: Option<String>,
    recovered: bool,
    declared_reachable: bool,
}

fn validate_registration_request(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    validate_registration_shape(request)
        .or_else(|| validate_registration_capabilities(request))
        .or_else(|| validate_registration_policy_manifest(request))
}

fn validate_registration_policy_manifest(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let manifest = request.policy_manifest.as_ref()?;
    if let Err(message) = policy_manifest::validate_shape(manifest) {
        return Some(reject("validation_error", message));
    }
    let verification = policy_manifest::verify(manifest);
    (!verification.accepted()).then(|| {
        reject(
            "validation_error",
            &format!(
                "Invalid node policy manifest signature: {}",
                verification.status
            ),
        )
    })
}

fn validate_registration_shape(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if request.capabilities.is_empty() {
        return Some(reject(
            "validation_error",
            "at least one capability is required",
        ));
    }
    if request
        .backend
        .as_deref()
        .is_some_and(|backend| !registration::BACKENDS.contains(&backend))
    {
        return Some(reject(
            "validation_error",
            &format!(
                "invalid backend: {}",
                request.backend.as_deref().unwrap_or_default()
            ),
        ));
    }
    if request
        .implementation_name
        .as_deref()
        .is_some_and(|value| !valid_implementation_name(value))
        || request
            .implementation_version
            .as_deref()
            .is_some_and(|value| !valid_version_axis(value))
        || request
            .sdk_compatibility_version
            .as_deref()
            .is_some_and(|value| !valid_version_axis(value))
        || request
            .sdk_version
            .as_deref()
            .is_some_and(|value| !valid_version_axis(value))
    {
        return Some(reject(
            "validation_error",
            "invalid implementation metadata",
        ));
    }
    if matches!(
        (
            request.sdk_compatibility_version.as_deref(),
            request.sdk_version.as_deref(),
        ),
        (Some(preferred), Some(legacy)) if preferred != legacy
    ) {
        return Some(reject(
            "validation_error",
            "sdk_compatibility_version must match sdk_version when both are supplied",
        ));
    }
    validate_registration_profiles_and_exposure(request)
}

pub(crate) fn valid_implementation_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'@')
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'@' | b'+' | b'-')
        })
}

pub(crate) fn valid_version_axis(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn validate_registration_profiles_and_exposure(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if request.supported_receipt_profiles.len() > 4
        || request
            .supported_receipt_profiles
            .iter()
            .any(|profile| profile != "consumer_cosignature_v1")
    {
        return Some(reject("validation_error", "unsupported receipt profile"));
    }
    if request
        .exposure_mode
        .as_deref()
        .is_some_and(|mode| !EXPOSURE_MODES.contains(&mode))
    {
        return Some(reject(
            "validation_error",
            &format!(
                "invalid exposure_mode: {}",
                request.exposure_mode.as_deref().unwrap_or_default()
            ),
        ));
    }
    None
}

fn validate_registration_capabilities(
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let mut exact = std::collections::HashSet::new();
    let mut variants = std::collections::HashSet::new();
    for capability in &request.capabilities {
        if !validate_intent(&capability.intent) {
            return Some(reject(
                "validation_error",
                &format!("invalid intent URN: {}", capability.intent),
            ));
        }
        if let Some(classification) =
            policy::IntentPolicyGuard::public_mesh_refusal(&capability.intent)
        {
            return Some(policy_reject(&classification));
        }
        let canonical = serde_json::to_string(capability).unwrap_or_default();
        if !exact.insert(canonical)
            || capability.variant_id.as_ref().is_some_and(|variant| {
                !variants.insert((capability.intent.clone(), variant.clone()))
            })
        {
            return Some(reject("validation_error", "duplicate capability variant"));
        }
        if capability
            .variant_id
            .as_deref()
            .is_some_and(|value| !valid_capability_identifier(value, 64))
            || capability
                .version
                .as_deref()
                .is_some_and(|value| value.is_empty() || value.len() > 32)
            || capability.phase == Some(0)
            || capability.max_tokens == Some(0)
            || !valid_capability_string_set(&capability.models)
            || !valid_capability_string_set(&capability.input_modalities)
            || !valid_capability_string_set(&capability.output_modalities)
            || !valid_capability_string_set(&capability.features)
            || !valid_capability_string_set(&capability.execution_capabilities)
        {
            return Some(reject("validation_error", "invalid capability variant"));
        }
        if capability
            .input_modalities
            .iter()
            .any(|value| !matches!(value.as_str(), "text" | "image" | "audio" | "video"))
            || capability
                .output_modalities
                .iter()
                .any(|value| !matches!(value.as_str(), "text" | "image" | "audio" | "video"))
        {
            return Some(reject("validation_error", "invalid capability modality"));
        }
        if capability.limits.len() > 32
            || capability.limits.iter().any(|(name, limit)| {
                !valid_limit_name(name)
                    || !limit.value.is_finite()
                    || limit.value < 0.0
                    || !matches!(
                        limit.unit.as_str(),
                        "tokens" | "items" | "bytes" | "milliseconds" | "dimensions"
                    )
            })
        {
            return Some(reject("validation_error", "invalid capability limit"));
        }
        if capability.claim_provenance.as_ref().is_some_and(|claim| {
            !matches!(
                claim.source.as_str(),
                "heuristic_fallback"
                    | "operator_assertion"
                    | "provider_metadata"
                    | "runtime_introspection"
                    | "conformance_probe"
            ) || claim
                .observed_at
                .as_deref()
                .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_err())
                || claim
                    .valid_until
                    .as_deref()
                    .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_err())
                || claim
                    .evidence_ref
                    .as_deref()
                    .is_some_and(|value| value.is_empty() || value.len() > 255)
        }) {
            return Some(reject(
                "validation_error",
                "invalid capability claim provenance",
            ));
        }
        if capability.extensions.len() > 32
            || capability.extensions.iter().any(|(name, _extension)| {
                name.len() < 3
                    || name.len() > 128
                    || !name.contains('.')
                    || !name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b':' | b'-')
                    })
            })
        {
            return Some(reject(
                "validation_error",
                "invalid namespaced capability extension",
            ));
        }
        if capability.supported_profiles.len() > 16
            || capability.supported_profiles.iter().any(|profile| {
                profile.len() > 160
                    || !profile.starts_with("urn:iicp:profile:")
                    || profile[17..].is_empty()
                    || !profile[17..].bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
                    })
            })
            || {
                let unique: std::collections::HashSet<_> =
                    capability.supported_profiles.iter().collect();
                unique.len() != capability.supported_profiles.len()
            }
        {
            return Some(reject(
                "validation_error",
                "invalid capability supported_profiles",
            ));
        }
    }
    None
}

fn valid_capability_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_capability_string_set(values: &[String]) -> bool {
    values.len() <= 64
        && values
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 255)
        && values
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            == values.len()
}

fn valid_limit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

async fn commit_registration(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    pending: PendingRegistration,
) -> (StatusCode, Json<serde_json::Value>) {
    if state
        .repo
        .register(repo::NodeRecord {
            node: pending.node,
            intents: pending.intents,
            capabilities: pending.request.capabilities.clone(),
            capability_profiles: pending.capability_profiles,
            availability: pending.availability,
            node_token: Some(pending.node_token.clone()),
            node_hmac_key: Some(pending.node_hmac_key.clone()),
            proxy_token: Some(pending.proxy_token.clone()),
        })
        .await
        .is_err()
    {
        eprintln!("[repository] registration transaction failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": {
                    "code": "server_error",
                    "message": "registration persistence failed"
                }
            })),
        );
    }

    // Tokens become externally visible only after the node and all capabilities commit.
    let client_ip = get_client_ip(headers);
    state
        .repo
        .observe_address(&pending.node_id, client_ip, "register")
        .await;
    upsert_operator_from_register(
        state,
        &pending.operator_pubkey_for_upsert,
        pending.request.operator_display_name.as_deref(),
        pending.request.operator_created_at.as_deref(),
        pending.request.operator_integrity_hash.as_deref(),
    )
    .await;
    emit_event(
        state,
        "REGISTER",
        &pending.node_id,
        serde_json::json!({
            "endpoint": pending.request.endpoint,
            "region": pending.request.region,
            "backend": pending.request.backend,
            "supported_receipt_profiles": pending.request.supported_receipt_profiles,
            "capabilities": pending.request.capabilities.iter().map(|capability| serde_json::json!({
                "intent": capability.intent,
                "version": capability.version,
                "phase": capability.phase,
                "variant_id": capability.variant_id,
                "models": capability.models,
                "max_tokens": capability.max_tokens,
                "quantization": capability.quantization,
                "inference_engine": capability.inference_engine,
                "input_modalities": capability.input_modalities,
                "output_modalities": capability.output_modalities,
                "features": capability.features,
                "execution_capabilities": capability.execution_capabilities,
                "limits": capability.limits,
                "supported_profiles": capability.supported_profiles,
                "claim_provenance": capability.claim_provenance,
                "extensions": capability.extensions,
            })).collect::<Vec<_>>(),
        }),
    )
    .await;

    let jwt_token = auth::issue_jwt(&pending.node_id);
    let jwt_expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(3600))
        .map(|time| time.to_rfc3339());
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "node_id": pending.node_id,
            "node_token": pending.node_token,
            "proxy_token": pending.proxy_token,
            "node_hmac_key": pending.node_hmac_key,
            "expires_at": serde_json::Value::Null,
            "jwt_token": jwt_token,
            "jwt_expires_at": jwt_expires_at,
            "directory": "iicp-directory-rs",
            "observed_source_ip": client_ip,
            "recovered": pending.recovered,
            "lifetime_jobs": 0u32,
            "public_reachable": pending.declared_reachable,
        })),
    )
}

fn registration_rate_rejection(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let ip = get_client_ip(headers).to_string();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let count = {
        let mut rates = state.register_rate.lock().unwrap();
        let (count, start) =
            register_rate_step(rates.get(&ip).copied(), now_ms, REGISTER_RATE_TTL_MS);
        rates.insert(ip, (count, start));
        count
    };
    (count > REGISTER_RATE_LIMIT).then(|| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "IICP-E034",
                "message": "Too many registration attempts from this source IP. Try again shortly.",
                "retry_after": REGISTER_RATE_TTL_MS / 1000
            })),
        )
    })
}

async fn registration_ownership_rejection(
    state: &AppState,
    request: &RegisterRequest,
    node_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let existing = state.repo.get(node_id).await?;
    let has_ownership = match request.current_node_token.as_deref() {
        Some(token) if !token.is_empty() => state.repo.verify_node_token(node_id, token).await,
        _ => false,
    };

    let cx_changed = request
        .cx_public_key
        .as_ref()
        .is_some_and(|key| !key.is_null() && existing.public_key.as_ref() != Some(key));
    if cx_changed && !has_ownership {
        return Some((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "IICP-E049",
                "message": "cx_public_key update requires a valid current_node_token"
            })),
        ));
    }

    let endpoint_changed = existing.endpoint != request.endpoint;
    let transport_endpoint_changed = existing.transport_endpoint != request.transport_endpoint;
    let relay_endpoint_changed = relay_endpoint(existing.transport_metadata.as_ref())
        != relay_endpoint(request.transport_metadata.as_ref());
    let secured = existing.operator_pubkey.is_some() || existing.public_key.is_some();
    let old_alive = if endpoint_changed && !has_ownership && !(state.strict_e050_secured && secured)
    {
        probe_endpoint_alive(&existing.endpoint, state.allow_insecure_tls).await
    } else {
        false
    };
    if registration::routing_change_allowed(
        state.strict_e050_secured,
        secured,
        endpoint_changed,
        transport_endpoint_changed,
        relay_endpoint_changed,
        has_ownership,
        old_alive,
    ) {
        return None;
    }

    Some((
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "IICP-E050",
            "message": if state.strict_e050_secured && secured {
                "secured-node re-registration requires a valid current_node_token"
            } else {
                "endpoint change requires the current node_token (the existing endpoint is still reachable); re-register with current_node_token to prove ownership"
            }
        })),
    ))
}

async fn registration_control_rejection(
    state: &AppState,
    request: &RegisterRequest,
    node_id: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if let Some(rejection) = policy_manifest_lifecycle_rejection(state, request).await {
        return Some(rejection);
    }
    registration_ownership_rejection(state, request, node_id).await
}

async fn policy_manifest_lifecycle_rejection(
    state: &AppState,
    request: &RegisterRequest,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let manifest = request.policy_manifest.as_ref()?;
    let key_sha = policy_manifest::verify(manifest).public_key_sha256?;
    state
        .repo
        .policy_key_lifecycle_status(&key_sha)
        .await
        .filter(|status| status != "active")
        .map(|_| {
            reject(
                "validation_error",
                "Invalid node policy manifest signature: directory lifecycle record is not active",
            )
        })
}

async fn operator_display_name_rejection(
    state: &AppState,
    operator_pubkey: Option<&str>,
    display_name: Option<&str>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let (Some(operator_pubkey), Some(display_name)) = (operator_pubkey, display_name) else {
        return None;
    };
    let normalized = normalize_operator_display_name(display_name)?;
    state
        .repo
        .operator_display_name_claimed_by_other(operator_pubkey, &normalized)
        .await
        .then(|| {
            reject(
                "validation_error",
                "operator_display_name is already claimed by another verified operator (IICP-E051)",
            )
        })
}

/// `POST /v1/register` (iicp-dir §3.1). Validates the endpoint routability invariant
/// (IICP-E035) and every capability intent URN before issuing a token. The RT-04 guard
/// (`is_declared_reachable`) decides whether a liveness probe may be skipped. Dynamic
/// external tunnels never bypass the dial-back merely because a URL was allocated.
pub(crate) async fn register(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // IICP-E034 (W-033 PHP parity): rate-limit registrations per source IP BEFORE any work,
    // so rapid capability cycling can't churn the directory. Source IP via get_client_ip
    // (CF-Connecting-IP → X-Forwarded-For), same extraction the rest of the handler uses.
    if let Some(rejection) = registration_rate_rejection(&st, &headers) {
        return rejection;
    }
    if let Some(rejection) = validate_registration_request(&req) {
        return rejection;
    }
    if let Err(e) = endpoint_routable(&req.endpoint, st.env) {
        return reject("IICP-E035", &format!("non-routable endpoint: {e:?}"));
    }

    // RT-04: a node without a concrete topology declaration must prove dial-back
    // reachability before credentials are issued. TLS identity remains enabled in
    // production; only an explicit non-production testbed can disable it.
    let declared = is_declared_reachable(req.nat_type.as_deref(), req.transport_method.as_deref());
    let endpoint_verified = if declared || st.skip_liveness_check {
        true
    } else {
        probe_endpoint_alive(&req.endpoint, st.allow_insecure_tls).await
    };
    if !endpoint_verified {
        return reject(
            "IICP-E036",
            "endpoint unreachable or TLS identity verification failed",
        );
    }

    // node_id: collision-free UUID v4 (iter-1571 BUG fix — SystemTime-nanos could collide).
    // node_token: UUID v4, bcrypt-hashed by MySqlRepo at cost 12 before storing.
    // node_hmac_key: 32-byte hex secret for CIP credit receipt signing (W-009, iicp-dir §6.2).
    // `recovered` = true when caller supplied a known node_id (identity recovery per ADR-026).
    let recovered = req.node_id.as_deref().is_some_and(|s| !s.is_empty());
    // PHP validates node_id format: alphanumeric start, then [a-zA-Z0-9._:-], max 36 chars.
    // If a custom node_id is supplied, validate it before assigning.
    let node_id = match registration::resolve_node_id(req.node_id.as_deref()) {
        Ok(node_id) => node_id,
        Err(message) => return reject("validation_error", message),
    };

    // IICP-E049/E050 (F2/#529) — re-registration ownership guards. When this node_id
    // already exists, protect the two takeover vectors. Ownership = a current_node_token
    // that verifies against the stored hash; computed once and shared. PHP NodeRegistry
    // applyReRegistrationUpdate parity.
    if let Some(rejection) = registration_control_rejection(&st, &req, &node_id).await {
        return rejection;
    }

    let node_token = uuid::Uuid::new_v4().to_string();
    let proxy_token = uuid::Uuid::new_v4().to_string();
    let node_hmac_key = hex::encode(uuid::Uuid::new_v4().as_bytes());

    // ADR-045 Phase A (#407) — verify an optional operator→node delegation and bind the
    // verified operator identity (PHP NodeRegistry parity, #385; lenient/fail-safe: an
    // invalid or absent delegation leaves the node unverified, never aborts registration).
    let (operator_pubkey, operator_verified, operator_trust_tier) = delegation::evaluate(
        req.operator_delegation.as_ref(),
        &node_id,
        delegation::now_unix(),
    );
    if let Some(operator_pubkey) = operator_pubkey.as_deref() {
        if st.repo.operator_identity_active(operator_pubkey).await == Some(false) {
            return reject(
                "validation_error",
                "operator delegation references an inactive identity",
            );
        }
    }
    // #463/#464 — capture before operator_pubkey moves into the Node, for the operators upsert.
    let operator_pubkey_for_upsert = operator_pubkey.clone();

    // #525/G3 — operator display names are public handles; a look-alike claim by another
    // verified operator is rejected using PHP's whitespace-folded, case-insensitive check.
    if let Some(rejection) = operator_display_name_rejection(
        &st,
        operator_pubkey_for_upsert.as_deref(),
        req.operator_display_name.as_deref(),
    )
    .await
    {
        return rejection;
    }

    if !registration::valid_availability(
        req.availability
            .iter()
            .map(|window| (window.start.as_str(), window.end.as_str(), window.share)),
    ) {
        return reject("validation_error", "invalid availability window");
    }
    if req.pricing.as_ref().is_some_and(|pricing| {
        !registration::valid_pricing(pricing.credit_cost_multiplier, &pricing.pricing_model)
    }) {
        return reject("validation_error", "invalid pricing declaration");
    }
    let advertised_models = registration::advertised_models(
        req.capabilities
            .iter()
            .map(|capability| capability.models.as_slice()),
    );
    let pricing_multiplier = registration::bounded_pricing(
        &advertised_models,
        req.pricing
            .as_ref()
            .map(|pricing| pricing.credit_cost_multiplier),
    );
    let node = types::Node {
        node_id: node_id.clone(),
        endpoint: req.endpoint.clone(),
        region: req.region.clone().unwrap_or_default(),
        score: reputation::STARTING_SCORE,
        available: true,
        load: 0.0,
        active_jobs: 0,
        max_concurrent: 0,
        reputation_score: reputation::STARTING_SCORE,
        reputation_model: Some("outcome-v2".to_string()),
        reputation_epoch: Some("outcome-v2-initial".to_string()),
        latency_estimate_ms: None,
        completed_tasks_count: 0,
        health_label: None,
        exposure_mode: req.exposure_mode.clone(),
        reputation_tier: Some("bronze".into()), // probation (< 100 tasks) → bronze floor tier
        transport_endpoint: req.transport_endpoint.clone(),
        cip_conformance_level: Some("CIP-None".into()),
        models: advertised_models,
        supported_profiles: vec![],
        capabilities: req.capabilities.clone(),
        pricing: None,
        cip_policy: Some(serde_json::json!({
            "allow_remote_inference": false,
            "allow_tool_execution": false,
            "allow_file_access": false,
            "pricing_credits_per_1000": null
        })),
        quantization: req
            .capabilities
            .iter()
            .filter_map(|c| c.quantization.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .map(String::from)
            .collect(),
        inference_engine: req
            .capabilities
            .iter()
            .filter_map(|c| c.inference_engine.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .map(String::from)
            .collect(),
        nat_type: req.nat_type.clone(),
        transport_method: req.transport_method.clone(),
        relay_capable: req.relay_capable,
        sdk_language: req.sdk_language.clone(),
        implementation_name: req.implementation_name.clone(),
        implementation_version: req.implementation_version.clone(),
        sdk_compatibility_version: req
            .sdk_compatibility_version
            .clone()
            .or_else(|| req.sdk_version.clone()),
        sdk_version: req
            .sdk_compatibility_version
            .clone()
            .or_else(|| req.sdk_version.clone()),
        consumer_cosignature_ready: req
            .supported_receipt_profiles
            .iter()
            .any(|profile| profile == "consumer_cosignature_v1"),
        backend: req.backend.clone(),
        address_family: None, // set at query time by detect_address_family
        public_key: req.cx_public_key.clone(),
        transport_metadata: req.transport_metadata.clone(),
        // #400 — pricing/attestation default at register; pricing refined via heartbeat.
        credit_cost_multiplier: pricing_multiplier,
        pricing_model: Some(
            req.pricing
                .as_ref()
                .map_or_else(default_pricing_model, |pricing| {
                    pricing.pricing_model.clone()
                }),
        ),
        attested: false,
        tasks_failed: 0,
        transport: vec![], // #397 — derived at discover time
        // #385 — new node: public_reachable=false until probed; relay per request.
        reachability_signal: health::reachability_from_flags(
            false,
            req.relay_capable.unwrap_or(false),
        ),
        operator_pubkey,
        operator_display_name: None,
        operator_fingerprint: None,
        operator_verified,
        operator_trust_tier,
        // WQ-058 / ADR-017 REG-01 — operator public-listing opt-in (default: not listed).
        public_listing: req
            .listing
            .as_ref()
            .map(|l| l.public_listing)
            .unwrap_or(false),
        operator_url: req.listing.as_ref().and_then(|l| l.operator_url.clone()),
        policy_manifest: req.policy_manifest.clone(),
        health_models: None, // #494 — populated by the first heartbeat with a backend URL
        routing_policy: types::RoutingPolicyState::default(),
    };
    let intents = req.capabilities.iter().map(|c| c.intent.clone()).collect();
    let capability_profiles = req
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.intent.clone(),
                capability.supported_profiles.clone(),
            )
        })
        .collect();
    let availability = req
        .availability
        .iter()
        .map(|window| repo::AvailabilityWindow {
            start: window.start.clone(),
            end: window.end.clone(),
            share: window.share,
        })
        .collect();
    commit_registration(
        &st,
        &headers,
        PendingRegistration {
            request: req,
            node,
            intents,
            capability_profiles,
            availability,
            node_id,
            node_token,
            proxy_token,
            node_hmac_key,
            operator_pubkey_for_upsert,
            recovered,
            declared_reachable: endpoint_verified,
        },
    )
    .await
}

// ── heartbeat (iicp-dir §3.2) ─────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct HeartbeatMetrics {
    #[serde(default)]
    tasks_success: u32,
    #[serde(default)]
    tasks_failed: u32,
    #[serde(default)]
    avg_latency_ms: f64,
}

/// ADR-019 pricing block carried in heartbeat.
#[derive(Debug, Deserialize, Default)]
struct HeartbeatPricing {
    #[serde(default)]
    credit_cost_multiplier: Option<f64>,
    #[serde(default)]
    pricing_model: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HeartbeatRequest {
    node_id: String,
    /// ADR-047: lowercase-hex HMAC-SHA256 of the challenge issued by the prior PONG.
    #[serde(default)]
    challenge_response: Option<String>,
    #[serde(default)]
    load: f64,
    #[serde(default)]
    available: Option<bool>,
    #[serde(default)]
    active_jobs: Option<u32>,
    #[serde(default)]
    metrics: Option<HeartbeatMetrics>,
    #[serde(default)]
    metrics_batch_id: Option<String>,
    #[serde(default)]
    pricing: Option<HeartbeatPricing>,
    /// #494 — live model list probed by the SDK on each heartbeat.
    /// null / absent = SDK did not report (backward compat); [] = no models loaded.
    #[serde(default)]
    health_models: Option<Vec<String>>,
}

/// `POST /v1/heartbeat` (iicp-dir §3.2). Requires `Authorization: Bearer <node_token>`.
/// Computes the reputation delta via the auditable `reputation::compute_delta` (RT-01 cap),
/// persists load/available + the new score against the node record, and returns PONG with
/// the node's real reputation_score. 404 if the node_id is unknown.
pub(crate) async fn heartbeat(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": { "code": "unauthorized", "message": "missing node_token" } }),
                ),
            )
        }
    };
    // InMemoryRepo always accepts (local/test mode); MySqlRepo verifies against node_token_hash.
    if !st.repo.verify_node_token(&req.node_id, &token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": { "code": "unauthorized", "message": "invalid node_token" } }),
            ),
        );
    }

    let m = req.metrics.unwrap_or_default();
    if req.metrics_batch_id.as_ref().is_some_and(|id| {
        id.is_empty() || id.len() > 64 || !id.bytes().all(|b| (0x21..=0x7e).contains(&b))
    }) {
        return reject("validation_error", "invalid metrics_batch_id");
    }
    // PHP HeartbeatController caps tasks at 1000 per call (physically implausible above this).
    let tasks_success = m.tasks_success.min(1000);
    let tasks_failed = m.tasks_failed.min(1000);
    let tasks_delta = tasks_success + tasks_failed;
    let avg_latency = m.avg_latency_ms.max(0.0);
    let delta = reputation::compute_delta(tasks_success, tasks_failed, avg_latency);
    let available = req.available.unwrap_or(true);
    let active_jobs = req.active_jobs.unwrap_or(0);
    // PHP validates load in [0.0, 1.0]. Clamp rather than reject — adapters may overshoot.
    let load = req.load.clamp(0.0, 1.0);

    // PHP HeartbeatController updates observed_source_ip on every heartbeat (DIR-ADDR-08).
    let client_ip = get_client_ip(&headers);
    st.repo
        .observe_address(&req.node_id, client_ip, "heartbeat")
        .await;

    // ADR-019: update pricing declaration when a pricing block is present.
    if let Some(ref pricing) = req.pricing {
        // AL2 (#401) — pricing_model enum parity with PHP: reject out-of-vocabulary values.
        if let Some(ref pm) = pricing.pricing_model {
            if !registration::PRICING_MODELS.contains(&pm.as_str()) {
                return reject("validation_error", &format!("invalid pricing_model: {pm}"));
            }
        }
        if let Some(multiplier) = pricing.credit_cost_multiplier {
            let models = st
                .repo
                .node_by_prefix(&req.node_id)
                .await
                .filter(|node| node.node_id == req.node_id)
                .map(|node| node.models)
                .unwrap_or_default();
            let multiplier = registration::bounded_pricing(&models, Some(multiplier));
            st.repo
                .update_pricing(&req.node_id, multiplier, pricing.pricing_model.as_deref())
                .await;
        }
    }

    match st
        .repo
        .heartbeat(
            &req.node_id,
            load,
            available,
            active_jobs,
            tasks_delta,
            tasks_failed,
            delta,
            req.metrics_batch_id.clone(),
            req.health_models,
        )
        .await
    {
        Some(outcome) => {
            let score = outcome.score;
            let next_challenge = hex::encode(uuid::Uuid::new_v4().as_bytes());
            if st
                .repo
                .verify_and_rotate_liveness_challenge(
                    &req.node_id,
                    req.challenge_response.as_deref(),
                    &next_challenge,
                )
                .await
                .is_none()
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": {
                            "code": "internal_error",
                            "message": "heartbeat liveness state could not be persisted"
                        }
                    })),
                );
            }
            // PHP logs REPUTATION_UPDATE event when tasks are reported (Phase 6 prereq).
            if tasks_delta > 0 && outcome.metrics_applied {
                let payload = serde_json::json!({
                    "source": "heartbeat_metrics",
                    "tasks_success": tasks_success,
                    "tasks_failed": tasks_failed,
                    "reputation_score": score
                })
                .to_string();
                st.repo
                    .log_event(&req.node_id, "REPUTATION_UPDATE", &payload)
                    .await;
            }
            // Maybe award free credits (6h gate, §6.5, RT-02b IP gate #380).
            let client_ip = get_client_ip(&headers);
            let free_credits = st
                .repo
                .maybe_allocate_free_credits(&req.node_id, client_ip)
                .await;
            let mut resp = serde_json::json!({
                "ok": true,
                "next_heartbeat_ms": 30000,
                "reputation_score": (score * 10000.0).round() / 10000.0,
                "reputation_model": outcome.reputation_model,
                "reputation_epoch": outcome.reputation_epoch,
                "metrics_batch_accepted": req.metrics_batch_id,
                "challenge": next_challenge,
            });
            if free_credits > 0.0 {
                resp["free_credits_awarded"] = serde_json::json!(free_credits);
            }
            (StatusCode::OK, Json(resp))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({ "error": { "code": "IICP-E003", "message": "node not registered" } }),
            ),
        ),
    }
}

//! Privacy-preserving public registry handlers.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::health;
use crate::repo::{IntentSummary, RegistryStats};
use crate::state::AppState;
use crate::{operator_display_name_for, operator_fingerprint_for, transport_methods};

#[derive(Debug, Deserialize)]
pub(crate) struct RegistryNodesParams {
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    per_page: Option<usize>,
}

fn listing_exposure(public_listing: bool, operator_url: &Option<String>) -> serde_json::Value {
    if public_listing {
        serde_json::json!(operator_url)
    } else {
        serde_json::Value::Null
    }
}

pub(crate) async fn registry_nodes(
    State(st): State<AppState>,
    Query(p): Query<RegistryNodesParams>,
) -> Json<serde_json::Value> {
    let per_page = p.per_page.unwrap_or(20).min(100);
    let page = p.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page as u64;
    let raw_nodes = st.repo.list_public(offset, per_page).await;
    let total = raw_nodes.len() as u32;
    let nodes: Vec<serde_json::Value> = raw_nodes
        .into_iter()
        .map(|n| {
            let is_uuid = uuid::Uuid::parse_str(&n.node_id).is_ok();
            let prefix = if is_uuid {
                n.node_id[..8.min(n.node_id.len())].to_string()
            } else {
                n.node_id.clone()
            };
            serde_json::json!({
                "node_id_prefix": prefix,
                "region": n.region,
                "reputation_score": (n.reputation_score * 1000.0).round() / 1000.0,
                "reputation_tier": n.reputation_tier,
                "models": n.models,
                "probation": n.completed_tasks_count < 100,
                "last_seen": serde_json::Value::Null,
                "public_listing": n.public_listing,
                "operator_url": listing_exposure(n.public_listing, &n.operator_url),
            })
        })
        .collect();
    Json(serde_json::json!({ "total": total, "page": page, "limit": per_page, "nodes": nodes }))
}

pub(crate) async fn registry_stats(State(st): State<AppState>) -> Json<RegistryStats> {
    Json(st.repo.registry_stats().await)
}

pub(crate) async fn registry_node_detail(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let valid = (1..=36).contains(&id.len())
        && id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if !valid {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "REGISTRY-INVALID-PREFIX",
                "message": "Prefix must be alphanumeric (max 36 chars)."
            })),
        );
    }

    match st.repo.node_by_prefix(&id).await {
        Some(n) => {
            let is_uuid = uuid::Uuid::parse_str(&n.node_id).is_ok();
            let prefix = if is_uuid {
                n.node_id[..8.min(n.node_id.len())].to_string()
            } else {
                n.node_id.clone()
            };
            let signals = health::HealthSignals {
                reachability: n.reachability_signal,
                latency_ms: n.latency_estimate_ms.map(|ms| ms as f64),
            };
            let nh = health::score_node(&signals);
            let comp = health::components_of(&signals);
            let r3 = |x: f64| (x * 1000.0).round() / 1000.0;
            let operator_display_name =
                operator_display_name_for(&st, n.operator_pubkey.as_deref()).await;
            let operator_fingerprint = operator_fingerprint_for(n.operator_pubkey.as_deref());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "node_id_prefix": prefix,
                    "region": n.region,
                    "reputation_score": (n.reputation_score * 1000.0).round() / 1000.0,
                    "reputation_tier": n.reputation_tier,
                    "transport": transport_methods(&n.endpoint, n.transport_endpoint.as_deref()),
                    "health": {
                        "score": nh.score,
                        "label": nh.label,
                        "observed": false,
                        "components": {
                            "liveness": 1.0,
                            "reachability": r3(comp.reachability),
                            "latency": r3(comp.latency),
                        },
                        "evaluated_at": chrono::Utc::now().to_rfc3339(),
                    },
                    "probation": n.completed_tasks_count < 100,
                    "completed_tasks": n.completed_tasks_count,
                    "observed_latency_ms": n.latency_estimate_ms,
                    "exposure_mode": n.exposure_mode,
                    "operator_display_name": operator_display_name,
                    "operator_fingerprint": operator_fingerprint,
                    "last_seen": serde_json::Value::Null,
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "REGISTRY-NODE-NOT-FOUND",
                "message": "No active node found for this prefix."
            })),
        ),
    }
}

pub(crate) async fn registry_intents(State(st): State<AppState>) -> Json<serde_json::Value> {
    let intents: Vec<IntentSummary> = st.repo.list_intents().await;
    Json(serde_json::json!({ "intents": intents }))
}

#[cfg(test)]
mod tests {
    use super::listing_exposure;

    #[test]
    fn operator_url_is_served_only_for_opted_in_listings() {
        let url = Some("https://op.example".to_string());
        assert_eq!(
            listing_exposure(true, &url),
            serde_json::json!("https://op.example")
        );
        assert_eq!(listing_exposure(false, &url), serde_json::Value::Null);
        assert_eq!(listing_exposure(true, &None), serde_json::Value::Null);
    }
}

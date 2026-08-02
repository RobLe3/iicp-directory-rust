//! Read-only directory health and aggregate statistics handlers.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Instant;

use axum::extract::State;
use axum::Json;

use crate::health as health_scoring;
use crate::state::AppState;
use crate::VERSION;

/// Process start instant backing `server.uptime_seconds` in `/v1/stats`.
/// It is set once by process composition and remains unset in unit tests.
static START_TIME: OnceLock<Instant> = OnceLock::new();

pub(crate) fn mark_started() {
    START_TIME.set(Instant::now()).ok();
}

pub(crate) async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "version": VERSION }))
}

pub(crate) fn sdk_adoption_json(nodes: &[crate::types::Node]) -> serde_json::Value {
    let mut by_language: BTreeMap<String, u32> = BTreeMap::new();
    let mut by_version: BTreeMap<String, u32> = BTreeMap::new();
    for n in nodes {
        let lang = n
            .sdk_language
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let version = n
            .effective_sdk_compatibility_version()
            .filter(|v| !v.is_empty())
            .unwrap_or("unknown")
            .to_string();
        *by_language.entry(lang).or_insert(0) += 1;
        *by_version.entry(version).or_insert(0) += 1;
    }
    serde_json::json!({
        "total_active": nodes.len(),
        "by_language": by_language,
        "by_version": by_version,
    })
}

fn receipt_profile_adoption_json(nodes: &[crate::types::Node]) -> serde_json::Value {
    let ready = nodes
        .iter()
        .filter(|node| node.consumer_cosignature_ready)
        .count();
    serde_json::json!({
        "basis": "heartbeating_nodes",
        "profile": "consumer_cosignature_v1",
        "ready": ready,
        "total_heartbeating": nodes.len(),
    })
}

/// `/v1/stats` (iicp-dir §3.9b). Returns live active_node count when backed by MySQL;
/// mesh_health score is deferred to Phase 2 (requires per-node health vector aggregation).
pub(crate) async fn stats(State(st): State<AppState>) -> Json<serde_json::Value> {
    let active_nodes = st.repo.active_count().await;
    let last_probe_at = st.repo.last_probe_at().await;
    // ADR-044 mesh_health: median per-node health over the active provider set.
    // Signal mapping (#385 Phase-B): reputation + latency + success ratio + reachability
    // are all real node-row signals now. Reachability uses public_reachable/relay_capable
    // per PHP NodeHealthService reachabilityScore fallback (the recent-probe branch is
    // #373/VPS-gated active probing, which the Rust directory does not perform). The
    // scoring algorithm itself is byte-for-byte the PHP NodeHealthService.
    let provider_set = st.repo.active_nodes().await;
    let sdk_adoption = sdk_adoption_json(&provider_set);
    let receipt_profile_adoption = receipt_profile_adoption_json(&provider_set);
    let dispatch_discovery_adoption = st.repo.dispatch_usage_summary(7).await;
    let healths: Vec<health_scoring::NodeHealth> = provider_set
        .iter()
        .map(|n| {
            health_scoring::score_node(&health_scoring::HealthSignals {
                reachability: n.reachability_signal,
                latency_ms: n.latency_estimate_ms.map(|ms| ms as f64),
            })
        })
        .collect();
    let mesh = health_scoring::mesh_health(&healths);
    // ADR-048 (#374): federation-aware mesh_health — resolve each node by majority-vote
    // across evaluators over the union of replicated HEALTH snapshots, so any replica
    // reports the same fleet aggregate. Null until HEALTH events have been applied
    // (federation active); the single-directory mesh_health above stays authoritative.
    let fed_rows = st.repo.all_health_observations().await;
    let mesh_health_federated = if fed_rows.is_empty() {
        serde_json::Value::Null
    } else {
        let obs: Vec<health_scoring::HealthObservation> = fed_rows
            .into_iter()
            .map(|(node_id, evaluator_did, score, evaluated_at_ms)| {
                health_scoring::HealthObservation {
                    node_id,
                    evaluator_did,
                    score,
                    evaluated_at_ms,
                }
            })
            .collect();
        let f = health_scoring::federated_mesh_health(&obs);
        serde_json::json!({
            "score": f.score,
            "label": f.label,
            "mean": f.mean,
            "p10": f.p10,
            "distribution": {
                "healthy": f.distribution.healthy,
                "degraded": f.distribution.degraded,
                "impaired": f.distribution.impaired,
                "critical": f.distribution.critical,
                "offline": f.distribution.offline
            },
            "sample": f.sample,
            "contested": f.contested,
            "unconfirmed": f.unconfirmed,
            "basis": "federated_union",
            "window": "replicated"
        })
    };
    // PHP StatsController parity: probe aggregates + directory_health (ADR-044).
    let (probe_active_count, probe_regions) = st.repo.probe_active_count_and_regions().await;
    let agg24 = st.repo.probe_aggregate_24h().await;
    let top_failures = st.repo.probe_top_failures().await;
    let top_failures_json: Vec<serde_json::Value> = top_failures
        .iter()
        .map(|f| {
            serde_json::json!({
                "test_id": f.test_id,
                "passed": f.passed,
                "failed": f.failed,
                "total": f.total,
                "fail_rate": f.fail_rate,
            })
        })
        .collect();
    let directory_health = compute_directory_health(&agg24);
    // PHP StatsController credit_schedule static data (§8.3 pre-flight).
    let credit_schedule = serde_json::json!({
        "formula": "ceil(output_tokens / tokens_per_credit) × tier_weight × node_multiplier",
        "tokens_per_credit": 1000,
        "tier_weights": { "sub_1b": 0.05, "7b": 1.0, "13b": 2.0, "30b": 6.5, "70b": 32.0, "100b_plus": 75.0 },
        "evaluation_grant": { "credits": 5, "interval_seconds": 21600 },
        "burn_rate_pct": 2.0
    });
    Json(serde_json::json!({
        "server": {
            "active_nodes": active_nodes,
            "version": VERSION,
            // PHP StatsController parity: internal_nodes (directory-internal seed nodes —
            // Rust has no internal-node classification yet → 0) + process uptime.
            "internal_nodes": 0u32,
            "stale_active_nodes": 0u32,  // DIR-STATS-02: Rust NodeLifecycle background task prunes stale rows
            "uptime_seconds": START_TIME.get().map(|t| t.elapsed().as_secs()).unwrap_or(0),
        },
        "probes": {
            "active_count": probe_active_count,
            "regions": probe_regions,
            "aggregate_24h": {
                "discover_p50_ms": agg24.discover_p50_ms,
                "discover_p95_ms": agg24.discover_p95_ms,
                "heartbeat_p50_ms": agg24.heartbeat_p50_ms,
                "reachability_pct": agg24.reachability_pct,
                "task_success_rate_pct": agg24.task_success_rate_pct,
            },
            "conformance_24h": {
                "passed": agg24.conformance_passed,
                "failed": agg24.conformance_failed,
                "top_failures": top_failures_json,
            },
            "last_probe_at": last_probe_at,
        },
        "credit_schedule": credit_schedule,
        "mesh_health": {
            "score": mesh.score,
            "label": mesh.label,
            "mean": mesh.mean,
            "p10": mesh.p10,
            "distribution": {
                "healthy": mesh.distribution.healthy,
                "degraded": mesh.distribution.degraded,
                "impaired": mesh.distribution.impaired,
                "critical": mesh.distribution.critical,
                "offline": mesh.distribution.offline
            },
            "sample": mesh.sample,
            "basis": "active_provider_nodes",
            "window": "live"
        },
        "mesh_health_federated": mesh_health_federated,
        "directory_health": directory_health,
        "sdk_adoption": sdk_adoption,
        "receipt_profile_adoption": receipt_profile_adoption,
        "dispatch_discovery_adoption": dispatch_discovery_adoption,
    }))
}

/// ADR-044 directory_health score — matches PHP StatsController::directoryHealth().
/// Formula: 0.6 × discover_latency_score + 0.4 × conformance_pass_fraction.
/// Returns `label: "unavailable"` when no probe data has been ingested yet.
pub(crate) fn compute_directory_health(agg: &crate::repo::ProbeAggregate24h) -> serde_json::Value {
    let p50 = agg.discover_p50_ms;
    let passed = agg.conformance_passed;
    let failed = agg.conformance_failed;

    if p50.is_none() && passed == 0 && failed == 0 {
        return serde_json::json!({
            "score": serde_json::Value::Null,
            "label": "unavailable",
            "components": serde_json::Value::Null,
            "probe_reachability_pct": agg.reachability_pct,
            "window": "24h",
        });
    }

    let lat_score = p50
        .map(|v| (1.0 - (v - 50.0) / 450.0).clamp(0.0, 1.0))
        .unwrap_or(0.5);
    let total = passed + failed;
    let conf_score = if total > 0 {
        passed as f64 / total as f64
    } else {
        1.0
    };
    let score = ((0.6 * lat_score + 0.4 * conf_score) * 1000.0).round() / 1000.0;

    let label = if score >= 0.85 {
        "healthy"
    } else if score >= 0.65 {
        "degraded"
    } else if score >= 0.40 {
        "impaired"
    } else {
        "critical"
    };

    serde_json::json!({
        "score": score,
        "label": label,
        "components": {
            "discover_latency": (lat_score * 1000.0).round() / 1000.0,
            "conformance": (conf_score * 1000.0).round() / 1000.0,
        },
        "discover_p50_ms": p50,
        "probe_reachability_pct": agg.reachability_pct,
        "window": "24h",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_reports_current_version() {
        let Json(value) = health().await;
        assert_eq!(value["ok"], true);
        assert_eq!(value["version"], VERSION);
    }

    #[test]
    fn directory_health_is_unavailable_without_probe_data() {
        let aggregate = crate::repo::ProbeAggregate24h::default();
        let health = compute_directory_health(&aggregate);
        assert_eq!(health["label"], "unavailable");
        assert!(health["score"].is_null());
    }

    #[test]
    fn directory_health_is_healthy_for_fast_conformant_probes() {
        let aggregate = crate::repo::ProbeAggregate24h {
            discover_p50_ms: Some(50.0),
            conformance_passed: 100,
            conformance_failed: 0,
            ..Default::default()
        };
        let health = compute_directory_health(&aggregate);
        assert_eq!(health["label"], "healthy");
        let score = health["score"].as_f64().expect("numeric score");
        assert!((score - 1.0).abs() < 0.001, "score was {score}");
    }

    #[test]
    fn directory_health_is_critical_for_slow_half_failing_probes() {
        let aggregate = crate::repo::ProbeAggregate24h {
            discover_p50_ms: Some(500.0),
            conformance_passed: 50,
            conformance_failed: 50,
            ..Default::default()
        };
        let health = compute_directory_health(&aggregate);
        assert_eq!(health["label"], "critical");
        let score = health["score"].as_f64().expect("numeric score");
        assert!(score < 0.40, "score was {score}");
    }
}

// SPDX-License-Identifier: Apache-2.0

//! NodeHealthService parity port — ADR-044 (issue #372/#385).
//!
//! Faithful Rust port of the *pure scoring algorithm* from the PHP
//! `App\Services\NodeHealthService`. Health is a per-node property first; mesh
//! health is a derived aggregate that is the **median** of active provider
//! nodes, with the full distribution and worst-decile (p10) exposed so a few
//! good nodes cannot mask a tail of bad ones.
//!
//! Component weights, curves, label thresholds, percentile method and aggregate
//! shape are byte-for-byte equivalent to the PHP service so `/v1/stats`
//! `mesh_health` is identical across the two directory implementations.
//!
//! ## Signal availability (Phase-A status, #385)
//!
//! PHP scores four components from the full `nodes` row + `telemetry_probes`.
//! The Rust directory's wire/DB model currently exposes only **reputation** and
//! **latency** as ground-truth per-node signals. **Reachability** (probe /
//! `public_reachable` / `relay_capable`) and **success ratio** (`tasks_failed`
//! window) require schema columns the Rust port does not yet carry; until those
//! land (tracked follow-up), callers pass PHP's documented neutral fallbacks
//! (`reachability` per caller policy, `success` → 0.5 for no task data). The
//! algorithm here is complete and identical to PHP; only the *inputs* are
//! Phase-A until the signal-collection layer is ported.

/// Component weights — sum to 1.0 (PHP `W_*` constants). Reachability dominates
/// because an unreachable node cannot serve regardless of latency. Reputation is
/// intentionally absent: health reflects operational liveness, not earned task
/// history (#492 / ADR-044).
const W_REACHABILITY: f64 = 0.70;
const W_LATENCY: f64 = 0.30;

/// Below this many active nodes a single mesh number is not meaningful
/// (PHP `MIN_MESH_SAMPLE`).
const MIN_MESH_SAMPLE: u32 = 3;

/// Per-node input signals, each already normalised to [0, 1] except the raw
/// latency (milliseconds).
#[derive(Debug, Clone)]
pub struct HealthSignals {
    /// Reachability in [0, 1]. 1.0 = directly reachable, 0.5 = relay-only,
    /// 0.0 = unreachable. Phase-A: caller supplies the best available estimate.
    pub reachability: f64,
    /// Observed/estimated round-trip latency in ms. `None` → no measurement.
    pub latency_ms: Option<f64>,
}

/// Per-node health vector: integer score (0–100) + ADR-044 label.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeHealth {
    pub score: u32,
    pub label: &'static str,
}

/// Component sub-scores (each in [0, 1]) behind a node's composite score —
/// surfaced verbatim in the `/v1/registry/nodes/:id` `health.components` field
/// (PHP `forNode`).
#[derive(Debug, Clone, PartialEq)]
pub struct Components {
    pub reachability: f64,
    pub latency: f64,
}

/// Compute the two weighted component sub-scores from a node's signals.
/// `score_node` derives the composite from exactly these values, so the
/// detail endpoint's breakdown and the mesh score can never disagree.
pub fn components_of(s: &HealthSignals) -> Components {
    Components {
        reachability: s.reachability.clamp(0.0, 1.0),
        latency: latency_score(s.latency_ms),
    }
}

/// Mesh aggregate, ready to serialise into the `/v1/stats` `mesh_health` shape.
#[derive(Debug, Clone)]
pub struct MeshHealth {
    /// Median node score normalised to [0, 1], rounded to 3 dp.
    pub score: f64,
    pub label: String,
    pub mean: Option<f64>,
    pub p10: Option<f64>,
    pub distribution: Distribution,
    pub sample: u32,
}

/// Label histogram over the active provider set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Distribution {
    pub healthy: u32,
    pub degraded: u32,
    pub impaired: u32,
    pub critical: u32,
    pub offline: u32,
}

/// Latency curve: ≤ 50 ms → 1.0, ≥ 500 ms → 0.0, linear between (PHP `latencyCurve`).
fn latency_curve(ms: f64) -> f64 {
    (1.0 - (ms - 50.0) / 450.0).clamp(0.0, 1.0)
}

/// Latency component: prefer the measured value; neutral 0.5 when absent
/// (PHP `latencyScore` no-data branch).
fn latency_score(latency_ms: Option<f64>) -> f64 {
    match latency_ms {
        Some(ms) if ms > 0.0 => latency_curve(ms),
        _ => 0.5,
    }
}

/// #385 Phase-B reachability fallback — byte-for-byte parity with PHP
/// `NodeHealthService::reachabilityScore()` self-attested branch: a directly
/// reachable node scores 1.0; otherwise a relay-capable node scores 0.5; an
/// unreachable, non-relay node scores 0.0. (PHP's recent-probe branch is Phase-B
/// active probing — #373/VPS-gated — and never fires on the Rust directory, which
/// writes no reachability probes, so the fallback is the operative path.)
pub fn reachability_from_flags(public_reachable: bool, relay_capable: bool) -> f64 {
    if public_reachable {
        1.0
    } else if relay_capable {
        0.5
    } else {
        0.0
    }
}

/// ADR-044 label from a 0–100 score (PHP `label`).
fn label(score: u32) -> &'static str {
    match score {
        s if s >= 85 => "healthy",
        s if s >= 65 => "degraded",
        s if s >= 40 => "impaired",
        _ => "critical",
    }
}

/// Per-node health vector from a live node's signals. Liveness is assumed
/// (callers pass only the active provider set — heartbeat-fresh nodes); dead
/// nodes are excluded upstream and counted as `offline` separately.
pub fn score_node(s: &HealthSignals) -> NodeHealth {
    let c = components_of(s);
    let score01 = W_REACHABILITY * c.reachability + W_LATENCY * c.latency;
    let score = (score01 * 100.0).round() as u32;
    NodeHealth {
        score,
        label: label(score),
    }
}

/// Nearest-rank percentile over an ascending-sorted slice of 0–100 scores
/// (PHP `percentile`). Returns 0 for an empty slice.
fn percentile(sorted: &[u32], p: u32) -> u32 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    let rank = ((p as f64 / 100.0) * n as f64).ceil() as i64;
    let idx = (rank - 1).clamp(0, n as i64 - 1) as usize;
    sorted[idx]
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// Mesh health: median of per-node scores over the active provider set, with
/// distribution + p10 exposed (PHP `meshHealth`). An empty set yields the
/// `unavailable` sentinel (score 0.0 satisfies the float[0,1] wire contract).
pub fn mesh_health(healths: &[NodeHealth]) -> MeshHealth {
    let sample = healths.len() as u32;
    if sample == 0 {
        return MeshHealth {
            score: 0.0,
            label: "unavailable".to_string(),
            mean: None,
            p10: None,
            distribution: Distribution::default(),
            sample: 0,
        };
    }

    let mut scores: Vec<u32> = healths.iter().map(|h| h.score).collect();
    scores.sort_unstable();
    let median = percentile(&scores, 50);
    let avg = scores.iter().map(|&s| s as f64).sum::<f64>() / sample as f64;

    let mut dist = Distribution::default();
    for h in healths {
        match h.label {
            "healthy" => dist.healthy += 1,
            "degraded" => dist.degraded += 1,
            "impaired" => dist.impaired += 1,
            "critical" => dist.critical += 1,
            "offline" => dist.offline += 1,
            _ => {}
        }
    }

    MeshHealth {
        score: round3(median as f64 / 100.0),
        label: if sample < MIN_MESH_SAMPLE {
            "insufficient_sample".to_string()
        } else {
            label(median).to_string()
        },
        mean: Some(round3(avg / 100.0)),
        p10: Some(round3(percentile(&scores, 10) as f64 / 100.0)),
        distribution: dist,
        sample,
    }
}

// ── ADR-048 (#374): federation-aware mesh_health ───────────────────────────────
//
// The per-node health vector travels directory-to-directory in the signed event log
// as a HEALTH event; every replica stores per-(node, evaluator) snapshots and resolves
// each node's canonical health by MAJORITY-VOTE across evaluators, then aggregates over
// the union of known nodes. This MUST be byte-for-byte equivalent to the PHP
// `FederatedMeshHealthResolver` so any replica reports the same federation aggregate.
//
// The items below carry `#[allow(dead_code)]`: the pure resolver + tests land in this
// apply_event(HEALTH) storage + /v1/stats wiring now live (slice 5); resolver is wired.

/// Distinct evaluator DIDs required before a majority is "confirmed" (PHP `QUORUM`).
pub const HEALTH_QUORUM: usize = 3;

/// A per-node, per-evaluator health snapshot replicated via the HEALTH event — mirror of
/// the PHP `node_health_observations` row. `score` is on the [0,1] wire scale.
#[derive(Debug, Clone)]
pub struct HealthObservation {
    pub node_id: String,
    pub evaluator_did: String,
    pub score: f64,
    pub evaluated_at_ms: i64,
}

/// One node's canonical health after applying the conflict/staleness rule.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedNode {
    pub score: f64,
    pub label: String,
    /// majority | most_recent | unconfirmed | none
    pub resolution: String,
    pub evaluators: usize,
    pub contested: bool,
}

/// Federation-wide aggregate over the union of nodes (PHP `federatedMeshHealth`).
#[derive(Debug, Clone)]
pub struct FederatedMeshHealth {
    pub score: f64,
    pub label: String,
    pub mean: Option<f64>,
    pub p10: Option<f64>,
    pub distribution: Distribution,
    pub sample: u32,
    pub contested: u32,
    pub unconfirmed: u32,
}

/// ADR-044 label for a [0,1] score (PHP `labelForScore((int) round(score*100))`).
fn label01(score: f64) -> &'static str {
    label((score * 100.0).round() as u32)
}

/// Nearest-rank percentile over a pre-sorted slice of [0,1] floats (PHP `percentile`).
fn percentile_f64(sorted: &[f64], p: u32) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    let rank = ((p as f64 / 100.0) * n as f64).ceil() as i64;
    let idx = (rank - 1).clamp(0, n as i64 - 1) as usize;
    sorted[idx]
}

/// Resolve one node's canonical health from its per-evaluator snapshots.
///
/// Each evaluator casts one vote (its snapshot); votes are bucketed by ADR-044 label.
/// A strict-majority label wins (canonical score = median of that bucket). No majority →
/// most-recent by `evaluated_at_ms` (contested). Fewer than `HEALTH_QUORUM` distinct
/// evaluators → freshest single snapshot (unconfirmed). Mirrors PHP `resolveNode`.
pub fn resolve_node(obs: &[HealthObservation]) -> ResolvedNode {
    // One vote per distinct evaluator_did (the storage layer keeps a single row per
    // evaluator, but counting distinct DIDs is the spec-correct quorum quantity).
    let evaluators = obs
        .iter()
        .map(|o| o.evaluator_did.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    if evaluators == 0 {
        return ResolvedNode {
            score: 0.0,
            label: "unavailable".to_string(),
            resolution: "none".to_string(),
            evaluators: 0,
            contested: false,
        };
    }

    let freshest = obs.iter().max_by_key(|o| o.evaluated_at_ms).unwrap();

    if evaluators < HEALTH_QUORUM {
        let score = round3(freshest.score);
        return ResolvedNode {
            score,
            label: label01(score).to_string(),
            resolution: "unconfirmed".to_string(),
            evaluators,
            contested: false,
        };
    }

    // Bucket votes by label. A strict majority (> half) can be reached by at most one
    // bucket, so iteration order is irrelevant to the outcome.
    let mut buckets: std::collections::HashMap<&'static str, Vec<f64>> =
        std::collections::HashMap::new();
    for o in obs {
        buckets.entry(label01(o.score)).or_default().push(o.score);
    }
    let needed = evaluators / 2 + 1;

    if let Some((_, scores)) = buckets.iter().find(|(_, v)| v.len() >= needed) {
        let mut s = scores.clone();
        s.sort_by(|a, b| a.total_cmp(b));
        let median = round3(percentile_f64(&s, 50));
        return ResolvedNode {
            score: median,
            label: label01(median).to_string(),
            resolution: "majority".to_string(),
            evaluators,
            contested: false,
        };
    }

    let score = round3(freshest.score);
    ResolvedNode {
        score,
        label: label01(score).to_string(),
        resolution: "most_recent".to_string(),
        evaluators,
        contested: true,
    }
}

/// Federation-wide mesh_health over the union of nodes with any HEALTH observation
/// (PHP `federatedMeshHealth`). Pure function of the snapshots → identical across replicas.
pub fn federated_mesh_health(obs: &[HealthObservation]) -> FederatedMeshHealth {
    if obs.is_empty() {
        return FederatedMeshHealth {
            score: 0.0,
            label: "unavailable".to_string(),
            mean: None,
            p10: None,
            distribution: Distribution::default(),
            sample: 0,
            contested: 0,
            unconfirmed: 0,
        };
    }

    let mut groups: std::collections::HashMap<&str, Vec<HealthObservation>> =
        std::collections::HashMap::new();
    for o in obs {
        groups
            .entry(o.node_id.as_str())
            .or_default()
            .push(o.clone());
    }

    let resolved: Vec<ResolvedNode> = groups.values().map(|v| resolve_node(v)).collect();
    let mut scores: Vec<f64> = resolved.iter().map(|r| r.score).collect();
    scores.sort_by(|a, b| a.total_cmp(b));
    let sample = scores.len() as u32;
    let median = percentile_f64(&scores, 50);
    let avg = scores.iter().sum::<f64>() / sample as f64;

    let mut dist = Distribution::default();
    for r in &resolved {
        match r.label.as_str() {
            "healthy" => dist.healthy += 1,
            "degraded" => dist.degraded += 1,
            "impaired" => dist.impaired += 1,
            "critical" => dist.critical += 1,
            "offline" => dist.offline += 1,
            _ => {}
        }
    }

    FederatedMeshHealth {
        score: round3(median),
        label: if sample < MIN_MESH_SAMPLE {
            "insufficient_sample".to_string()
        } else {
            label01(median).to_string()
        },
        mean: Some(round3(avg)),
        p10: Some(round3(percentile_f64(&scores, 10))),
        distribution: dist,
        sample,
        contested: resolved.iter().filter(|r| r.contested).count() as u32,
        unconfirmed: resolved
            .iter()
            .filter(|r| r.resolution == "unconfirmed")
            .count() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #385 Phase-B — reachability fallback parity with PHP reachabilityScore:
    // public_reachable → 1.0; else relay_capable → 0.5; else 0.0.
    #[test]
    fn reachability_from_flags_matches_php_fallback() {
        assert_eq!(reachability_from_flags(true, false), 1.0); // direct
        assert_eq!(reachability_from_flags(true, true), 1.0); // public wins over relay
        assert_eq!(reachability_from_flags(false, true), 0.5); // relay-only
        assert_eq!(reachability_from_flags(false, false), 0.0); // unreachable, non-relay
    }

    #[test]
    fn latency_curve_boundaries() {
        assert_eq!(latency_curve(50.0), 1.0);
        assert_eq!(latency_curve(0.0), 1.0); // clamped
        assert_eq!(latency_curve(500.0), 0.0);
        assert_eq!(latency_curve(1000.0), 0.0); // clamped
        assert!((latency_curve(275.0) - 0.5).abs() < 1e-9); // midpoint
    }

    #[test]
    fn latency_score_no_data_is_neutral() {
        assert_eq!(latency_score(None), 0.5);
        assert_eq!(latency_score(Some(0.0)), 0.5);
        assert_eq!(latency_score(Some(-1.0)), 0.5);
        assert_eq!(latency_score(Some(50.0)), 1.0);
    }

    #[test]
    fn label_thresholds() {
        assert_eq!(label(100), "healthy");
        assert_eq!(label(85), "healthy");
        assert_eq!(label(84), "degraded");
        assert_eq!(label(65), "degraded");
        assert_eq!(label(64), "impaired");
        assert_eq!(label(40), "impaired");
        assert_eq!(label(39), "critical");
        assert_eq!(label(0), "critical");
    }

    #[test]
    fn score_node_all_perfect() {
        let h = score_node(&HealthSignals {
            reachability: 1.0,
            latency_ms: Some(50.0),
        });
        assert_eq!(h.score, 100);
        assert_eq!(h.label, "healthy");
    }

    // #492 — brand-new reachable node with no task history (latency unknown → neutral 0.5)
    // must score ≥ 85 (healthy). Old formula: 0.30 + 0.35 = 0.65 → 65 → degraded.
    // New formula: 0.70*1.0 + 0.30*0.5 = 0.85 → 85 → healthy.
    #[test]
    fn new_reachable_node_with_no_task_history_is_healthy() {
        let h = score_node(&HealthSignals {
            reachability: 1.0,
            latency_ms: None,
        });
        assert_eq!(h.score, 85);
        assert_eq!(h.label, "healthy");
    }

    #[test]
    fn score_node_weighting() {
        // reachability=1, latency neutral(0.5), endpoint-only formula
        // = 0.70*1 + 0.30*0.5 = 0.85 → 85
        let h = score_node(&HealthSignals {
            reachability: 1.0,
            latency_ms: None,
        });
        assert_eq!(h.score, 85);
        assert_eq!(h.label, "healthy");
    }

    #[test]
    fn components_match_score() {
        let s = HealthSignals {
            reachability: 0.5,
            latency_ms: Some(50.0),
        };
        let c = components_of(&s);
        assert_eq!(c.reachability, 0.5);
        assert_eq!(c.latency, 1.0);
        // composite = 0.70*0.5 + 0.30*1.0 = 0.35+0.30 = 0.65 → 65
        assert_eq!(score_node(&s).score, 65);
    }

    #[test]
    fn percentile_nearest_rank() {
        let s = [10u32, 20, 30, 40, 50];
        assert_eq!(percentile(&s, 50), 30); // ceil(2.5)=3 → idx 2
        assert_eq!(percentile(&s, 10), 10); // ceil(0.5)=1 → idx 0
        assert_eq!(percentile(&s, 100), 50);
        assert_eq!(percentile(&[], 50), 0);
    }

    #[test]
    fn mesh_health_empty_is_unavailable() {
        let m = mesh_health(&[]);
        assert_eq!(m.score, 0.0);
        assert_eq!(m.label, "unavailable");
        assert_eq!(m.sample, 0);
        assert_eq!(m.mean, None);
    }

    #[test]
    fn mesh_health_below_min_sample() {
        let healths = vec![
            NodeHealth {
                score: 90,
                label: "healthy",
            },
            NodeHealth {
                score: 60,
                label: "impaired",
            },
        ];
        let m = mesh_health(&healths);
        // median of [60,90] nearest-rank p50 = idx ceil(1.0)-1=0 → wait: n=2, ceil(0.5*2)=1 → idx0 = 60
        assert_eq!(m.score, 0.6);
        assert_eq!(m.label, "insufficient_sample"); // 2 < 3
        assert_eq!(m.sample, 2);
        assert_eq!(m.distribution.healthy, 1);
        assert_eq!(m.distribution.impaired, 1);
    }

    #[test]
    fn mesh_health_full_sample_uses_median_label() {
        let healths = vec![
            NodeHealth {
                score: 90,
                label: "healthy",
            },
            NodeHealth {
                score: 88,
                label: "healthy",
            },
            NodeHealth {
                score: 86,
                label: "healthy",
            },
        ];
        let m = mesh_health(&healths);
        // sorted [86,88,90], p50 nearest-rank ceil(1.5)=2 → idx1 = 88
        assert_eq!(m.score, 0.88);
        assert_eq!(m.label, "healthy"); // 3 >= MIN_MESH_SAMPLE
        assert_eq!(m.distribution.healthy, 3);
        assert_eq!(m.mean, Some(round3((86.0 + 88.0 + 90.0) / 3.0 / 100.0)));
    }

    // ── ADR-048 federated mesh_health (parity with PHP FederatedMeshHealthResolverTest) ──

    fn obs(node: &str, evaluator: &str, score: f64, at_ms: i64) -> HealthObservation {
        HealthObservation {
            node_id: node.to_string(),
            evaluator_did: evaluator.to_string(),
            score,
            evaluated_at_ms: at_ms,
        }
    }

    #[test]
    fn majority_label_wins_with_quorum() {
        let o = vec![
            obs("node-a", "did:web:e1", 0.90, 1000),
            obs("node-a", "did:web:e2", 0.88, 1000),
            obs("node-a", "did:web:e3", 0.10, 1000),
        ];
        let r = resolve_node(&o);
        assert_eq!(r.resolution, "majority");
        assert_eq!(r.label, "healthy");
        assert!(!r.contested);
        // median of healthy bucket {0.88, 0.90} nearest-rank p50 → idx0 → 0.88
        assert_eq!(r.score, 0.88);
    }

    #[test]
    fn no_majority_falls_back_to_most_recent_contested() {
        let o = vec![
            obs("node-a", "did:web:e1", 0.90, 1000), // healthy
            obs("node-a", "did:web:e2", 0.70, 1000), // degraded
            obs("node-a", "did:web:e3", 0.45, 3000), // impaired, freshest
        ];
        let r = resolve_node(&o);
        assert_eq!(r.resolution, "most_recent");
        assert!(r.contested);
        assert_eq!(r.score, 0.45);
    }

    #[test]
    fn below_quorum_uses_freshest_unconfirmed() {
        let o = vec![
            obs("node-a", "did:web:e1", 0.30, 1000),
            obs("node-a", "did:web:e2", 0.95, 5000), // freshest
        ];
        let r = resolve_node(&o);
        assert_eq!(r.resolution, "unconfirmed");
        assert!(!r.contested);
        assert_eq!(r.score, 0.95);
    }

    #[test]
    fn federated_aggregate_over_union() {
        let mut o = Vec::new();
        for e in ["e1", "e2", "e3"] {
            o.push(obs("node-a", &format!("did:web:{e}"), 0.90, 1000));
            o.push(obs("node-b", &format!("did:web:{e}"), 0.10, 1000));
            o.push(obs("node-c", &format!("did:web:{e}"), 0.70, 1000));
        }
        let m = federated_mesh_health(&o);
        assert_eq!(m.sample, 3);
        assert_eq!(m.contested, 0);
        // union {0.10, 0.70, 0.90} → median 0.70
        assert_eq!(m.score, 0.70);
        assert_eq!(m.distribution.healthy, 1);
        assert_eq!(m.distribution.degraded, 1);
        assert_eq!(m.distribution.critical, 1);
    }

    #[test]
    fn empty_observations_unavailable() {
        let m = federated_mesh_health(&[]);
        assert_eq!(m.sample, 0);
        assert_eq!(m.label, "unavailable");
        assert_eq!(m.score, 0.0);
    }
}

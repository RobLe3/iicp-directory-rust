// SPDX-License-Identifier: Apache-2.0
//! Reputation scoring — the auditable core (PARITY: ReputationService, M4).
//!
//! This is the Rust directory's reason to exist (concept-review F7/F10): the scoring
//! formula is a **pure function compiled into the binary**, not a set of configurable
//! server-side weights an operator can silently bias. Mirrors `iicp-semantics.md §11.2`
//! and the PHP `ReputationService`, including the RT-01 (#375) per-heartbeat cap.

/// Normative delta constants — iicp-semantics §11.2.
const DELTA_SUCCESS: f64 = 0.01;
const DELTA_OK: f64 = 0.0;
const DELTA_LATENCY_BREACH: f64 = -0.05;
const DELTA_FAILURE: f64 = -0.05;
/// Interactive QoS latency budget (ms) — iicp-semantics §11.1.
const LATENCY_BUDGET_MS: f64 = 2000.0;
/// RT-01 (#375): a single heartbeat's positive delta is capped so self-reported task
/// counts cannot inflate a score from 0.5 → 1.0 in one call.
const MAX_POSITIVE_DELTA_PER_HEARTBEAT: f64 = 0.10;

/// Compute the reputation delta for one heartbeat's reported task outcomes.
/// Positive component is capped (RT-01); negative component (failures) is not.
pub fn compute_delta(tasks_success: u32, tasks_failed: u32, avg_latency_ms: f64) -> f64 {
    let mut delta = 0.0;

    if tasks_success > 0 {
        let per_success = if avg_latency_ms <= LATENCY_BUDGET_MS {
            DELTA_SUCCESS
        } else if avg_latency_ms <= LATENCY_BUDGET_MS * 2.0 {
            DELTA_OK
        } else {
            DELTA_LATENCY_BREACH
        };
        delta += tasks_success as f64 * per_success;
    }

    delta += tasks_failed as f64 * DELTA_FAILURE;

    // RT-01: cap the positive component only.
    if delta > MAX_POSITIVE_DELTA_PER_HEARTBEAT {
        delta = MAX_POSITIVE_DELTA_PER_HEARTBEAT;
    }
    delta
}

/// Apply a delta to a score, clamped to [0.0, 1.0] (iicp-semantics §11.4 bounded invariant).
pub fn apply_delta(old_score: f64, delta: f64) -> f64 {
    (old_score + delta).clamp(0.0, 1.0)
}

/// Default starting score for a node with no history (iicp-semantics §11.3).
pub const STARTING_SCORE: f64 = 0.5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_good_task_earns_delta_success() {
        assert_eq!(compute_delta(1, 0, 500.0), 0.01);
    }

    #[test]
    fn rt01_inflated_task_count_is_capped() {
        // Attack: claim 100 successes at 0ms — uncapped this is +1.0.
        let d = compute_delta(100, 0, 0.0);
        assert!(
            d <= MAX_POSITIVE_DELTA_PER_HEARTBEAT,
            "delta {d} must be capped at 0.10"
        );
        // From 0.5, one heartbeat cannot reach 1.0.
        assert!(apply_delta(STARTING_SCORE, d) < 1.0);
    }

    #[test]
    fn rt01_even_1000_tasks_capped() {
        assert!(compute_delta(1000, 0, 0.0) <= MAX_POSITIVE_DELTA_PER_HEARTBEAT);
    }

    #[test]
    fn failures_not_capped() {
        // 10 failures → -0.50, applied in full (negative side is uncapped).
        assert_eq!(compute_delta(0, 10, 0.0), -0.50);
    }

    #[test]
    fn latency_breach_penalises_success() {
        // success but > 2× budget → per-success is a breach penalty.
        assert_eq!(compute_delta(1, 0, 5000.0), DELTA_LATENCY_BREACH);
    }

    #[test]
    fn ok_band_no_change() {
        // between budget and 2× budget → neutral.
        assert_eq!(compute_delta(3, 0, 3000.0), DELTA_OK);
    }

    #[test]
    fn score_clamps_to_bounds() {
        assert_eq!(apply_delta(0.98, 0.10), 1.0); // clamps high
        assert_eq!(apply_delta(0.02, -0.50), 0.0); // clamps low
    }
}

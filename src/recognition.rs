// SPDX-License-Identifier: Apache-2.0
//! Founder-ordinal recognition computation — spec/iicp-recognition.md §5.4 (#310).
//!
//! Pure, side-effect-free functions: given a founder's ordinal + lock-in time + genesis
//! time, compute the **single-best** founder badge. The directory is authoritative
//! (DIR-RECOG / RECOG-FND); the underlying state rides two signed event types on the #458
//! hash-chained log (see [`FOUNDER_LOCKIN`] / [`FOUNDER_SUCCESSION`]). The 30-day lock-in
//! *detector* + persistence + read endpoint are a later #310 slice; this module is the
//! algorithm those slices call, and is fully unit-testable on synthetic events.
//!
//! Parity: byte-for-byte logic match with PHP `App\Services\FounderRecognition` (#385).

// The lock-in detector + read endpoint that call these land in the next #310 slice.
#![allow(dead_code)]

/// New signed event types (extend ADR-013 / iicp-dir §3.4). Emitted only by the directory.
pub const FOUNDER_LOCKIN: &str = "FOUNDER_LOCKIN";
pub const FOUNDER_SUCCESSION: &str = "FOUNDER_SUCCESSION";

/// One "month" = 30 days in ms. Uniform definition for the tier windows (avoids calendar
/// ambiguity; MUST match PHP `FounderRecognition::MONTH_MS`).
pub const MONTH_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// (ordinal cap, lock-in window, tier badge) per founder tier — nested, ascending cap
/// (spec §5.4.3): Genesis-50 ≤3mo, Founders-500 ≤6mo, Founders-1000 ≤12mo.
const TIERS: [(u64, i64, &str); 3] = [
    (50, 3 * MONTH_MS, "genesis_50"),
    (500, 6 * MONTH_MS, "founders_500"),
    (1000, 12 * MONTH_MS, "founders_1000"),
];

/// Inner pure-ordinal sub-brackets inside Genesis-50 (single-best, finest threshold first).
const INNER: [(u64, &str); 4] = [
    (10, "first_10"),
    (20, "first_20"),
    (30, "first_30"),
    (50, "first_50"),
];

/// §5.4.2 primary lock-in gate: ≥ 30 days of healthy operation. The demand-scaled task floor
/// (verified availability substitutes for a raw task count when there are no consumers) is a
/// refinement layered in the scan/detect step; this is the age component. MUST match PHP
/// `FounderRecognition::LOCKIN_MIN_AGE_MS`.
pub const LOCKIN_MIN_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// The immutable assignment a lock-in produces — persisted on the operator record + emitted
/// as a `FOUNDER_LOCKIN` event.
#[derive(Debug, Clone, PartialEq)]
pub struct LockinAssignment {
    pub ordinal: u64,
    pub tier: &'static str,
    pub badge: &'static str,
    pub locked_at_ms: i64,
}

/// The broad founder tier (genesis_50 / founders_500 / founders_1000) for an ordinal locked at
/// `locked_at_ms` (genesis at `genesis_ms`), or `None` if outside every founder tier. A tier
/// requires BOTH its ordinal cap AND its lock-in window (spec §5.4.3, rule R2 — measured on the
/// lock-in timestamp). Tiers checked tightest-first.
pub fn founder_tier(ordinal: u64, locked_at_ms: i64, genesis_ms: i64) -> Option<&'static str> {
    if ordinal == 0 {
        return None;
    }
    let elapsed = locked_at_ms.saturating_sub(genesis_ms);
    for (cap, window, tier) in TIERS {
        if ordinal <= cap && elapsed <= window {
            return Some(tier);
        }
    }
    None
}

/// The **single-best** founder badge — the broad tier, refined inside Genesis-50 to the finest
/// inner sub-bracket (first_10 / first_20 / first_30 / first_50). `None` if not a founder.
pub fn founder_badge(ordinal: u64, locked_at_ms: i64, genesis_ms: i64) -> Option<&'static str> {
    let tier = founder_tier(ordinal, locked_at_ms, genesis_ms)?;
    if tier == "genesis_50" {
        for (thresh, badge) in INNER {
            if ordinal <= thresh {
                return Some(badge);
            }
        }
    }
    Some(tier)
}

/// The ordinal assigned to the next lock-in = (count of prior `FOUNDER_LOCKIN` events) + 1
/// (spec §5.4.3 / caveat N4 — assigned at lock-in so reclaiming a provisional slot
/// renumbers nobody).
pub fn assign_ordinal(prior_lockin_count: u64) -> u64 {
    prior_lockin_count + 1
}

/// §5.4.2 lock-in eligibility: ≥ 30 days of operation AND currently healthy
/// (heartbeat-challenge-verified by the caller). `first_seen_ms` is the directory-observed
/// first-seen timestamp — NEVER the backdatable attested created_at.
pub fn is_lockin_eligible(first_seen_ms: i64, now_ms: i64, healthy: bool) -> bool {
    healthy && now_ms.saturating_sub(first_seen_ms) >= LOCKIN_MIN_AGE_MS
}

/// Decide a founder lock-in (§5.4.2 gate + §5.4.3 assignment). Returns the immutable assignment
/// to persist + emit as `FOUNDER_LOCKIN`, or `None` when not (yet) eligible or past the final
/// founder window. The lock-in timestamp is `now_ms` (directory-observed); tiers measured on it.
pub fn decide_lockin(
    first_seen_ms: i64,
    now_ms: i64,
    healthy: bool,
    prior_lockin_count: u64,
    genesis_ms: i64,
) -> Option<LockinAssignment> {
    if !is_lockin_eligible(first_seen_ms, now_ms, healthy) {
        return None;
    }
    let ordinal = assign_ordinal(prior_lockin_count);
    let tier = founder_tier(ordinal, now_ms, genesis_ms)?; // None → past final window, no mint
    Some(LockinAssignment {
        ordinal,
        tier,
        badge: founder_badge(ordinal, now_ms, genesis_ms).unwrap_or(tier),
        locked_at_ms: now_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: i64 = 0; // genesis at t=0 for readability
    fn day(n: i64) -> i64 {
        n * 24 * 60 * 60 * 1000
    }

    #[test]
    fn single_best_inner_brackets_within_genesis_50() {
        assert_eq!(founder_badge(1, day(1), G), Some("first_10"));
        assert_eq!(founder_badge(10, day(1), G), Some("first_10"));
        assert_eq!(founder_badge(11, day(1), G), Some("first_20"));
        assert_eq!(founder_badge(25, day(1), G), Some("first_30"));
        assert_eq!(founder_badge(45, day(1), G), Some("first_50"));
    }

    #[test]
    fn tier_requires_both_ordinal_and_window() {
        // ordinal 5 but locked at day 100 (> 3mo) → Genesis-50 window fails → Founders-500.
        assert_eq!(founder_badge(5, day(100), G), Some("founders_500"));
        // ordinal 51 within 6mo → Founders-500 (past the inner brackets).
        assert_eq!(founder_badge(51, day(1), G), Some("founders_500"));
        // ordinal 600 at day 200 (> 6mo, ≤ 12mo) → Founders-1000.
        assert_eq!(founder_badge(600, day(200), G), Some("founders_1000"));
    }

    #[test]
    fn outside_every_tier_is_none() {
        assert_eq!(founder_badge(1001, day(1), G), None); // over the 1000 cap
        assert_eq!(founder_badge(600, day(400), G), None); // > 12mo window
        assert_eq!(founder_badge(0, day(1), G), None); // no ordinal
    }

    #[test]
    fn window_boundaries_are_inclusive() {
        assert_eq!(founder_badge(50, 3 * MONTH_MS, G), Some("first_50")); // exactly 3mo
        assert_eq!(founder_badge(500, 6 * MONTH_MS, G), Some("founders_500"));
        assert_eq!(founder_badge(1000, 12 * MONTH_MS, G), Some("founders_1000"));
        assert_eq!(founder_badge(50, 3 * MONTH_MS + 1, G), Some("founders_500"));
        // 1ms over → next tier
    }

    #[test]
    fn ordinal_assigned_sequentially_at_lockin() {
        assert_eq!(assign_ordinal(0), 1);
        assert_eq!(assign_ordinal(49), 50);
        assert_eq!(assign_ordinal(999), 1000);
    }

    #[test]
    fn founder_tier_is_broad_not_single_best() {
        assert_eq!(founder_tier(5, day(1), G), Some("genesis_50"));
        assert_eq!(founder_badge(5, day(1), G), Some("first_10"));
        assert_eq!(founder_tier(60, day(1), G), Some("founders_500"));
    }

    #[test]
    fn lockin_eligibility_age_and_health_gate() {
        assert!(is_lockin_eligible(0, LOCKIN_MIN_AGE_MS, true)); // exactly 30 days
        assert!(!is_lockin_eligible(0, LOCKIN_MIN_AGE_MS - 1, true)); // 1ms short
        assert!(!is_lockin_eligible(0, LOCKIN_MIN_AGE_MS, false)); // unhealthy (uptime-primary)
    }

    #[test]
    fn decide_lockin_assigns_ordinal_tier_badge_when_eligible() {
        let d = decide_lockin(0, day(31), true, 0, G).unwrap();
        assert_eq!(d.ordinal, 1);
        assert_eq!(d.tier, "genesis_50");
        assert_eq!(d.badge, "first_10");
        assert_eq!(d.locked_at_ms, day(31));
    }

    #[test]
    fn decide_lockin_none_when_not_eligible_or_past_window() {
        assert_eq!(decide_lockin(0, day(10), true, 0, G), None); // only 10 days
        assert_eq!(decide_lockin(0, day(400), true, 0, G), None); // past 12mo window
    }
}

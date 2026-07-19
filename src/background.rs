// SPDX-License-Identifier: Apache-2.0
//! Background task loops — spawned at startup alongside the HTTP server.
//!
//! Each loop runs in its own tokio task and is driven by a `tokio::time::interval`.
//! Repository lifecycle loops take `Arc<dyn NodeRepository>`. The bounded
//! telemetry-retention loop takes a MySQL pool and is spawned only for the
//! persistent backend; in-memory mode has no retained telemetry to prune.

use std::sync::Arc;
use std::time::Duration;

use crate::repo::NodeRepository;
use sqlx::{MySql, Pool};

/// ProbeNodes: actively probe each registered node's endpoint (#373 Phase B).
///
/// Fires every 5 minutes. For each available node, attempts a TCP connection to the
/// advertised endpoint (SSRF-guarded). Records the pass/fail result in
/// iicp_telemetry_probes so NodeHealthService::reachabilityScore() can use an
/// independently-observed signal instead of the node's self-attested `public_reachable`.
///
/// SSRF guard: RFC1918/loopback/link-local hosts are skipped (no probe recorded —
/// a false negative must not drive reachabilityScore down; PHP parity 2026-06-11).
/// IPv6-literal endpoints are skipped unless `IICP_PROBE_IPV6_EGRESS=1` — an origin
/// without IPv6 egress can never reach them, so probing only records false negatives.
/// TCP timeout: 5 seconds. Mirrors PHP `iicp:probe-nodes` Artisan command.
pub async fn run_probe_nodes_loop(repo: Arc<dyn NodeRepository>) {
    let ipv6_egress = std::env::var("IICP_PROBE_IPV6_EGRESS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    interval.tick().await; // skip first tick at startup
    loop {
        interval.tick().await;
        let nodes = repo.get_probeable_nodes(50).await;
        let mut count = 0u32;
        for (node_id, endpoint) in nodes {
            if !should_probe(&extract_host(&endpoint), ipv6_egress) {
                continue;
            }
            let (reachable, _latency_ms) = tcp_probe(&endpoint).await;
            repo.record_probe_result(&node_id, reachable, "DIR-PROBE-NODE-01")
                .await;
            count += 1;
        }
        if count > 0 {
            eprintln!("[probe_nodes] probed {count} node endpoint(s)");
        }
    }
}

/// Pure gate for the probe loop: false for private/loopback hosts (SSRF +
/// no-false-negative guard) and for IPv6-literal hosts when the origin has no
/// IPv6 egress. Extracted for unit testing (no DB harness in this repo).
pub fn should_probe(host: &str, ipv6_egress: bool) -> bool {
    if is_private_host(host) {
        return false;
    }
    // extract_host strips brackets, so any remaining ':' means an IPv6 literal.
    if host.contains(':') && !ipv6_egress {
        return false;
    }
    true
}

/// TCP-connect probe with SSRF guard and 5-second timeout.
/// Returns (reachable, latency_ms).
async fn tcp_probe(endpoint: &str) -> (bool, Option<u64>) {
    let host = extract_host(endpoint);
    if is_private_host(&host) {
        return (false, None);
    }
    let port = extract_port(endpoint);
    let addr = format!("{host}:{port}");
    let start = std::time::Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => (true, Some(start.elapsed().as_millis() as u64)),
        _ => (false, None),
    }
}

fn extract_host(url: &str) -> String {
    let after = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_port = after.split('/').next().unwrap_or("");
    // handle IPv6 brackets
    if let Some(inner) = host_port.strip_prefix('[') {
        inner.split(']').next().unwrap_or("").to_string()
    } else {
        host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port)
            .to_string()
    }
}

fn extract_port(url: &str) -> u16 {
    if url.starts_with("https://") {
        443
    } else {
        80
    }
}

const PRIVATE_PREFIXES: &[&str] = &[
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "169.254.",
];

fn is_private_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if h.is_empty() || h == "localhost" || h == "::1" {
        return true;
    }
    PRIVATE_PREFIXES.iter().any(|p| h.starts_with(p))
}

/// PruneHeartbeatEvents: delete HEARTBEAT events older than the configured
/// one-day default (PHP target-operation parity).
///
/// Fires daily. Without this, node_events grows unboundedly on active meshes.
pub async fn run_prune_heartbeat_loop(repo: Arc<dyn NodeRepository>) {
    let policy = crate::maintenance::RetentionPolicy::from_env();
    let mut interval = tokio::time::interval(Duration::from_secs(86_400));
    interval.tick().await;
    loop {
        interval.tick().await;
        let pruned = repo
            .prune_heartbeat_events(policy.heartbeat_event_days)
            .await;
        if pruned > 0 {
            eprintln!("[prune_heartbeat] deleted {pruned} stale HEARTBEAT event(s)");
        }
    }
}

/// Apply the same bounded telemetry-retention policy as the PHP scheduler.
/// The first tick is skipped, and each table deletes at most 5,000 rows per
/// daily pass. Failures are logged and retried on the next scheduled pass.
pub async fn run_prune_telemetry_loop(pool: Pool<MySql>) {
    let policy = crate::maintenance::RetentionPolicy::from_env();
    let mut interval = tokio::time::interval(Duration::from_secs(86_400));
    interval.tick().await;
    loop {
        interval.tick().await;
        match crate::maintenance::prune_telemetry(
            &pool,
            policy,
            crate::maintenance::DEFAULT_BATCH_SIZE,
            crate::maintenance::DEFAULT_MAX_BATCHES,
            true,
        )
        .await
        {
            Ok(report) => {
                let deleted: u64 = report.tables.iter().map(|table| table.deleted).sum();
                if deleted > 0 {
                    eprintln!("[prune_telemetry] deleted {deleted} expired telemetry row(s)");
                }
            }
            Err(error) => eprintln!("[prune_telemetry] pass failed: {error}"),
        }
    }
}

/// NodeLifecycle: archive dormant nodes older than 90 days.
///
/// Fires daily (86400s). Mirrors PHP `NodeLifecycleCommand` — transitions
/// status='dormant' nodes where dormant_since > 90 days to status='archived'.
/// Keeps the nodes table from accumulating indefinitely stale rows.
pub async fn run_node_lifecycle_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(86_400));
    interval.tick().await; // skip first tick
    loop {
        interval.tick().await;
        let archived = repo.archive_dormant(90).await;
        if archived > 0 {
            eprintln!("[node_lifecycle] archived {archived} dormant node(s)");
        }
    }
}

/// ExpireCredits: the 90-day TTL credit sink (WQ-056 / billing §11.3 / ADR-035).
///
/// Fires daily (86400s). Mirrors PHP `iicp:expire-credits` — sweeps idle nodes (newest
/// earn past its 90-day TTL with a positive balance), zeroing the unspent balance and
/// writing one `ttl_expire` debit per node. The PRIMARY anti-inflation sink; complements
/// the 2% transaction burn. Idempotent — a swept node is at zero, a fresh earn resets TTL.
pub async fn run_expire_credits_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(86_400));
    interval.tick().await; // skip first tick at startup
    loop {
        interval.tick().await;
        let (nodes, credits) = repo.expire_idle_node_credits().await;
        if nodes > 0 {
            eprintln!("[expire_credits] swept {nodes} idle node(s); {credits:.4} credits to sink");
        }
    }
}

/// ReputationDecay: apply hourly -0.005 decay to all nodes above score 0.30.
///
/// Fires every 3600 seconds. Mirrors the PHP `ReputationDecayCommand` Artisan job.
/// Without this, nodes accumulate artificially high scores since positive heartbeat
/// deltas are not offset by a time-based floor pull.
///
/// Spec reference: iicp-semantics §11 decay rule.
pub async fn run_reputation_decay_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    interval.tick().await; // skip first tick at startup
    loop {
        interval.tick().await;
        let decayed = repo.decay_reputation_pass().await;
        if decayed > 0 {
            eprintln!("[reputation_decay] applied decay to {decayed} node(s)");
        }
    }
}

/// RotateReputationWindow: snapshot and reset the 90-day rolling reputation window.
///
/// Fires daily (86400s). Mirrors PHP `RotateReputationWindowCommand` — snapshots
/// `tasks_total_recent / tasks_failed_recent / avg_latency_ms_recent` into the
/// previous-window columns, then resets the counters and advances `recent_window_start`.
/// This ensures the NodeScorer always has a clean 90-day window to score against.
pub async fn run_rotate_reputation_window_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(86_400));
    interval.tick().await; // skip first tick
    loop {
        interval.tick().await;
        let rotated = repo.rotate_reputation_windows().await;
        if rotated > 0 {
            eprintln!("[rotate_rep_window] rotated {rotated} node(s)");
        }
    }
}

/// ExpireStaleNodes: mark nodes unavailable when their heartbeat window expires.
///
/// Fires every 60 seconds. Sets `available=false, status='dormant'` for any node
/// whose `last_seen` is older than 90 seconds. This is the counterpart to the
/// heartbeat liveness update — without it, dead nodes accumulate in discover results.
///
/// Emits one EVICT event per expired node (#508 uptime tracking parity with PHP).
///
/// PHP equivalent: `ExpireStaleNodes` Artisan command scheduled via `php artisan schedule:run`.
pub async fn run_expire_nodes_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    // Skip the first tick (fires immediately at startup — all nodes are brand-new).
    interval.tick().await;
    loop {
        interval.tick().await;
        let expired_ids = repo.expire_stale().await;
        let count = expired_ids.len();
        if count > 0 {
            eprintln!("[expire_stale] marked {count} node(s) dormant");
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            for node_id in &expired_ids {
                let payload =
                    format!(r#"{{"reason":"heartbeat_expiry","dormant_since_ms":{now_ms}}}"#);
                repo.log_event(node_id, "EVICT", &payload).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Behavior test (2026-06-11): IPv6-literal endpoints must be skipped when
    /// the origin has no IPv6 egress — probing them only records false negatives.
    #[test]
    fn ipv6_literal_skipped_without_egress() {
        let host = extract_host("http://[2a0a:a543:df54:0:888:9777:7743:8ae]:9484");
        assert!(!should_probe(&host, false));
        assert!(should_probe(&host, true));
    }

    /// Private/loopback hosts are never probed (SSRF + no-false-negative guard),
    /// regardless of the IPv6-egress flag.
    #[test]
    fn private_hosts_never_probed() {
        for ep in [
            "http://192.168.1.50:8090",
            "http://127.0.0.1:9484",
            "http://[::1]:9484",
            "http://localhost:9484",
        ] {
            let host = extract_host(ep);
            assert!(!should_probe(&host, false), "{ep} must be skipped");
            assert!(
                !should_probe(&host, true),
                "{ep} must be skipped even with egress"
            );
        }
    }

    /// Public IPv4/hostname endpoints are probed in both egress modes.
    #[test]
    fn public_hosts_probed() {
        for ep in ["https://iicp.shaal.dev", "http://203.0.113.10:9484"] {
            let host = extract_host(ep);
            assert!(should_probe(&host, false), "{ep} must be probed");
        }
    }
}

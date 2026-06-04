// SPDX-License-Identifier: Apache-2.0
//! Background task loops — spawned at startup alongside the HTTP server.
//!
//! Each loop runs in its own tokio task and is driven by a `tokio::time::interval`.
//! They all take `Arc<dyn NodeRepository>` so they work with any repo backend (the
//! MySQL-backed impl does real DB work; InMemoryRepo impls are no-ops).

use std::sync::Arc;
use std::time::Duration;

use crate::repo::NodeRepository;

/// ProbeNodes: actively probe each registered node's endpoint (#373 Phase B).
///
/// Fires every 5 minutes. For each available node, attempts a TCP connection to the
/// advertised endpoint (SSRF-guarded). Records the pass/fail result in
/// iicp_telemetry_probes so NodeHealthService::reachabilityScore() can use an
/// independently-observed signal instead of the node's self-attested `public_reachable`.
///
/// SSRF guard: RFC1918/loopback/link-local hosts are skipped (recorded as failed).
/// TCP timeout: 5 seconds. Mirrors PHP `iicp:probe-nodes` Artisan command.
pub async fn run_probe_nodes_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    interval.tick().await; // skip first tick at startup
    loop {
        interval.tick().await;
        let nodes = repo.get_probeable_nodes(50).await;
        let mut count = 0u32;
        for (node_id, endpoint) in nodes {
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

/// PruneHeartbeatEvents: delete HEARTBEAT events older than 7 days (db-D4prime retention).
///
/// Fires weekly (604800s). Without this, node_events grows unboundedly on active meshes.
pub async fn run_prune_heartbeat_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(604_800));
    interval.tick().await;
    loop {
        interval.tick().await;
        let pruned = repo.prune_heartbeat_events(7).await;
        if pruned > 0 {
            eprintln!("[prune_heartbeat] deleted {pruned} stale HEARTBEAT event(s)");
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
/// PHP equivalent: `ExpireStaleNodes` Artisan command scheduled via `php artisan schedule:run`.
pub async fn run_expire_nodes_loop(repo: Arc<dyn NodeRepository>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    // Skip the first tick (fires immediately at startup — all nodes are brand-new).
    interval.tick().await;
    loop {
        interval.tick().await;
        let expired = repo.expire_stale().await;
        if expired > 0 {
            eprintln!("[expire_stale] marked {expired} node(s) dormant");
        }
    }
}

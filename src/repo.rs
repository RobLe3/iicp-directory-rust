// SPDX-License-Identifier: Apache-2.0
//! Node repository abstraction for the directory read path.
//!
//! The discover/scoring logic depends only on this trait, so the MySQL-backed
//! implementation (M2 wiring) can drop in without touching the HTTP layer. An
//! in-memory implementation backs the tests and local runs today.

use crate::types::Node;
use async_trait::async_trait;
use std::cmp::Reverse;

/// A node plus the intent URNs it serves (the `capabilities[].intent` set).
#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub node: Node,
    pub intents: Vec<String>,
    /// Plain token issued to the caller. The repository SHOULD hash this at rest;
    /// InMemoryRepo ignores it (no token auth in local/test mode).
    pub node_token: Option<String>,
    /// HMAC secret for CIP credit receipt verification (W-009). Generated at registration,
    /// returned to the node, stored plaintext (it is a shared secret, not a credential).
    pub node_hmac_key: Option<String>,
    /// Separate proxy_token for ProxyTokenAuth (POST /v1/telemetry). Bcrypt-hashed at rest.
    /// PHP NodeRegistry issues this alongside node_token on every registration.
    pub proxy_token: Option<String>,
}

/// Discovery query parameters (iicp-dir §3.3).
#[derive(Debug, Default, Clone)]
pub struct DiscoverQuery {
    pub intent: String,
    /// Region preference (not an exclusion). Captured from the query for a future
    /// region-boost scoring pass; intentionally not used as a filter yet (iicp-dir §3.3).
    #[allow(dead_code)]
    pub region: Option<String>,
    pub limit: usize,
    pub min_reputation: Option<f64>,
}

#[async_trait]
pub trait NodeRepository: Send + Sync {
    /// Return scored, filtered nodes for a discovery query (iicp-dir §3.3/§3.4).
    /// Excludes unavailable nodes and nodes below score 0.1, sorts by score desc,
    /// truncates to `limit` (default 10, max 50).
    async fn discover(&self, q: &DiscoverQuery) -> Vec<Node>;

    /// Persist a registration (iicp-dir §3.1). Re-registering an existing `node_id`
    /// replaces the record (idempotent recovery), preserving its reputation_score.
    async fn register(&self, rec: NodeRecord);

    /// Apply a heartbeat (iicp-dir §3.2): update load/available, add `delta` to the
    /// node's reputation_score (clamped 0..1), return the new score. `None` if unknown.
    #[allow(clippy::too_many_arguments)] // heartbeat carries the full per-tick node state
    async fn heartbeat(
        &self,
        node_id: &str,
        load: f64,
        available: bool,
        active_jobs: u32,
        tasks_delta: u32,
        // #385 Phase-B / AL3 — failure count from the SDK heartbeat metrics,
        // persisted to the tasks_failed column so a real success ratio can be
        // computed (was previously folded into tasks_delta and dropped).
        tasks_failed_delta: u32,
        delta: f64,
    ) -> Option<f64>;

    /// Fetch a single node by id for the node-detail endpoint (iicp-dir §3.4.x). `None` if unknown.
    async fn get(&self, node_id: &str) -> Option<Node>;

    /// Count of nodes that are available and within the 90-second liveness window.
    /// Used by `/v1/stats`. InMemoryRepo counts all available records (no timestamp).
    async fn active_count(&self) -> u32;

    /// The full active provider set (available + heartbeat-fresh) for the
    /// `/v1/stats` `mesh_health` aggregate (ADR-044). Unlike `bootstrap`, returns
    /// every qualifying node (no limit) so the median/distribution is over the
    /// whole serving mesh, not a truncated peek.
    async fn active_nodes(&self) -> Vec<Node>;

    /// Return recently-seen active nodes for `/v1/bootstrap` (iicp-dir §3.7).
    /// No intent filter — any available node qualifies. Sorted by last_seen desc.
    async fn bootstrap(&self, limit: usize) -> Vec<Node>;

    /// Remove a node from the directory (iicp-dir §3.6 deregister). Returns true if found.
    async fn deregister(&self, node_id: &str) -> bool;

    /// Verify that `token` is valid for `node_id`. InMemoryRepo always returns true
    /// (no token validation in local/test mode). MySqlRepo compares against node_token_hash.
    /// Phase 4 upgrades this to bcrypt::verify once the hash function is changed.
    async fn verify_node_token(&self, node_id: &str, token: &str) -> bool;

    /// Return active peers not in `known_ids` for the PEER_EXCHANGE endpoint (iicp-dir §3.5).
    /// `limit` is capped at 20; default 10. InMemoryRepo returns all available nodes
    /// not in `known_ids` (no timestamp filter in local mode).
    async fn peers_excluding(&self, known_ids: &[String], limit: usize) -> Vec<Node>;

    /// Mark nodes as unavailable when their last_seen timestamp is older than the 90-second
    /// liveness window. Called by the ExpireStaleNodes background task (every 60s).
    /// InMemoryRepo is a no-op (no timestamps in local mode).
    /// Returns the count of nodes marked unavailable.
    async fn expire_stale(&self) -> u32;

    /// Apply one hourly reputation decay pass (iicp-semantics §11 decay rule: -0.005/hr,
    /// floor 0.30). Called by the ReputationDecay background task (every 3600s).
    /// InMemoryRepo applies the decay in-memory; MySqlRepo uses a single UPDATE.
    /// Returns the count of nodes whose score was updated.
    async fn decay_reputation_pass(&self) -> u32;

    /// Public node listing for `/v1/registry/nodes` (ADR-017, iicp-dir §3.10a).
    /// Returns sanitised node records — NO endpoint or token hash exposed.
    /// `offset`/`limit` are for pagination; limit capped at 100.
    async fn list_public(&self, offset: u64, limit: usize) -> Vec<Node>;

    /// Aggregate counts for `/v1/registry/stats` (iicp-dir §3.10b).
    async fn registry_stats(&self) -> RegistryStats;

    /// List distinct intents with active node counts for `/v1/registry/intents`.
    async fn list_intents(&self) -> Vec<IntentSummary>;

    /// Credit balance for a node (iicp-dir §6.1). Returns None if node unknown.
    async fn credit_balance(&self, node_id: &str) -> Option<f64>;

    /// Archive dormant nodes older than `days_threshold` days and return count.
    /// PHP equivalent: NodeLifecycleCommand — transitions status → 'archived', sets
    /// dormant_since. InMemoryRepo is a no-op (no timestamps).
    async fn archive_dormant(&self, days_threshold: u32) -> u32;

    /// Fetch the node's HMAC key for credit receipt verification (W-009, iicp-dir §6.2).
    async fn node_hmac_key(&self, node_id: &str) -> Option<String>;

    /// Check whether a nonce has already been used (replay prevention, RT-02).
    /// InMemoryRepo always returns false (no nonce table in local mode).
    #[allow(dead_code)]
    async fn is_nonce_used(&self, nonce: &str) -> bool;

    /// Persist an awarded credit transaction and increment the node's balance.
    /// Returns the new balance on success, Err if the nonce is already used.
    async fn record_credit_award(
        &self,
        node_id: &str,
        amount: f64,
        task_id: &str,
        nonce: &str,
    ) -> Result<f64, CreditError>;

    /// Paginated credit transaction history for a node (iicp-dir §6.3).
    async fn credit_transactions(
        &self,
        node_id: &str,
        offset: u64,
        limit: usize,
    ) -> Vec<CreditTransaction>;

    /// Apply an audit-report delta to a target node's reputation_score (RT-05).
    /// Returns (applied: bool, new_score: f64, reason: &str).
    /// The delta is capped at MAX_REPORTERS_PER_TARGET_PER_DAY distinct reporters per 24h.
    async fn apply_audit_report(
        &self,
        target_node_id: &str,
        reporter_node_id: &str,
        finding: &str,
    ) -> AuditResult;

    /// Verify a probe token (SHA-256 hash lookup in probe_tokens table).
    /// InMemoryRepo always returns true (no probe token table in test mode).
    async fn verify_probe_token(&self, token_sha256_hex: &str) -> bool;

    /// Bulk-insert telemetry probe results and touch last_seen_at on the token.
    /// Returns the count of probes stored.
    async fn record_probe_batch(&self, token_sha256_hex: &str, probes: &[ProbeResult]) -> u32;

    /// Credit pricing quote for a discover-like intent query (iicp-dir §6.4).
    /// Returns the estimated cost per 1000 tokens (credit_cost_multiplier average).
    async fn credit_quote(&self, intent: &str) -> f64;

    /// Maybe allocate free credits (6h gate, iicp-dir §6.5).
    /// Two-tier gate: per node_id AND per source IP (RT-02b, #380).
    /// Awards FREE_CREDIT_AMOUNT (100) if both gates pass.
    /// Returns the amount awarded (0 if either gate blocks).
    async fn maybe_allocate_free_credits(&self, node_id: &str, ip: &str) -> f64;

    /// Prune old HEARTBEAT events to prevent unbounded growth (db-D4prime retention policy).
    /// Deletes HEARTBEAT events older than `retain_days`. Called weekly by background task.
    async fn prune_heartbeat_events(&self, retain_days: u32) -> u32;

    /// Rotate the 90-day rolling reputation window (RotateReputationWindowCommand).
    /// Snapshots tasks_total_recent/tasks_failed_recent/avg_latency_ms_recent to reputation_archive
    /// for nodes where recent_window_start < NOW() - 90 days, then resets the rolling counters.
    /// Returns the count of nodes rotated.
    async fn rotate_reputation_windows(&self) -> u32;

    /// Record the observed source IP for a node (NodeAddressObserver).
    /// InMemoryRepo is a no-op. MySqlRepo appends to node_address_history.
    async fn observe_address(&self, node_id: &str, ip: &str, request_type: &str);

    /// Return the most recently observed source IP for a node from node_address_history.
    /// Used by GET /v1/me to echo what the directory last saw (DIR-ADDR-08).
    async fn get_observed_ip(&self, node_id: &str) -> Option<String>;

    /// Update the credit cost multiplier and pricing model for a node (ADR-019).
    /// Called from the heartbeat handler when a `pricing` block is present.
    async fn update_pricing(&self, node_id: &str, multiplier: f64, model: Option<&str>);

    /// Append a structured event to node_events (NodeEventLogger parity).
    /// Used for DEREGISTER, REPUTATION_UPDATE, etc. to support Phase 6 federation.
    async fn log_event(&self, node_id: &str, event_type: &str, payload: &str);

    /// Return the probed_at timestamp of the most recent telemetry probe.
    /// Used by /v1/stats probes.last_probe_at (website + DG6).
    async fn last_probe_at(&self) -> Option<String>;

    /// Return (node_id, endpoint) pairs for available nodes to actively probe.
    /// Used by the ProbeNodes background task (#373 Phase B).
    /// Returns up to `limit` nodes sorted by last_seen descending.
    async fn get_probeable_nodes(&self, limit: u32) -> Vec<(String, String)>;

    /// Record a directory-internal reachability probe result in iicp_telemetry_probes.
    /// `passed` = TCP/HTTP connection succeeded. `test_id` = "DIR-PROBE-NODE-01".
    async fn record_probe_result(&self, node_id: &str, passed: bool, test_id: &str);

    /// Verify a proxy token (bearer + proxy_node_id → bcrypt verify against proxy_token_hash).
    /// InMemoryRepo: always true (no proxy auth in test mode).
    async fn verify_proxy_token(&self, proxy_node_id: &str, token: &str) -> bool;

    /// Record a proxy telemetry observation. Returns distinct proxy count for the target
    /// node in the last 7 days (used by the Sybil quorum check: need ≥3 for EMA update).
    /// Returns (accepted, quorum): accepted=false on duplicate (same proxy+node+60s bucket).
    async fn record_proxy_telemetry(&self, obs: &ProxyObservation) -> (bool, u32);

    /// List conformance badges (all or filtered by tier/status).
    async fn list_badges(&self, tier: Option<&str>) -> Vec<ConformanceBadge>;

    /// Submit a conformance evaluation request. Returns the new badge_id.
    async fn submit_conformance(&self, tier: &str, subject_did: Option<&str>) -> String;

    /// Get conformance status for a tier. Returns None if no badge exists.
    async fn get_badge(&self, tier: &str) -> Option<ConformanceBadge>;
}

/// A conformance badge record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConformanceBadge {
    pub badge_id: String,
    pub tier: String,
    pub status: String,
    pub subject_did: Option<String>,
    pub suite_version: String,
    pub passed_at: Option<String>,
    pub expires_at: Option<String>,
    pub test_results_url: Option<String>,
}

/// A proxy telemetry observation submitted via `POST /v1/telemetry`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProxyObservation {
    pub node_id: String,
    pub proxy_node_id: String,
    #[serde(default)]
    pub latency_ms_observed: Option<u32>,
    #[serde(default)]
    pub tokens_observed: Option<u32>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub qos_advertised: Option<f32>,
    #[serde(default)]
    pub qos_met: Option<bool>,
}

/// A single probe result from a REACH run.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProbeResult {
    pub probe_id: String,
    pub probe_type: String,
    #[serde(default)]
    pub test_id: Option<String>,
    #[serde(default)]
    pub level: String,
    pub passed: bool,
    #[serde(default)]
    pub latency_ms: Option<u32>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub probed_at: Option<String>,
}

/// A credit ledger entry returned by `/v1/credits/transactions`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CreditTransaction {
    pub id: u64,
    pub amount: f64,
    #[serde(rename = "type")]
    pub tx_type: String,
    pub task_id: Option<String>,
    pub reason: Option<String>,
    pub created_at: String,
}

/// Result of applying an audit report.
#[derive(Debug, Clone)]
pub struct AuditResult {
    pub applied: bool,
    #[allow(dead_code)] // reserved for debug logging; not in HTTP response (PHP parity)
    pub new_score: f64,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub enum CreditError {
    NonceReplay,
    NodeNotFound,
    DbError,
}

/// Intent summary entry for `/v1/registry/intents`.
/// PHP returns `urn` (not `intent`) — PHP parity.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntentSummary {
    #[serde(rename = "urn")]
    pub intent: String,
    pub node_count: u32,
}

/// Aggregate statistics returned by `/v1/registry/stats`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RegistryStats {
    pub total_nodes: u64,
    pub active_nodes: u64,
    /// Active node regions, ordered by count desc (PHP buildStats `regions`).
    pub regions: Vec<String>,
    /// Region → active node count (PHP `region_breakdown`).
    pub region_breakdown: std::collections::HashMap<String, u32>,
    /// Intent URN → active node count (PHP `intent_coverage`).
    pub intent_coverage: std::collections::HashMap<String, u32>,
    /// Intent URNs with ≥1 active node, ordered by count desc (PHP `intents_supported`).
    pub intents_supported: Vec<String>,
}

/// In-memory repository — backs tests and local runs until the MySQL layer lands.
/// Read-write via a Mutex so the register→discover→heartbeat lifecycle is consistent;
/// the MySQL-backed impl drops in behind the same trait.
#[derive(Debug, Default)]
pub struct InMemoryRepo {
    records: std::sync::Mutex<Vec<NodeRecord>>,
}

impl InMemoryRepo {
    // Test/local constructor; the production constructor is the MySQL-backed repo.
    #[allow(dead_code)]
    pub fn new(records: Vec<NodeRecord>) -> Self {
        Self {
            records: std::sync::Mutex::new(records),
        }
    }
}

const MIN_SCORE: f64 = 0.1; // iicp-semantics §3.3
const DEFAULT_LIMIT: usize = 10; // iicp-dir §3.3
const MAX_LIMIT: usize = 50; // iicp-dir §3.3

#[async_trait]
impl NodeRepository for InMemoryRepo {
    async fn discover(&self, q: &DiscoverQuery) -> Vec<Node> {
        let limit = match q.limit {
            0 => DEFAULT_LIMIT,
            n if n > MAX_LIMIT => MAX_LIMIT,
            n => n,
        };
        let guard = self.records.lock().unwrap();
        let mut matched: Vec<Node> = guard
            .iter()
            .filter(|r| r.intents.iter().any(|i| i == &q.intent))
            .filter(|r| r.node.available)
            .filter(|r| r.node.score >= MIN_SCORE)
            .filter(|r| {
                q.min_reputation
                    .is_none_or(|m| r.node.reputation_score >= m)
            })
            // NOTE: region is a preference, not an exclusion (iicp-dir §3.3) — no filter.
            // A future scoring pass may boost region matches; it must not drop non-matches.
            .map(|r| r.node.clone())
            .collect();

        // Sort by score descending; stable so equal scores keep insertion order.
        matched.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        matched.truncate(limit);
        matched
    }

    async fn register(&self, rec: NodeRecord) {
        let mut guard = self.records.lock().unwrap();
        if let Some(existing) = guard
            .iter_mut()
            .find(|r| r.node.node_id == rec.node.node_id)
        {
            // Re-registration: preserve reputation history (anti-laundering, ADR-026), refresh the rest.
            let preserved = existing.node.reputation_score;
            *existing = rec;
            existing.node.reputation_score = preserved;
        } else {
            guard.push(rec);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn heartbeat(
        &self,
        node_id: &str,
        load: f64,
        available: bool,
        active_jobs: u32,
        tasks_delta: u32,
        tasks_failed_delta: u32,
        delta: f64,
    ) -> Option<f64> {
        let mut guard = self.records.lock().unwrap();
        let rec = guard.iter_mut().find(|r| r.node.node_id == node_id)?;
        rec.node.load = load;
        rec.node.available = available;
        rec.node.active_jobs = active_jobs;
        rec.node.completed_tasks_count += tasks_delta as u64;
        rec.node.tasks_failed += tasks_failed_delta as u64;
        rec.node.reputation_score =
            crate::reputation::apply_delta(rec.node.reputation_score, delta);
        Some(rec.node.reputation_score)
    }

    async fn get(&self, node_id: &str) -> Option<Node> {
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .find(|r| r.node.node_id == node_id)
            .map(|r| r.node.clone())
    }

    async fn active_count(&self) -> u32 {
        let guard = self.records.lock().unwrap();
        guard.iter().filter(|r| r.node.available).count() as u32
    }

    async fn active_nodes(&self) -> Vec<Node> {
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .filter(|r| r.node.available)
            .map(|r| r.node.clone())
            .collect()
    }

    async fn bootstrap(&self, limit: usize) -> Vec<Node> {
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .filter(|r| r.node.available)
            .take(limit)
            .map(|r| r.node.clone())
            .collect()
    }

    async fn deregister(&self, node_id: &str) -> bool {
        let mut guard = self.records.lock().unwrap();
        let before = guard.len();
        guard.retain(|r| r.node.node_id != node_id);
        guard.len() < before
    }

    /// InMemoryRepo: skip token validation — all tokens accepted in local/test mode.
    async fn verify_node_token(&self, _node_id: &str, _token: &str) -> bool {
        true
    }

    async fn peers_excluding(&self, known_ids: &[String], limit: usize) -> Vec<Node> {
        let cap = match limit {
            0 => 10,
            n if n > 20 => 20,
            n => n,
        };
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .filter(|r| r.node.available && !known_ids.contains(&r.node.node_id))
            .take(cap)
            .map(|r| r.node.clone())
            .collect()
    }

    /// InMemoryRepo has no timestamps — no-op.
    async fn expire_stale(&self) -> u32 {
        0
    }

    async fn decay_reputation_pass(&self) -> u32 {
        const FLOOR: f64 = 0.30;
        const DECAY: f64 = 0.005;
        let mut guard = self.records.lock().unwrap();
        let mut count = 0u32;
        for rec in guard.iter_mut() {
            if rec.node.reputation_score > FLOOR {
                rec.node.reputation_score = (rec.node.reputation_score - DECAY).max(FLOOR);
                count += 1;
            }
        }
        count
    }

    async fn list_public(&self, offset: u64, limit: usize) -> Vec<Node> {
        let cap = limit.min(100);
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .skip(offset as usize)
            .take(cap)
            .map(|r| {
                // Strip sensitive fields — public listing shows only identity + reputation.
                let mut n = r.node.clone();
                n.endpoint = String::new(); // not exposed in public registry
                n
            })
            .collect()
    }

    async fn registry_stats(&self) -> RegistryStats {
        use std::collections::HashMap;
        let guard = self.records.lock().unwrap();
        let total = guard.len() as u64;
        let active = guard.iter().filter(|r| r.node.available).count() as u64;

        // Region + intent breakdowns over active nodes (PHP buildStats parity).
        let mut region_breakdown: HashMap<String, u32> = HashMap::new();
        let mut intent_coverage: HashMap<String, u32> = HashMap::new();
        for rec in guard.iter().filter(|r| r.node.available) {
            *region_breakdown.entry(rec.node.region.clone()).or_default() += 1;
            for intent in &rec.intents {
                *intent_coverage.entry(intent.clone()).or_default() += 1;
            }
        }
        // PHP orders keys by COUNT(*) DESC — mirror that for the array fields.
        let sort_by_count_desc = |map: &HashMap<String, u32>| -> Vec<String> {
            let mut pairs: Vec<_> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            pairs.into_iter().map(|(k, _)| k).collect()
        };
        let regions = sort_by_count_desc(&region_breakdown);
        let intents_supported = sort_by_count_desc(&intent_coverage);

        RegistryStats {
            total_nodes: total,
            active_nodes: active,
            regions,
            region_breakdown,
            intent_coverage,
            intents_supported,
        }
    }

    async fn list_intents(&self) -> Vec<IntentSummary> {
        let guard = self.records.lock().unwrap();
        let mut counts: std::collections::HashMap<String, u32> = Default::default();
        for rec in guard.iter().filter(|r| r.node.available) {
            for intent in &rec.intents {
                *counts.entry(intent.clone()).or_default() += 1;
            }
        }
        let mut result: Vec<IntentSummary> = counts
            .into_iter()
            .map(|(intent, node_count)| IntentSummary { intent, node_count })
            .collect();
        result.sort_by_key(|s| Reverse(s.node_count));
        result
    }

    async fn credit_balance(&self, node_id: &str) -> Option<f64> {
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .find(|r| r.node.node_id == node_id)
            .map(|_| 0.0_f64) // InMemoryRepo has no credit ledger
    }

    async fn archive_dormant(&self, _days_threshold: u32) -> u32 {
        0 // InMemoryRepo has no timestamps
    }

    async fn node_hmac_key(&self, node_id: &str) -> Option<String> {
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .find(|r| r.node.node_id == node_id)
            .and_then(|r| r.node_hmac_key.clone())
    }

    /// InMemoryRepo: no nonce tracking — always returns false (no replay detection in test mode).
    async fn is_nonce_used(&self, _nonce: &str) -> bool {
        false
    }

    async fn record_credit_award(
        &self,
        node_id: &str,
        amount: f64,
        _task_id: &str,
        _nonce: &str,
    ) -> Result<f64, CreditError> {
        let guard = self.records.lock().unwrap();
        if guard.iter().any(|r| r.node.node_id == node_id) {
            Ok(amount)
        } else {
            Err(CreditError::NodeNotFound)
        }
    }

    async fn credit_transactions(
        &self,
        _node_id: &str,
        _offset: u64,
        _limit: usize,
    ) -> Vec<CreditTransaction> {
        vec![] // InMemoryRepo has no ledger
    }

    async fn verify_probe_token(&self, _token_sha256_hex: &str) -> bool {
        true // InMemoryRepo: no probe token table in test mode
    }

    async fn record_probe_batch(&self, _token_sha256_hex: &str, probes: &[ProbeResult]) -> u32 {
        probes.len() as u32 // InMemoryRepo: no telemetry table; count only
    }

    async fn credit_quote(&self, _intent: &str) -> f64 {
        1.0 // InMemoryRepo: static default quote
    }

    async fn maybe_allocate_free_credits(&self, node_id: &str, _ip: &str) -> f64 {
        let guard = self.records.lock().unwrap();
        if guard.iter().any(|r| r.node.node_id == node_id) {
            100.0
        } else {
            0.0
        }
    }

    async fn prune_heartbeat_events(&self, _retain_days: u32) -> u32 {
        0 // InMemoryRepo: no node_events table
    }

    async fn rotate_reputation_windows(&self) -> u32 {
        // InMemoryRepo: reset rolling counters for all records (no window_start tracking).
        0 // No-op in test mode — timestamp-based window logic requires DB
    }

    async fn observe_address(&self, _node_id: &str, _ip: &str, _request_type: &str) {
        // InMemoryRepo: no-op — no address history in test mode
    }

    async fn get_observed_ip(&self, _node_id: &str) -> Option<String> {
        None // InMemoryRepo: no address history in test mode
    }

    async fn update_pricing(&self, _node_id: &str, _multiplier: f64, _model: Option<&str>) {
        // InMemoryRepo: no-op — pricing not persisted in test mode
    }

    async fn log_event(&self, _node_id: &str, _event_type: &str, _payload: &str) {
        // InMemoryRepo: no-op — no event log in test mode
    }

    async fn last_probe_at(&self) -> Option<String> {
        None // InMemoryRepo: no probe history in test mode
    }

    async fn get_probeable_nodes(&self, _limit: u32) -> Vec<(String, String)> {
        vec![] // InMemoryRepo: no-op — active probing not available in test mode
    }

    async fn record_probe_result(&self, _node_id: &str, _passed: bool, _test_id: &str) {
        // InMemoryRepo: no-op — no telemetry_probes table in test mode
    }

    async fn verify_proxy_token(&self, _proxy_node_id: &str, _token: &str) -> bool {
        true // InMemoryRepo: no proxy auth in test mode
    }

    async fn record_proxy_telemetry(&self, _obs: &ProxyObservation) -> (bool, u32) {
        (true, 1) // InMemoryRepo: always accepted, quorum=1 in test mode
    }

    /// InMemoryRepo: always applies the delta (no reporter-count tracking in test mode).
    async fn apply_audit_report(
        &self,
        target_node_id: &str,
        _reporter_node_id: &str,
        _finding: &str,
    ) -> AuditResult {
        const DELTA: f64 = -0.05;
        let mut guard = self.records.lock().unwrap();
        if let Some(rec) = guard.iter_mut().find(|r| r.node.node_id == target_node_id) {
            rec.node.reputation_score =
                crate::reputation::apply_delta(rec.node.reputation_score, DELTA);
            AuditResult {
                applied: true,
                new_score: rec.node.reputation_score,
                reason: "applied",
            }
        } else {
            AuditResult {
                applied: false,
                new_score: 0.0,
                reason: "target_not_found",
            }
        }
    }

    async fn list_badges(&self, _tier: Option<&str>) -> Vec<ConformanceBadge> {
        vec![]
    }

    async fn submit_conformance(&self, tier: &str, _subject_did: Option<&str>) -> String {
        format!("badge-{tier}-test")
    }

    async fn get_badge(&self, _tier: &str) -> Option<ConformanceBadge> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, score: f64, available: bool, rep: f64) -> Node {
        Node {
            node_id: id.into(),
            endpoint: format!("https://{id}"),
            region: "eu".into(),
            score,
            available,
            load: 0.0,
            active_jobs: 0,
            max_concurrent: 4,
            reputation_score: rep,
            latency_estimate_ms: None,
            completed_tasks_count: 0,
            health_label: None,
            exposure_mode: None,
            reputation_tier: None,
            transport_endpoint: None,
            cip_conformance_level: Some("CIP-None".to_string()),
            models: vec![],
            pricing: None,
            nat_type: None,
            transport_method: None,
            relay_capable: None,
            sdk_language: None,
            sdk_version: None,
            address_family: None,
            cip_policy: None,
            quantization: vec![],
            inference_engine: vec![],
            public_key: None,
            transport_metadata: None,
            credit_cost_multiplier: 1.0,
            pricing_model: Some("per_token".into()),
            attested: false,
            tasks_failed: 0,
            transport: vec![],
            // Representative active test node = relay-reachable (0.5), per PHP
            // reachabilityScore relay tier (#385).
            reachability_signal: 0.5,
        }
    }

    fn rec(id: &str, score: f64, available: bool, rep: f64, intents: &[&str]) -> NodeRecord {
        NodeRecord {
            node: node(id, score, available, rep),
            intents: intents.iter().map(|s| s.to_string()).collect(),
            node_token: None,
            node_hmac_key: None,
            proxy_token: None,
        }
    }

    const CHAT: &str = "urn:iicp:intent:llm:chat:v1";

    #[tokio::test]
    async fn filters_by_intent_and_availability_and_min_score() {
        let repo = InMemoryRepo::new(vec![
            rec("a", 0.9, true, 0.8, &[CHAT]),
            rec("b", 0.5, false, 0.8, &[CHAT]), // unavailable
            rec("c", 0.05, true, 0.8, &[CHAT]), // below MIN_SCORE
            rec("d", 0.7, true, 0.8, &["urn:iicp:intent:other:x:v1"]), // wrong intent
        ]);
        let out = repo
            .discover(&DiscoverQuery {
                intent: CHAT.into(),
                limit: 0,
                ..Default::default()
            })
            .await;
        assert_eq!(
            out.iter().map(|n| n.node_id.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );
    }

    #[tokio::test]
    async fn sorts_by_score_desc_and_respects_limit() {
        let repo = InMemoryRepo::new(vec![
            rec("low", 0.3, true, 0.8, &[CHAT]),
            rec("high", 0.9, true, 0.8, &[CHAT]),
            rec("mid", 0.6, true, 0.8, &[CHAT]),
        ]);
        let out = repo
            .discover(&DiscoverQuery {
                intent: CHAT.into(),
                limit: 2,
                ..Default::default()
            })
            .await;
        assert_eq!(
            out.iter().map(|n| n.node_id.as_str()).collect::<Vec<_>>(),
            vec!["high", "mid"]
        );
    }

    #[tokio::test]
    async fn min_reputation_excludes_below_threshold() {
        let repo = InMemoryRepo::new(vec![
            rec("good", 0.8, true, 0.9, &[CHAT]),
            rec("bad", 0.8, true, 0.4, &[CHAT]),
        ]);
        let out = repo
            .discover(&DiscoverQuery {
                intent: CHAT.into(),
                min_reputation: Some(0.5),
                limit: 0,
                ..Default::default()
            })
            .await;
        assert_eq!(
            out.iter().map(|n| n.node_id.as_str()).collect::<Vec<_>>(),
            vec!["good"]
        );
    }

    #[tokio::test]
    async fn limit_capped_at_max() {
        let recs: Vec<_> = (0..60)
            .map(|i| rec(&format!("n{i}"), 0.5, true, 0.8, &[CHAT]))
            .collect();
        let repo = InMemoryRepo::new(recs);
        let out = repo
            .discover(&DiscoverQuery {
                intent: CHAT.into(),
                limit: 100,
                ..Default::default()
            })
            .await;
        assert_eq!(out.len(), 50);
    }

    #[tokio::test]
    async fn decay_reduces_score_above_floor() {
        let repo = InMemoryRepo::new(vec![
            rec("hi", 0.9, true, 0.9, &[CHAT]),  // above floor — should decay
            rec("lo", 0.5, true, 0.28, &[CHAT]), // below floor — should NOT decay
        ]);
        let count = repo.decay_reputation_pass().await;
        assert_eq!(count, 1); // only "hi" decayed
                              // "hi" node: reputation_score was 0.9 → after decay 0.895, still > 0.30.
                              // Access via get() to check.
        let hi = repo.get("hi").await.unwrap();
        assert!((hi.reputation_score - 0.895).abs() < 1e-6);
        // "lo" node: below floor, unchanged at 0.28.
        let lo = repo.get("lo").await.unwrap();
        assert!((lo.reputation_score - 0.28).abs() < 1e-6);
    }

    #[tokio::test]
    async fn decay_floors_at_0_30() {
        let repo = InMemoryRepo::new(vec![rec("edge", 0.5, true, 0.303, &[CHAT])]);
        repo.decay_reputation_pass().await;
        let n = repo.get("edge").await.unwrap();
        // 0.303 - 0.005 = 0.298 → floors to 0.30
        assert!((n.reputation_score - 0.30).abs() < 1e-6);
    }
}

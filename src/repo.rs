// SPDX-License-Identifier: Apache-2.0
//! Node repository abstraction for the directory read path.
//!
//! The discover/scoring logic depends only on this trait, so the MySQL-backed
//! implementation (M2 wiring) can drop in without touching the HTTP layer. An
//! in-memory implementation backs the tests and local runs today.

use crate::types::Node;
use async_trait::async_trait;
use std::cmp::Reverse;
use std::collections::HashMap;

pub(crate) const DSR_RETENTION_REASON: &str = "Minimal ledger/security/accounting records retained; public/operator-identifying fields removed or restricted where possible.";

pub(crate) fn dispatch_usage_summary_value(
    days: u32,
    ticketed: u64,
    legacy: u64,
    public: u64,
) -> serde_json::Value {
    let dispatch_total = ticketed.saturating_add(legacy);
    serde_json::json!({
        "basis": "anonymous_daily_request_counts",
        "window_days": days,
        "ticketed_requests": ticketed,
        "legacy_route_discovery_requests": legacy,
        "public_view_requests": public,
        "ticketed_share": (dispatch_total > 0).then(|| (ticketed as f64 / dispatch_total as f64 * 10_000.0).round() / 10_000.0),
        "retention_days": 30,
        "contains_caller_identifiers": false,
        "measurement_valid_since": serde_json::Value::Null,
        "measurement_days_observed": 0,
        "measurement_window_complete": false,
        "minimum_sample_requests": 100,
        "sample_eligible": dispatch_total >= 100,
        "cutover_share_threshold": 0.90,
        "cutover_sustained_days": 14,
        "cutover_eligible": false,
        "measurement_limits": "Anonymous request-path counts can include manual or automated callers; use only after read-only tooling has moved to public view."
    })
}

/// A node plus the intent URNs it serves (the `capabilities[].intent` set).
#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub node: Node,
    pub intents: Vec<String>,
    /// Complete capability variants as registered. Legacy records may leave
    /// this empty and continue to use `intents` plus `capability_profiles`.
    pub capabilities: Vec<crate::types::EffectiveCapability>,
    /// Per-intent additive capability profiles advertised at registration.
    pub capability_profiles: HashMap<String, Vec<String>>,
    pub availability: Vec<AvailabilityWindow>,
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

#[derive(Debug, Clone)]
pub struct AvailabilityWindow {
    pub start: String,
    pub end: String,
    pub share: f64,
}

/// Redacted repository failure surfaced to HTTP handlers. Concrete database
/// errors stay in the persistence layer and must never leak tokens or SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoError {
    Persistence,
}

/// A transition in the independently observed direct-route state.
///
/// This is deliberately separate from node availability and relay capability:
/// a failed direct route must not hide a still-valid relay route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRouteTransition {
    Unchanged,
    Demoted,
    Restored,
}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "repository persistence failed")
    }
}

impl std::error::Error for RepoError {}

/// Public-safe result of an accountless operator identity lifecycle action.
/// Raw keys remain repository-private; callers receive only counts and the
/// replacement identity needed for internal registration continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorLifecycleResult {
    pub linked_nodes: u32,
    pub rotation_epoch: Option<u32>,
    pub revoked_at_unix: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorLifecycleError {
    Unknown,
    Inactive,
    SuccessorExists,
    Invalid,
    Storage,
}

/// Accountless operator governance/DSR failures.  The HTTP layer deliberately
/// maps these to stable, non-diagnostic responses so storage details and raw
/// operator identifiers never escape the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorSelfServiceError {
    Unknown,
    Inactive,
    DuplicateTrackingId,
    Storage,
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

#[derive(Debug, Clone)]
pub struct HeartbeatOutcome {
    pub score: f64,
    pub metrics_applied: bool,
    pub reputation_model: String,
    pub reputation_epoch: Option<String>,
}

#[async_trait]
pub trait NodeRepository: Send + Sync {
    /// Return scored, filtered nodes for a discovery query (iicp-dir §3.3/§3.4).
    /// Excludes unavailable nodes and nodes below score 0.1, sorts by score desc,
    /// truncates to `limit` (default 10, max 50).
    async fn discover(&self, q: &DiscoverQuery) -> Vec<Node>;

    /// Persist a registration (iicp-dir §3.1). Re-registering an existing `node_id`
    /// replaces the record (idempotent recovery), preserving its reputation_score.
    async fn register(&self, rec: NodeRecord) -> Result<(), RepoError>;

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
        metrics_batch_id: Option<String>,
        // #494 — live model list probed by the SDK on each heartbeat.
        // None = SDK did not report (backward compat); Some([]) = no models loaded.
        health_models: Option<Vec<String>>,
    ) -> Option<HeartbeatOutcome>;

    /// Fetch a single node by id for the node-detail endpoint (iicp-dir §3.4.x). `None` if unknown.
    async fn get(&self, node_id: &str) -> Option<Node>;

    /// Resolve a node for `GET /v1/registry/nodes/{prefix}` by an exact id OR an id **prefix**
    /// (the website hits this with an 8-hex UUID prefix, e.g. `b33d00e5`), matching only
    /// AVAILABLE nodes, exact match preferred. Mirrors PHP RegistryController::show
    /// (`id = ? OR id LIKE ?%` AND available). `None` if no available node matches.
    async fn node_by_prefix(&self, prefix: &str) -> Option<Node>;

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

    /// Verify that `token` is valid for `node_id`. InMemoryRepo is permissive
    /// by default and can opt into plaintext-token checks for focused lifecycle
    /// tests. MySqlRepo compares against node_token_hash.
    async fn verify_node_token(&self, node_id: &str, token: &str) -> bool;

    /// Return active peers not in `known_ids` for the PEER_EXCHANGE endpoint (iicp-dir §3.5).
    /// `limit` is capped at 20; default 10. InMemoryRepo returns all available nodes
    /// not in `known_ids` (no timestamp filter in local mode).
    async fn peers_excluding(&self, known_ids: &[String], limit: usize) -> Vec<Node>;

    /// Mark nodes as unavailable when their last_seen timestamp is older than the 90-second
    /// liveness window. Called by the ExpireStaleNodes background task (every 60s).
    /// InMemoryRepo is a no-op (no timestamps in local mode).
    /// Returns the IDs of nodes that were just marked dormant (uptime tracking #508).
    async fn expire_stale(&self) -> Vec<String>;

    /// Legacy compatibility hook. `outcome-v2` does not change with elapsed
    /// time; freshness and liveness are separate evidence dimensions.
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

    /// Lifetime credit summary: earned / spent / balance + tx count (#456).
    /// Returns None if the node is unknown.
    async fn credit_summary(&self, node_id: &str) -> Option<CreditSummary>;

    /// #466 v1 — the operator wallet: aggregate `(total_balance, node_count)` over the
    /// non-archived nodes sharing this node's `operator_pubkey`. `None` when the node is
    /// not operator-bound (no `operator_pubkey`). The `operator_pubkey` is never returned —
    /// only the totals. Kept for backward-compatible tests; rich summaries use
    /// operator_wallet_summary().
    #[allow(dead_code)]
    async fn operator_wallet(&self, node_id: &str) -> Option<(f64, u32)>;

    /// Rich operator wallet rollup: balance, earned, spent, tx count and reconcile flag.
    async fn operator_wallet_summary(&self, node_id: &str) -> Option<OperatorWalletSummary>;

    /// Effective balance used by credit quote/pre-flight checks.
    async fn effective_credit_balance(&self, node_id: &str) -> Option<EffectiveCreditBalance>;

    /// Archive dormant nodes older than `days_threshold` days and return count.
    /// PHP equivalent: NodeLifecycleCommand — transitions status → 'archived', sets
    /// dormant_since. InMemoryRepo is a no-op (no timestamps).
    async fn archive_dormant(&self, days_threshold: u32) -> u32;

    /// Fetch the node's HMAC key for credit receipt verification (W-009, iicp-dir §6.2).
    async fn node_hmac_key(&self, node_id: &str) -> Option<String>;

    /// Verify the prior ADR-047 heartbeat challenge and rotate it atomically.
    /// A response can succeed at most once because every call installs a fresh challenge.
    async fn verify_and_rotate_liveness_challenge(
        &self,
        node_id: &str,
        response: Option<&str>,
        next_challenge: &str,
    ) -> Option<bool>;

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

    /// Debit task spend from the consumer. Operator-bound consumers spend from the pooled
    /// operator wallet; unbound consumers retain node-local debit behavior.
    async fn debit_for_consumer(
        &self,
        consumer_node_id: &str,
        amount: f64,
        task_id: &str,
        reason: &str,
    ) -> WalletDebitResult;

    /// WQ-056 / billing §11.3 — the 90-day TTL credit sink. Sweep idle nodes (newest earn
    /// past TTL + positive balance): zero the balance and write one `ttl_expire` debit per
    /// node. Idempotent. Returns (expired_nodes, expired_credits). Called by the nightly
    /// `run_expire_credits_loop`. The PRIMARY anti-inflation sink (the 2% burn is secondary).
    async fn expire_idle_node_credits(&self) -> (u64, f64);

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

    /// Latest completed conformance run used by the signed compliance
    /// attestation. Returns content-free test identifiers only.
    async fn latest_conformance_run(&self) -> Option<ConformanceRun>;

    /// WQ-057 — the `credit_cost_multiplier` of every available node serving `intent` with
    /// reputation ≥ `min_reputation` (the quote candidate set, PHP CreditsController::quote).
    /// The handler derives estimated/min/max credits + nodes_quoted from this list.
    async fn quote_multipliers(&self, intent: &str, min_reputation: f64) -> Vec<f64>;

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

    /// Apply a confirmed active-probe observation to the direct route.
    /// Implementations must emit evidence only when the persisted route state changes.
    async fn apply_probe_route_state(&self, _node_id: &str, _passed: bool) -> ProbeRouteTransition {
        ProbeRouteTransition::Unchanged
    }

    /// Count of probe tokens active in the last 2 hours, plus their distinct regions.
    /// Used by `/v1/stats` `probes.active_count` + `probes.regions` (PHP StatsController parity).
    async fn probe_active_count_and_regions(&self) -> (i64, Vec<String>);

    /// Read the most-recent 24h aggregate metrics from `iicp_telemetry_aggregates`.
    /// Returns defaults when the table is empty (REACH not yet active).
    /// Also computes `task_success_rate_pct` from the `nodes` table (PHP D2-READ parity).
    async fn probe_aggregate_24h(&self) -> ProbeAggregate24h;

    /// Up to 5 test_ids with the highest fail count in the last 24h (PHP `topFailures` parity).
    /// Returns an empty vec when `iicp_telemetry_probes` has no recent failures.
    async fn probe_top_failures(&self) -> Vec<TopFailure>;

    /// Verify a proxy token (bearer + proxy_node_id → bcrypt verify against proxy_token_hash).
    /// InMemoryRepo: always true (no proxy auth in test mode).
    async fn verify_proxy_token(&self, proxy_node_id: &str, token: &str) -> bool;

    /// Record a proxy telemetry observation. Returns distinct proxy count for the target
    /// node in the last 7 days (used by the Sybil quorum check: need ≥3 for EMA update).
    /// Returns (accepted, quorum): accepted=false on duplicate (same proxy+node+60s bucket).
    async fn record_proxy_telemetry(&self, obs: &ProxyObservation) -> (bool, u32);

    /// #463/#310/#464 — upsert the operator-identity record on a verified delegation. On the
    /// FIRST insert, pin `integrity_hash` + the directory-observed `first_seen_ms`
    /// (authoritative for founder ordinals — never the backdatable `attested_created_at`).
    /// `display_name` is mutable on a later (delegated, key-proven) register. Fail-safe.
    async fn upsert_operator(
        &self,
        operator_pubkey: &str,
        display_name: Option<&str>,
        attested_created_at: Option<&str>,
        integrity_hash: Option<&str>,
    );

    /// #463 — the public `display_name` for an operator_pubkey, or None. Used by node detail
    /// (the operator_pubkey itself is directory-private and never served).
    async fn operator_display_name(&self, operator_pubkey: &str) -> Option<String>;

    /// #525/G3 — true when another *active* verified operator owns this normalized name.
    /// Rotated and revoked identity records remain as private lifecycle evidence, but
    /// must not prevent their active successor from retaining the same public handle.
    async fn operator_display_name_claimed_by_other(
        &self,
        operator_pubkey: &str,
        normalized_display_name: &str,
    ) -> bool;

    /// #460 — set the mutable `display_name` for an already-known operator (authenticated by
    /// the operator's own signature at the handler). Returns `false` when the operator does
    /// not exist (404) — never creates a record here; binding happens only via a verified
    /// register delegation. `integrity_hash`/`first_seen_ms`/ordinal stay pinned.
    async fn rename_operator(&self, operator_pubkey: &str, display_name: &str) -> bool;

    /// Lifecycle state is private control-plane data. `active` is the only
    /// identity state allowed to create new signed self-service actions.
    async fn operator_identity_active(&self, operator_pubkey: &str) -> Option<bool>;

    /// Atomically rotate an active operator to a fresh successor key, preserving
    /// node-linked wallet/reputation/recognition continuity through rebinding.
    async fn rotate_operator_identity(
        &self,
        old_operator_pubkey: &str,
        new_operator_pubkey: &str,
        requested_epoch: Option<u32>,
        reason_class: &str,
    ) -> Result<OperatorLifecycleResult, OperatorLifecycleError>;

    /// Revoke an active operator identity. Linked nodes become unverified but
    /// retain their historical node-backed ledger evidence.
    async fn revoke_operator_identity(
        &self,
        operator_pubkey: &str,
        reason_class: &str,
    ) -> Result<OperatorLifecycleResult, OperatorLifecycleError>;

    /// Persist current-version governance acceptance authenticated by the
    /// accountless operator challenge.  This is evidence of acceptance, not a
    /// legal certification or user-account system.
    async fn accept_operator_governance(
        &self,
        operator_pubkey: &str,
        terms_version: &str,
        dpa_version: &str,
        nonce_sha256: &str,
    ) -> Result<String, OperatorSelfServiceError>;

    /// DataSubjectRights: execute a redacted operator-scoped data-subject action. Implementations
    /// must preserve ledger/security evidence while removing or restricting
    /// public/operator-identifying fields where possible.
    async fn operator_dsr(
        &self,
        operator_pubkey: &str,
        action: &str,
        tracking_id: &str,
    ) -> Result<serde_json::Value, OperatorSelfServiceError>;

    /// DispatchUsage: record one anonymous request-path count. Implementations
    /// must not retain caller, route, endpoint, ticket or payload identifiers.
    async fn record_dispatch_usage(&self, mode: &str);

    async fn dispatch_usage_summary(&self, days: u32) -> serde_json::Value;

    /// Directory-owned PolicyKeyLifecycle status by SHA-256(raw Ed25519 key).
    /// Missing records mean no authoritative override; non-active records fail
    /// policy-manifest registration closed.
    async fn policy_key_lifecycle_status(&self, policy_key_sha256: &str) -> Option<String>;

    /// #310 — assign founder recognition state (ordinal/tier/badge) to a known operator. Called
    /// by the founder lock-in detector (§5.4); no-op if the operator does not exist. (Forward
    /// interface — exercised by tests today; the lock-in detector wires it in a later #310 slice.)
    #[allow(dead_code)]
    async fn set_operator_recognition(
        &self,
        operator_pubkey: &str,
        ordinal: i64,
        tier: Option<&str>,
        badge: Option<&str>,
    );

    /// #310/#463 — founder leaderboard rows (operators with an ordinal), best (lowest) first,
    /// up to `limit`. operator_pubkey is never returned — only the public recognition fields.
    async fn list_founders(&self, limit: u32) -> Vec<FounderEntry>;

    /// Provisional founders for the board's `pending` section: operators with NO ordinal,
    /// a pinned first_seen_ms, and a genuine served node (operator_verified +
    /// public_reachable + active/available or seen within the trailing 24h — the same gate
    /// the lock-in detector applies). Ordered by first appearance, up to `limit`.
    async fn list_pending_founders(&self, limit: u32) -> Vec<PendingFounderEntry>;

    /// List conformance badges (all or filtered by tier/status).
    async fn list_badges(&self, tier: Option<&str>) -> Vec<ConformanceBadge>;

    /// Submit a conformance evaluation request. Returns the new badge_id.
    async fn submit_conformance(&self, tier: &str, subject_did: Option<&str>) -> String;

    /// Get conformance status for a tier. Returns None if no badge exists.
    async fn get_badge(&self, tier: &str) -> Option<ConformanceBadge>;

    /// ADR-048 (#374): store/refresh a per-(node, evaluator) health snapshot from an
    /// applied HEALTH event. Monotonic — an `evaluated_at_ms` older than the stored one
    /// is ignored (out-of-order replay is a no-op). Returns true if a row was written.
    async fn upsert_health_observation(
        &self,
        node_id: &str,
        evaluator_did: &str,
        score: f64,
        evaluated_at_ms: i64,
    ) -> bool;

    /// ADR-048: every stored health snapshot as
    /// `(node_id, evaluator_did, score, evaluated_at_ms)` — the input to
    /// `health::federated_mesh_health` for the federation-wide `/v1/stats` aggregate.
    async fn all_health_observations(&self) -> Vec<(String, String, f64, i64)>;

    /// #441 (replica full-state fidelity): set a node's absolute reputation_score from an
    /// applied REPUTATION_DECAY event (mirrors PHP ReplicaEventApplier::applyReputationDecay).
    /// Returns true if the node exists.
    async fn set_reputation_score(&self, node_id: &str, score: f64) -> bool;

    /// #441: set a node's absolute credit_balance from an applied CREDIT_AWARD event
    /// (mirrors PHP applyCreditAward, which sets balance = new_balance). Returns true if known.
    async fn set_credit_balance(&self, node_id: &str, balance: f64) -> bool;

    /// #441: record a trusted replica from an applied REPLICA_REGISTERED event (mirrors PHP
    /// applyReplicaRegistered — upsert by DID). Returns true if stored.
    async fn upsert_replica(
        &self,
        replica_id: &str,
        did: &str,
        endpoint: &str,
        trust_tier: &str,
    ) -> bool;

    /// Store the SHA-256 hash of the currently issued replica JWT. Plaintext tokens
    /// never enter repository storage.
    async fn set_replica_token_hash(&self, replica_id: &str, token_hash: &str) -> bool;

    /// Return the stored hash for the current replica JWT.
    async fn replica_token_hash(&self, replica_id: &str) -> Option<String>;

    /// Persistent lifecycle gate, independent of JWT validity.
    async fn replica_is_active(&self, replica_id: &str) -> bool;

    /// Retain an audit tombstone while invalidating the active registration.
    async fn decommission_replica(&self, replica_id: &str) -> bool;

    /// Seed-side atomic lifecycle write: decommission plus signed event append.
    async fn decommission_replica_with_event(
        &self,
        replica_id: &str,
        did: &str,
        secret_key_hex: &str,
    ) -> bool;

    /// #441: trusted replicas as `(replica_id, did, endpoint, trust_tier, registered_at_ms)`.
    /// Consumed by the `/.well-known/iicp-replicas.json` endpoint (DIR-FED-19) and replica
    /// tests. `registered_at_ms` = Unix ms at first registration (accurate for InMemory;
    /// MySQL uses `created_at`).
    async fn all_replicas(&self) -> Vec<(String, String, String, String, i64)>;

    /// Stable identity lookup includes lifecycle tombstones so same-DID
    /// re-registration reuses the original replica_id.
    async fn replica_id_by_did(&self, did: &str) -> Option<String>;

    /// #442 (seed side): append a signed event to `node_events` — assign the next monotonic
    /// `seq`, mint an event_id, stamp ts_ms, Ed25519-sign via `federation::sign_event` (when
    /// a 64-byte key is configured), and persist. Returns the assigned seq. Mirrors PHP
    /// `NodeEventLogger::log`. This is what lets a Rust directory be a SEED (emit its own log).
    #[allow(dead_code)]
    async fn append_signed_event(
        &self,
        secret_key_hex: &str,
        event_type: &str,
        node_id: &str,
        payload: &serde_json::Value,
    ) -> Option<i64>;

    /// #442 (seed side): the event log from `seq > since_seq`, ascending, capped at `limit`
    /// — the read backing a future `GET /v1/events` so a replica (PHP or Rust) can tail
    /// this directory's signed log.
    #[allow(dead_code)]
    async fn events_since(&self, since_seq: i64, limit: u32) -> Vec<EventRow>;

    /// #442 (seed side): all nodes + their intents for `GET /v1/snapshot` (full-state
    /// bootstrap a replica applies before tailing). Mirrors PHP SnapshotController
    /// (Node::all() + Capability::all()).
    #[allow(dead_code)]
    async fn snapshot_records(&self) -> Vec<NodeRecord>;
}

/// One signed event-log row (#442) — the shape a replica consumes from `GET /v1/events`.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EventRow {
    pub seq: i64,
    pub event_id: String,
    pub event_type: String,
    pub node_id: String,
    pub ts_ms: i64,
    pub payload: serde_json::Value,
    /// Hash-chain link to the predecessor (#458). `None` for legacy pre-migration rows.
    pub prev_hash: Option<String>,
    pub sig: Option<String>,
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

/// #310/#463 — one row of the public founder leaderboard. Carries only the public handle +
/// recognition state; the operator_pubkey is directory-private and never included.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FounderEntry {
    pub display_name: Option<String>,
    pub ordinal: i64,
    pub tier: Option<String>,
    pub badge: Option<String>,
}

/// Provisional founder (spec iicp-recognition §5.4.2 provisional state, surfaced on the
/// founders board `pending` section): an operator with a genuine served node whose 30-day
/// lock-in clock is still running. Public handle + first-appearance only — never the pubkey.
#[derive(Debug, Clone)]
pub struct PendingFounderEntry {
    pub display_name: Option<String>,
    pub first_seen_ms: i64,
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
    /// #373 — node this probe targets (per-node reachability/health); None for
    /// directory-infra probes.
    #[serde(default)]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ConformanceRun {
    pub run_id: String,
    pub probed_at: String,
    pub passed: Vec<String>,
    pub failed: Vec<String>,
}

fn conformance_run_from_probes(probes: &[ProbeResult]) -> Option<ConformanceRun> {
    let latest = probes
        .iter()
        .filter(|probe| probe.probe_type == "conformance" && !probe.run_id.is_empty())
        .max_by_key(|probe| probe.probed_at.as_deref().unwrap_or(""))?;
    let mut passed = Vec::new();
    let mut failed = Vec::new();
    for probe in probes
        .iter()
        .filter(|probe| probe.probe_type == "conformance" && probe.run_id == latest.run_id)
    {
        let Some(test_id) = probe.test_id.as_ref() else {
            continue;
        };
        if probe.passed {
            passed.push(test_id.clone());
        } else {
            failed.push(test_id.clone());
        }
    }
    passed.sort();
    passed.dedup();
    failed.sort();
    failed.dedup();
    Some(ConformanceRun {
        run_id: latest.run_id.clone(),
        probed_at: latest
            .probed_at
            .clone()
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        passed,
        failed,
    })
}

/// Pre-aggregated probe metrics from `iicp_telemetry_aggregates` for a 24h window.
/// All fields are None/0 until the REACH aggregation job has run (PHP parity: unavailable).
#[derive(Debug, Default)]
pub struct ProbeAggregate24h {
    pub discover_p50_ms: Option<f64>,
    pub discover_p95_ms: Option<f64>,
    pub heartbeat_p50_ms: Option<f64>,
    pub reachability_pct: Option<f64>,
    pub conformance_passed: i64,
    pub conformance_failed: i64,
    pub task_success_rate_pct: Option<f64>,
}

/// One entry in the top-failing probes list (last 24h, by fail count).
#[derive(Debug)]
pub struct TopFailure {
    pub test_id: String,
    pub passed: i64,
    pub failed: i64,
    pub total: i64,
    pub fail_rate: f64,
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

/// Lifetime credit summary for a node (#456). `reconciles` (balance == earned − spent)
/// is computed in the handler, not stored — it is an integrity check, not a column.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CreditSummary {
    pub balance: f64,
    pub total_earned: f64,
    pub total_spent: f64,
    pub tx_count: u64,
}

/// Operator-level credit wallet summary. The raw operator_pubkey is never returned.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OperatorWalletSummary {
    pub total_balance: f64,
    pub total_earned: f64,
    pub total_spent: f64,
    pub tx_count: u64,
    pub node_count: u32,
    pub reconciles: bool,
    pub operator_fingerprint: String,
}

/// Effective balance for quote/pre-flight spend checks.
#[derive(Debug, Clone)]
pub struct EffectiveCreditBalance {
    pub consumer_balance: f64,
    pub effective_balance: f64,
    pub balance_scope: &'static str,
    pub operator_wallet_balance: Option<f64>,
}

/// Result of debiting a task spend from either a node-local or operator wallet.
#[derive(Debug, Clone)]
pub struct WalletDebitResult {
    #[allow(dead_code)]
    // response currently uses spent/reason; bool remains useful for callers/tests.
    pub debited: bool,
    pub spent: f64,
    pub scope: &'static str,
    pub reason: Option<&'static str>,
    pub debit_count: u32,
}

pub fn operator_fingerprint(operator_pubkey: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(operator_pubkey.as_bytes());
    hex::encode(digest)[..12].to_string()
}

pub(crate) fn verify_liveness_response(key: &str, challenge: &str, response: &str) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    let Ok(candidate) = hex::decode(response) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key.as_bytes()) else {
        return false;
    };
    mac.update(challenge.as_bytes());
    mac.verify_slice(&candidate).is_ok()
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
type ReplicaTuple = (String, String, String, String, i64);

#[derive(Debug, Default)]
pub struct InMemoryRepo {
    records: std::sync::Mutex<Vec<NodeRecord>>,
    /// Optional strict token checking for HTTP lifecycle canaries. Ordinary
    /// in-memory tests retain the historical permissive behavior.
    verify_tokens: bool,
    /// Outstanding ADR-047 challenge by node ID. Kept separate from the public node model.
    liveness_challenges: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// ADR-048 (#374): per-(node, evaluator) health snapshots —
    /// (node_id, evaluator_did, score, evaluated_at_ms).
    health_obs: std::sync::Mutex<Vec<(String, String, f64, i64)>>,
    /// #441: trusted replicas — (replica_id, did, endpoint, trust_tier, registered_at_ms).
    replicas: std::sync::Mutex<Vec<ReplicaTuple>>,
    replica_token_hashes: std::sync::Mutex<std::collections::HashMap<String, String>>,
    decommissioned_replicas: std::sync::Mutex<std::collections::HashSet<String>>,
    /// #442: appended signed event log (seq-monotonic).
    events: std::sync::Mutex<Vec<EventRow>>,
    /// #463/#310: operator-identity records keyed by operator_pubkey → [`OperatorRow`].
    operators: std::sync::Mutex<std::collections::HashMap<String, OperatorRow>>,
    dispatch_usage: std::sync::Mutex<std::collections::HashMap<(String, String), u64>>,
    probe_results: std::sync::Mutex<Vec<ProbeResult>>,
    last_metrics_batches: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

/// In-memory operator-identity record (#463/#310). `ordinal`/`tier`/`badge` are the founder
/// recognition state (None until assigned by the lock-in detector / #310 slice).
/// `attested_created_at`/`integrity_hash`/`first_seen_ms` mirror the persisted schema (read via
/// SQL in `MySqlRepo`; retained here for parity, hence allow(dead_code) in the test repo).
#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
struct OperatorRow {
    display_name: Option<String>,
    attested_created_at: Option<String>,
    integrity_hash: Option<String>,
    first_seen_ms: i64,
    ordinal: Option<i64>,
    tier: Option<String>,
    badge: Option<String>,
    identity_status: String,
    rotation_epoch: Option<u32>,
    terms_version: Option<String>,
    terms_accepted_at: Option<String>,
    dpa_version: Option<String>,
    dpa_accepted_at: Option<String>,
    acceptance_method: Option<String>,
    acceptance_nonce_sha256: Option<String>,
}

impl InMemoryRepo {
    // Test/local constructor; the production constructor is the MySQL-backed repo.
    #[allow(dead_code)]
    pub fn new(records: Vec<NodeRecord>) -> Self {
        Self {
            records: std::sync::Mutex::new(records),
            verify_tokens: false,
            liveness_challenges: std::sync::Mutex::new(std::collections::HashMap::new()),
            health_obs: std::sync::Mutex::new(Vec::new()),
            replicas: std::sync::Mutex::new(Vec::new()),
            replica_token_hashes: std::sync::Mutex::new(std::collections::HashMap::new()),
            decommissioned_replicas: std::sync::Mutex::new(std::collections::HashSet::new()),
            events: std::sync::Mutex::new(Vec::new()),
            operators: std::sync::Mutex::new(std::collections::HashMap::new()),
            dispatch_usage: std::sync::Mutex::new(std::collections::HashMap::new()),
            probe_results: std::sync::Mutex::new(Vec::new()),
            last_metrics_batches: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    #[cfg(test)]
    pub fn new_with_token_verification(records: Vec<NodeRecord>) -> Self {
        Self {
            verify_tokens: true,
            ..Self::new(records)
        }
    }
}

struct InMemoryDsrSubject {
    row: OperatorRow,
    node_ids: Vec<String>,
    fingerprint: String,
    pubkey_sha256: String,
    selector: serde_json::Value,
    subject_hash: String,
}

fn in_memory_dsr_subject(
    repo: &InMemoryRepo,
    operator_pubkey: &str,
) -> Result<InMemoryDsrSubject, OperatorSelfServiceError> {
    use sha2::{Digest, Sha256};
    let row = repo
        .operators
        .lock()
        .unwrap()
        .get(operator_pubkey)
        .cloned()
        .ok_or(OperatorSelfServiceError::Unknown)?;
    if row.identity_status != "active" {
        return Err(OperatorSelfServiceError::Inactive);
    }
    let fingerprint = crate::public_operator_fingerprint(operator_pubkey);
    let pubkey_sha256 = hex::encode(Sha256::digest(operator_pubkey.as_bytes()));
    let selector = serde_json::json!({
        "operator_pubkey": {"sha256": pubkey_sha256, "fingerprint": fingerprint}
    });
    let subject_hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&selector).unwrap_or_default(),
    ));
    let node_ids = repo
        .records
        .lock()
        .unwrap()
        .iter()
        .filter(|record| record.node.operator_pubkey.as_deref() == Some(operator_pubkey))
        .map(|record| record.node.node_id.clone())
        .collect();
    Ok(InMemoryDsrSubject {
        row,
        node_ids,
        fingerprint,
        pubkey_sha256,
        selector,
        subject_hash,
    })
}

fn in_memory_dsr_export(subject: &InMemoryDsrSubject, tracking_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": "iicp.dsr.export.v1",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "tracking_id": tracking_id,
        "selector": subject.selector,
        "subject_hash": subject.subject_hash,
        "retention_notice": DSR_RETENTION_REASON,
        "records": {
            "operators": [{"operator_fingerprint": subject.fingerprint, "operator_pubkey_sha256": subject.pubkey_sha256, "display_name": subject.row.display_name, "terms_version": subject.row.terms_version, "dpa_version": subject.row.dpa_version, "acceptance_method": subject.row.acceptance_method}],
            "nodes": subject.node_ids.iter().map(|id| serde_json::json!({"id": id})).collect::<Vec<_>>(),
            "capabilities": [], "credits": [], "credit_transactions": [], "reputations": [],
            "node_address_history": [], "telemetry_probes": [], "proxy_telemetry": [],
            "node_events": [], "data_subject_actions": []
        }
    })
}

fn apply_in_memory_dsr(
    repo: &InMemoryRepo,
    operator_pubkey: &str,
    action: &str,
    tracking_id: &str,
    subject: &InMemoryDsrSubject,
) -> Result<serde_json::Value, OperatorSelfServiceError> {
    clear_in_memory_operator_subject(repo, operator_pubkey)?;
    clear_in_memory_node_subjects(repo, operator_pubkey, action);
    if action == "anonymize" {
        anonymize_in_memory_operator(repo, operator_pubkey, tracking_id);
    }
    Ok(serde_json::json!({
        "action": action, "dry_run": false, "tracking_id": tracking_id,
        "selector": subject.selector, "subject_hash": subject.subject_hash,
        "affected_counts": {"nodes": subject.node_ids.len(), "operators": 1, "credits": 0, "credit_transactions": 0, "node_events_retained": 0, "node_address_history": 0, "telemetry_probes": 0, "proxy_telemetry": 0},
        "retention_reason": DSR_RETENTION_REASON
    }))
}

fn clear_in_memory_operator_subject(
    repo: &InMemoryRepo,
    operator_pubkey: &str,
) -> Result<(), OperatorSelfServiceError> {
    let mut operators = repo.operators.lock().unwrap();
    let row = operators
        .get_mut(operator_pubkey)
        .ok_or(OperatorSelfServiceError::Unknown)?;
    row.display_name = None;
    row.attested_created_at = None;
    row.integrity_hash = None;
    row.tier = None;
    row.badge = None;
    row.terms_version = None;
    row.terms_accepted_at = None;
    row.dpa_version = None;
    row.dpa_accepted_at = None;
    row.acceptance_method = None;
    row.acceptance_nonce_sha256 = None;
    Ok(())
}

fn clear_in_memory_node_subjects(repo: &InMemoryRepo, operator_pubkey: &str, action: &str) {
    for record in repo
        .records
        .lock()
        .unwrap()
        .iter_mut()
        .filter(|record| record.node.operator_pubkey.as_deref() == Some(operator_pubkey))
    {
        record.node.available = false;
        record.node.public_listing = false;
        record.node.operator_url = None;
        if action == "anonymize" {
            record.node.operator_pubkey = None;
            record.node.operator_verified = false;
            record.node.operator_trust_tier = None;
        }
    }
}

fn anonymize_in_memory_operator(repo: &InMemoryRepo, operator_pubkey: &str, tracking_id: &str) {
    use sha2::{Digest, Sha256};
    let Some(mut row) = repo.operators.lock().unwrap().remove(operator_pubkey) else {
        return;
    };
    let anonymized = format!(
        "dsr_{}",
        &hex::encode(Sha256::digest(
            format!("operator:{tracking_id}:{operator_pubkey}").as_bytes()
        ))[..60]
    );
    row.identity_status = "restricted".to_string();
    repo.operators.lock().unwrap().insert(anonymized, row);
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
            .map(|r| {
                let mut node = r.node.clone();
                node.capabilities = r
                    .capabilities
                    .iter()
                    .filter(|capability| capability.intent == q.intent)
                    .cloned()
                    .collect();
                node.supported_profiles = if node.capabilities.is_empty() {
                    r.capability_profiles
                        .get(&q.intent)
                        .cloned()
                        .unwrap_or_default()
                } else {
                    node.capabilities
                        .iter()
                        .flat_map(|capability| capability.supported_profiles.iter().cloned())
                        .collect()
                };
                node.supported_profiles.sort();
                node.supported_profiles.dedup();
                node
            })
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

    async fn register(&self, rec: NodeRecord) -> Result<(), RepoError> {
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
        Ok(())
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
        metrics_batch_id: Option<String>,
        health_models: Option<Vec<String>>,
    ) -> Option<HeartbeatOutcome> {
        let mut guard = self.records.lock().unwrap();
        let rec = guard.iter_mut().find(|r| r.node.node_id == node_id)?;
        let metrics_applied = metrics_batch_id.as_ref().is_none_or(|batch_id| {
            let mut batches = self.last_metrics_batches.lock().unwrap();
            if batches.get(node_id) == Some(batch_id) {
                false
            } else {
                batches.insert(node_id.to_string(), batch_id.clone());
                true
            }
        });
        rec.node.load = load;
        rec.node.available = available;
        rec.node.active_jobs = active_jobs;
        if metrics_applied {
            rec.node.completed_tasks_count += tasks_delta as u64;
            rec.node.tasks_failed += tasks_failed_delta as u64;
            rec.node.reputation_score =
                crate::reputation::apply_delta(rec.node.reputation_score, delta);
        }
        // #494 — update live model list only when the SDK reported one.
        if health_models.is_some() {
            rec.node.health_models = health_models;
        }
        Some(HeartbeatOutcome {
            score: rec.node.reputation_score,
            metrics_applied,
            reputation_model: "outcome-v2".to_string(),
            reputation_epoch: Some("outcome-v2-initial".to_string()),
        })
    }

    async fn get(&self, node_id: &str) -> Option<Node> {
        let guard = self.records.lock().unwrap();
        guard.iter().find(|r| r.node.node_id == node_id).map(|r| {
            let mut node = r.node.clone();
            node.capabilities = r.capabilities.clone();
            node.supported_profiles = r.capability_profiles.values().flatten().cloned().collect();
            node.supported_profiles.sort();
            node.supported_profiles.dedup();
            node
        })
    }

    async fn node_by_prefix(&self, prefix: &str) -> Option<Node> {
        // Exact match preferred, then prefix; AVAILABLE only (PHP show() parity).
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .find(|r| r.node.available && r.node.node_id == prefix)
            .or_else(|| {
                guard
                    .iter()
                    .find(|r| r.node.available && r.node.node_id.starts_with(prefix))
            })
            .map(|r| {
                let mut node = r.node.clone();
                node.capabilities = r.capabilities.clone();
                node.supported_profiles =
                    r.capability_profiles.values().flatten().cloned().collect();
                node.supported_profiles.sort();
                node.supported_profiles.dedup();
                node
            })
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

    /// InMemoryRepo keeps issued tokens only in process memory.  Comparing them
    /// gives HTTP lifecycle tests realistic rotation/replay behavior without
    /// weakening the production bcrypt-backed repository.
    async fn verify_node_token(&self, node_id: &str, token: &str) -> bool {
        if !self.verify_tokens {
            return true;
        }
        self.records
            .lock()
            .unwrap()
            .iter()
            .find(|record| record.node.node_id == node_id)
            .is_some_and(|record| {
                record
                    .node_token
                    .as_deref()
                    .is_none_or(|expected| expected == token)
            })
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
    async fn expire_stale(&self) -> Vec<String> {
        vec![]
    }

    async fn decay_reputation_pass(&self) -> u32 {
        0
    }

    async fn list_public(&self, offset: u64, limit: usize) -> Vec<Node> {
        let cap = limit.min(100);
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            // Parity with PHP `RegistryController::index` / `MySqlRepo::list_public`:
            // only available nodes are listed (NOT gated on `public_listing`).
            .filter(|r| r.node.available)
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

    async fn credit_summary(&self, node_id: &str) -> Option<CreditSummary> {
        // InMemoryRepo has no ledger — an existing node summarises to all-zero, which
        // trivially reconciles (0 == 0 − 0). Real aggregation lives in MySqlRepo.
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .find(|r| r.node.node_id == node_id)
            .map(|_| CreditSummary {
                balance: 0.0,
                total_earned: 0.0,
                total_spent: 0.0,
                tx_count: 0,
            })
    }

    async fn operator_wallet(&self, node_id: &str) -> Option<(f64, u32)> {
        // #466 v1 — resolve the node's operator_pubkey, then count the operator's nodes.
        // Faithfully tests the operator-scoping + null guard (the bug-prone part); total_balance
        // is 0.0 here because the in-memory Node carries no credit_balance (DB-only field, like
        // credit_balance() returning 0.0) — the real SUM lives in MySqlRepo. No status/archived
        // in-memory, so no archived-exclusion (parity note: MySqlRepo excludes archived).
        let guard = self.records.lock().unwrap();
        let pubkey = guard
            .iter()
            .find(|r| r.node.node_id == node_id)
            .and_then(|r| r.node.operator_pubkey.clone())
            .filter(|p| !p.is_empty())?;
        let node_count = guard
            .iter()
            .filter(|r| r.node.operator_pubkey.as_deref() == Some(pubkey.as_str()))
            .count() as u32;
        Some((0.0, node_count))
    }

    async fn operator_wallet_summary(&self, node_id: &str) -> Option<OperatorWalletSummary> {
        let guard = self.records.lock().unwrap();
        let pubkey = guard
            .iter()
            .find(|r| r.node.node_id == node_id)
            .and_then(|r| r.node.operator_pubkey.clone())
            .filter(|p| !p.is_empty())?;
        let node_count = guard
            .iter()
            .filter(|r| r.node.operator_pubkey.as_deref() == Some(pubkey.as_str()))
            .count() as u32;
        Some(OperatorWalletSummary {
            total_balance: 0.0,
            total_earned: 0.0,
            total_spent: 0.0,
            tx_count: 0,
            node_count,
            reconciles: true,
            operator_fingerprint: operator_fingerprint(&pubkey),
        })
    }

    async fn effective_credit_balance(&self, node_id: &str) -> Option<EffectiveCreditBalance> {
        let guard = self.records.lock().unwrap();
        let rec = guard.iter().find(|r| r.node.node_id == node_id)?;
        if rec
            .node
            .operator_pubkey
            .as_deref()
            .is_some_and(|p| !p.is_empty())
        {
            Some(EffectiveCreditBalance {
                consumer_balance: 0.0,
                effective_balance: 0.0,
                balance_scope: "operator_wallet",
                operator_wallet_balance: Some(0.0),
            })
        } else {
            Some(EffectiveCreditBalance {
                consumer_balance: 0.0,
                effective_balance: 0.0,
                balance_scope: "node",
                operator_wallet_balance: None,
            })
        }
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

    async fn verify_and_rotate_liveness_challenge(
        &self,
        node_id: &str,
        response: Option<&str>,
        next_challenge: &str,
    ) -> Option<bool> {
        let hmac_key = {
            let guard = self.records.lock().unwrap();
            guard
                .iter()
                .find(|r| r.node.node_id == node_id)
                .map(|r| r.node_hmac_key.clone())?
        };
        let mut challenges = self.liveness_challenges.lock().unwrap();
        let verified = challenges.get(node_id).is_some_and(|challenge| {
            hmac_key.as_deref().is_some_and(|key| {
                response
                    .is_some_and(|candidate| verify_liveness_response(key, challenge, candidate))
            })
        });
        challenges.insert(node_id.to_string(), next_challenge.to_string());
        Some(verified)
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

    async fn debit_for_consumer(
        &self,
        consumer_node_id: &str,
        _amount: f64,
        _task_id: &str,
        _reason: &str,
    ) -> WalletDebitResult {
        let guard = self.records.lock().unwrap();
        let scope = guard
            .iter()
            .find(|r| r.node.node_id == consumer_node_id)
            .and_then(|r| r.node.operator_pubkey.as_deref())
            .filter(|p| !p.is_empty())
            .map(|_| "operator_wallet")
            .unwrap_or("node");
        WalletDebitResult {
            debited: false,
            spent: 0.0,
            scope,
            reason: Some(if scope == "operator_wallet" {
                "insufficient_operator_wallet_balance"
            } else {
                "insufficient_balance"
            }),
            debit_count: 0,
        }
    }

    async fn expire_idle_node_credits(&self) -> (u64, f64) {
        (0, 0.0) // InMemoryRepo has no ledger — the TTL sweep is a MySqlRepo concern.
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
        self.probe_results.lock().unwrap().extend_from_slice(probes);
        probes.len() as u32
    }

    async fn latest_conformance_run(&self) -> Option<ConformanceRun> {
        conformance_run_from_probes(&self.probe_results.lock().unwrap())
    }

    async fn quote_multipliers(&self, intent: &str, min_reputation: f64) -> Vec<f64> {
        let guard = self.records.lock().unwrap();
        guard
            .iter()
            .filter(|r| {
                r.node.available
                    && r.node.reputation_score >= min_reputation
                    && r.intents.iter().any(|i| i == intent)
            })
            .map(|r| r.node.credit_cost_multiplier)
            .collect()
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

    async fn probe_active_count_and_regions(&self) -> (i64, Vec<String>) {
        (0, vec![]) // InMemoryRepo: no probe_tokens table in test mode
    }

    async fn probe_aggregate_24h(&self) -> ProbeAggregate24h {
        ProbeAggregate24h::default() // InMemoryRepo: no aggregates in test mode
    }

    async fn probe_top_failures(&self) -> Vec<TopFailure> {
        vec![] // InMemoryRepo: no telemetry_probes table in test mode
    }

    async fn verify_proxy_token(&self, _proxy_node_id: &str, _token: &str) -> bool {
        true // InMemoryRepo: no proxy auth in test mode
    }

    async fn record_proxy_telemetry(&self, _obs: &ProxyObservation) -> (bool, u32) {
        (true, 1) // InMemoryRepo: always accepted, quorum=1 in test mode
    }

    /// InMemoryRepo: accepts the integrity evidence without changing outcome reputation.
    async fn apply_audit_report(
        &self,
        target_node_id: &str,
        _reporter_node_id: &str,
        _finding: &str,
    ) -> AuditResult {
        let mut guard = self.records.lock().unwrap();
        if let Some(rec) = guard.iter_mut().find(|r| r.node.node_id == target_node_id) {
            AuditResult {
                applied: true,
                new_score: rec.node.reputation_score,
                reason: "integrity_evidence_accepted",
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

    async fn upsert_health_observation(
        &self,
        node_id: &str,
        evaluator_did: &str,
        score: f64,
        evaluated_at_ms: i64,
    ) -> bool {
        let mut guard = self.health_obs.lock().unwrap();
        if let Some(row) = guard
            .iter_mut()
            .find(|(n, e, _, _)| n == node_id && e == evaluator_did)
        {
            // Monotonic staleness rule: older snapshot never overwrites a newer one.
            if evaluated_at_ms <= row.3 {
                return false;
            }
            row.2 = score;
            row.3 = evaluated_at_ms;
            return true;
        }
        guard.push((
            node_id.to_string(),
            evaluator_did.to_string(),
            score,
            evaluated_at_ms,
        ));
        true
    }

    async fn all_health_observations(&self) -> Vec<(String, String, f64, i64)> {
        self.health_obs.lock().unwrap().clone()
    }

    async fn set_reputation_score(&self, node_id: &str, score: f64) -> bool {
        let mut guard = self.records.lock().unwrap();
        if let Some(r) = guard.iter_mut().find(|r| r.node.node_id == node_id) {
            r.node.reputation_score = score.clamp(0.0, 1.0);
            return true;
        }
        false
    }

    async fn set_credit_balance(&self, node_id: &str, _balance: f64) -> bool {
        // InMemoryRepo has no credit ledger (credit_balance() returns 0.0) — the apply
        // contract (known node → true) is what's exercised in tests; the real balance write
        // is the MySqlRepo path.
        self.records
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.node.node_id == node_id)
    }

    async fn upsert_replica(
        &self,
        replica_id: &str,
        did: &str,
        endpoint: &str,
        trust_tier: &str,
    ) -> bool {
        let now = now_ms();
        let mut guard = self.replicas.lock().unwrap();
        if let Some(row) = guard.iter_mut().find(|(_, d, _, _, _)| d == did) {
            // Preserve original registered_at_ms on re-registration.
            let orig_ts = row.4;
            *row = (
                replica_id.to_string(),
                did.to_string(),
                endpoint.to_string(),
                trust_tier.to_string(),
                orig_ts,
            );
        } else {
            guard.push((
                replica_id.to_string(),
                did.to_string(),
                endpoint.to_string(),
                trust_tier.to_string(),
                now,
            ));
        }
        self.decommissioned_replicas
            .lock()
            .unwrap()
            .remove(replica_id);
        true
    }

    async fn set_replica_token_hash(&self, replica_id: &str, token_hash: &str) -> bool {
        if !self
            .replicas
            .lock()
            .unwrap()
            .iter()
            .any(|row| row.0 == replica_id)
        {
            return false;
        }
        self.replica_token_hashes
            .lock()
            .unwrap()
            .insert(replica_id.to_string(), token_hash.to_string());
        true
    }

    async fn replica_token_hash(&self, replica_id: &str) -> Option<String> {
        self.replica_token_hashes
            .lock()
            .unwrap()
            .get(replica_id)
            .cloned()
    }

    async fn replica_is_active(&self, replica_id: &str) -> bool {
        self.replicas
            .lock()
            .unwrap()
            .iter()
            .any(|row| row.0 == replica_id)
            && !self
                .decommissioned_replicas
                .lock()
                .unwrap()
                .contains(replica_id)
    }

    async fn decommission_replica(&self, replica_id: &str) -> bool {
        if !self
            .replicas
            .lock()
            .unwrap()
            .iter()
            .any(|row| row.0 == replica_id)
        {
            return false;
        }
        self.replica_token_hashes.lock().unwrap().remove(replica_id);
        self.decommissioned_replicas
            .lock()
            .unwrap()
            .insert(replica_id.to_string());
        true
    }

    async fn decommission_replica_with_event(
        &self,
        replica_id: &str,
        did: &str,
        secret_key_hex: &str,
    ) -> bool {
        if !self.decommission_replica(replica_id).await {
            return false;
        }
        self.append_signed_event(
            secret_key_hex,
            "REPLICA_DEREGISTERED",
            replica_id,
            &serde_json::json!({"did": did}),
        )
        .await
        .is_some()
    }

    async fn all_replicas(&self) -> Vec<(String, String, String, String, i64)> {
        let decommissioned = self.decommissioned_replicas.lock().unwrap();
        self.replicas
            .lock()
            .unwrap()
            .iter()
            .filter(|row| !decommissioned.contains(&row.0))
            .cloned()
            .collect()
    }

    async fn replica_id_by_did(&self, did: &str) -> Option<String> {
        self.replicas
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.1 == did)
            .map(|row| row.0.clone())
    }

    async fn append_signed_event(
        &self,
        secret_key_hex: &str,
        event_type: &str,
        node_id: &str,
        payload: &serde_json::Value,
    ) -> Option<i64> {
        let mut guard = self.events.lock().unwrap();
        let seq = guard.len() as i64 + 1;
        // Hash-chain link: seed from the tip event's signature (#458).
        let prev_hash =
            crate::federation::prev_hash_from(guard.last().and_then(|e| e.sig.as_deref()));
        let event_id = uuid::Uuid::new_v4().to_string();
        let ts_ms = now_ms();
        let sig = crate::federation::sign_event(
            secret_key_hex,
            &event_id,
            event_type,
            seq,
            ts_ms,
            payload,
            &prev_hash,
        );
        guard.push(EventRow {
            seq,
            event_id,
            event_type: event_type.to_string(),
            node_id: node_id.to_string(),
            ts_ms,
            payload: payload.clone(),
            prev_hash: Some(prev_hash),
            sig,
        });
        Some(seq)
    }

    async fn events_since(&self, since_seq: i64, limit: u32) -> Vec<EventRow> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.seq > since_seq)
            .take(limit as usize)
            .cloned()
            .collect()
    }

    async fn snapshot_records(&self) -> Vec<NodeRecord> {
        self.records.lock().unwrap().clone()
    }

    async fn upsert_operator(
        &self,
        operator_pubkey: &str,
        display_name: Option<&str>,
        attested_created_at: Option<&str>,
        integrity_hash: Option<&str>,
    ) {
        let mut g = self.operators.lock().unwrap();
        match g.get_mut(operator_pubkey) {
            Some(row) => {
                // display_name is mutable; integrity_hash + first_seen pinned on first insert.
                if display_name.is_some() {
                    row.display_name = display_name.map(String::from);
                }
            }
            None => {
                g.insert(
                    operator_pubkey.to_string(),
                    OperatorRow {
                        display_name: display_name.map(String::from),
                        attested_created_at: attested_created_at.map(String::from),
                        integrity_hash: integrity_hash.map(String::from),
                        first_seen_ms: now_ms(),
                        identity_status: "active".to_string(),
                        ..Default::default()
                    },
                );
            }
        }
    }

    async fn operator_display_name(&self, operator_pubkey: &str) -> Option<String> {
        self.operators
            .lock()
            .unwrap()
            .get(operator_pubkey)
            .and_then(|r| r.display_name.clone())
    }

    async fn operator_display_name_claimed_by_other(
        &self,
        operator_pubkey: &str,
        normalized_display_name: &str,
    ) -> bool {
        self.operators.lock().unwrap().iter().any(|(op, row)| {
            op != operator_pubkey
                && row.identity_status == "active"
                && row
                    .display_name
                    .as_deref()
                    .and_then(crate::normalize_operator_display_name)
                    .as_deref()
                    == Some(normalized_display_name)
        })
    }

    async fn rename_operator(&self, operator_pubkey: &str, display_name: &str) -> bool {
        let mut g = self.operators.lock().unwrap();
        match g.get_mut(operator_pubkey) {
            Some(row) if row.identity_status == "active" => {
                row.display_name = Some(display_name.to_string());
                true
            }
            _ => false,
        }
    }

    async fn operator_identity_active(&self, operator_pubkey: &str) -> Option<bool> {
        self.operators
            .lock()
            .unwrap()
            .get(operator_pubkey)
            .map(|row| row.identity_status == "active")
    }

    async fn rotate_operator_identity(
        &self,
        old_operator_pubkey: &str,
        new_operator_pubkey: &str,
        requested_epoch: Option<u32>,
        _reason_class: &str,
    ) -> Result<OperatorLifecycleResult, OperatorLifecycleError> {
        if old_operator_pubkey == new_operator_pubkey {
            return Err(OperatorLifecycleError::Invalid);
        }
        let mut operators = self.operators.lock().unwrap();
        let old = operators
            .get(old_operator_pubkey)
            .cloned()
            .ok_or(OperatorLifecycleError::Unknown)?;
        if old.identity_status != "active" {
            return Err(OperatorLifecycleError::Inactive);
        }
        if operators.contains_key(new_operator_pubkey) {
            return Err(OperatorLifecycleError::SuccessorExists);
        }
        let epoch = old
            .rotation_epoch
            .unwrap_or(0)
            .saturating_add(1)
            .max(requested_epoch.unwrap_or(0));
        let mut successor = old.clone();
        successor.identity_status = "active".to_string();
        successor.rotation_epoch = None;
        operators.insert(new_operator_pubkey.to_string(), successor);
        let old_mut = operators
            .get_mut(old_operator_pubkey)
            .expect("old operator retained as lifecycle evidence");
        old_mut.identity_status = "rotated".to_string();
        old_mut.rotation_epoch = Some(epoch);
        drop(operators);

        let mut records = self.records.lock().unwrap();
        let mut linked_nodes = 0u32;
        for rec in records.iter_mut() {
            if rec.node.operator_pubkey.as_deref() == Some(old_operator_pubkey) {
                rec.node.operator_pubkey = Some(new_operator_pubkey.to_string());
                rec.node.operator_verified = true;
                // PolicyKeyLifecycle: the operator successor must re-issue its
                // independently signed policy; never silently rewrite it.
                rec.node.policy_manifest = None;
                linked_nodes = linked_nodes.saturating_add(1);
            }
        }
        Ok(OperatorLifecycleResult {
            linked_nodes,
            rotation_epoch: Some(epoch),
            revoked_at_unix: None,
        })
    }

    async fn revoke_operator_identity(
        &self,
        operator_pubkey: &str,
        _reason_class: &str,
    ) -> Result<OperatorLifecycleResult, OperatorLifecycleError> {
        let mut operators = self.operators.lock().unwrap();
        let row = operators
            .get_mut(operator_pubkey)
            .ok_or(OperatorLifecycleError::Unknown)?;
        if row.identity_status != "active" {
            return Err(OperatorLifecycleError::Inactive);
        }
        row.identity_status = "revoked".to_string();
        drop(operators);

        let mut records = self.records.lock().unwrap();
        let mut linked_nodes = 0u32;
        for rec in records.iter_mut() {
            if rec.node.operator_pubkey.as_deref() == Some(operator_pubkey) {
                rec.node.operator_verified = false;
                rec.node.operator_trust_tier = None;
                rec.node.policy_manifest = None;
                linked_nodes = linked_nodes.saturating_add(1);
            }
        }
        Ok(OperatorLifecycleResult {
            linked_nodes,
            rotation_epoch: None,
            revoked_at_unix: Some(now_ms() / 1000),
        })
    }

    async fn accept_operator_governance(
        &self,
        operator_pubkey: &str,
        terms_version: &str,
        dpa_version: &str,
        nonce_sha256: &str,
    ) -> Result<String, OperatorSelfServiceError> {
        let accepted_at = chrono::Utc::now().to_rfc3339();
        let mut operators = self.operators.lock().unwrap();
        let row = operators
            .get_mut(operator_pubkey)
            .ok_or(OperatorSelfServiceError::Unknown)?;
        if row.identity_status != "active" {
            return Err(OperatorSelfServiceError::Inactive);
        }
        row.terms_version = Some(terms_version.to_string());
        row.terms_accepted_at = Some(accepted_at.clone());
        row.dpa_version = Some(dpa_version.to_string());
        row.dpa_accepted_at = Some(accepted_at.clone());
        row.acceptance_method = Some("operator_key_challenge".to_string());
        row.acceptance_nonce_sha256 = Some(nonce_sha256.to_string());
        Ok(accepted_at)
    }

    async fn operator_dsr(
        &self,
        operator_pubkey: &str,
        action: &str,
        tracking_id: &str,
    ) -> Result<serde_json::Value, OperatorSelfServiceError> {
        let subject = in_memory_dsr_subject(self, operator_pubkey)?;
        if action == "export" {
            return Ok(in_memory_dsr_export(&subject, tracking_id));
        }
        apply_in_memory_dsr(self, operator_pubkey, action, tracking_id, &subject)
    }

    async fn record_dispatch_usage(&self, mode: &str) {
        if !matches!(
            mode,
            "public_view" | "legacy_dispatch" | "ticketed_dispatch"
        ) {
            return;
        }
        let date = chrono::Utc::now().date_naive().to_string();
        let mut usage = self.dispatch_usage.lock().unwrap();
        *usage.entry((date, mode.to_string())).or_default() += 1;
    }

    async fn dispatch_usage_summary(&self, days: u32) -> serde_json::Value {
        let days = days.clamp(1, 30);
        let start = chrono::Utc::now().date_naive()
            - chrono::Duration::days(i64::from(days.saturating_sub(1)));
        let usage = self.dispatch_usage.lock().unwrap();
        let mut ticketed = 0u64;
        let mut legacy = 0u64;
        let mut public = 0u64;
        for ((date, mode), count) in usage.iter() {
            if chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok_and(|date| date >= start) {
                match mode.as_str() {
                    "ticketed_dispatch" => ticketed += count,
                    "legacy_dispatch" => legacy += count,
                    "public_view" => public += count,
                    _ => {}
                }
            }
        }
        dispatch_usage_summary_value(days, ticketed, legacy, public)
    }

    async fn policy_key_lifecycle_status(&self, _policy_key_sha256: &str) -> Option<String> {
        None
    }

    async fn set_operator_recognition(
        &self,
        operator_pubkey: &str,
        ordinal: i64,
        tier: Option<&str>,
        badge: Option<&str>,
    ) {
        if let Some(row) = self.operators.lock().unwrap().get_mut(operator_pubkey) {
            row.ordinal = Some(ordinal);
            row.tier = tier.map(String::from);
            row.badge = badge.map(String::from);
        }
    }

    async fn list_founders(&self, limit: u32) -> Vec<FounderEntry> {
        let g = self.operators.lock().unwrap();
        let mut founders: Vec<FounderEntry> = g
            .values()
            .filter_map(|r| {
                r.ordinal.map(|ord| FounderEntry {
                    display_name: r.display_name.clone(),
                    ordinal: ord,
                    tier: r.tier.clone(),
                    badge: r.badge.clone(),
                })
            })
            .collect();
        founders.sort_by_key(|f| f.ordinal);
        founders.truncate(limit as usize);
        founders
    }

    async fn list_pending_founders(&self, limit: u32) -> Vec<PendingFounderEntry> {
        // Genuine served node per operator: verified + available. The public_reachable leg
        // of the gate lives only in the MySQL impl — in-memory nodes are never probed
        // (reachability_signal starts 0.0), and local/test mode has no real reachability.
        let served: std::collections::HashSet<String> = {
            let recs = self.records.lock().unwrap();
            recs.iter()
                .filter(|r| r.node.available && r.node.operator_verified)
                .filter_map(|r| r.node.operator_pubkey.clone())
                .collect()
        };
        let g = self.operators.lock().unwrap();
        let mut pending: Vec<(i64, PendingFounderEntry)> = g
            .iter()
            .filter(|(pk, r)| r.ordinal.is_none() && served.contains(*pk))
            .map(|(_, r)| {
                (
                    r.first_seen_ms,
                    PendingFounderEntry {
                        display_name: r.display_name.clone(),
                        first_seen_ms: r.first_seen_ms,
                    },
                )
            })
            .collect();
        pending.sort_by_key(|(fs, _)| *fs);
        pending.truncate(limit as usize);
        pending.into_iter().map(|(_, e)| e).collect()
    }
}

/// Unix milliseconds (event ts_ms), parity with PHP `(int)(microtime(true)*1000)`.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // #442: appending signed events produces a seq-monotonic log whose every signature
    // verifies — i.e. a Rust directory can emit a log a replica (PHP or Rust) can consume.
    #[tokio::test]
    async fn append_signed_event_produces_verifiable_log() {
        let pubkey = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        // libsodium key = seed(0x11*32) ‖ pubkey (the federation KAT key).
        let key = format!("{}{}", "11".repeat(32), pubkey);
        let repo = InMemoryRepo::new(vec![]);

        let s1 = repo
            .append_signed_event(
                &key,
                "REGISTER",
                "n1",
                &serde_json::json!({"endpoint": "http://x"}),
            )
            .await
            .unwrap();
        let s2 = repo
            .append_signed_event(&key, "DEREGISTER", "n1", &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!((s1, s2), (1, 2), "seq must be monotonic from 1");

        let log = repo.events_since(0, 100).await;
        assert_eq!(log.len(), 2);
        // #458: verify each signature AND the hash-chain continuity (recompute prev_hash in
        // seq order, seeding from GENESIS_ROOT, and check it matches the stored link).
        let mut expected_prev = crate::federation::GENESIS_ROOT.to_string();
        for row in &log {
            let sig = row.sig.as_ref().expect("event must be signed");
            assert_eq!(
                row.prev_hash.as_deref(),
                Some(expected_prev.as_str()),
                "stored prev_hash must equal the recomputed chain link"
            );
            let msg = crate::federation::event_message(
                &row.event_id,
                &row.event_type,
                row.seq,
                row.ts_ms,
                &row.payload,
                &expected_prev,
            );
            assert!(
                crate::federation::verify_event(pubkey, sig, &msg),
                "every emitted event's signature must verify"
            );
            expected_prev = crate::federation::prev_hash_from(Some(sig));
        }
        assert_eq!(
            log[0].prev_hash.as_deref(),
            Some(crate::federation::GENESIS_ROOT),
            "first event chains from GENESIS_ROOT"
        );
        // since_seq filters out already-consumed events.
        assert_eq!(repo.events_since(1, 100).await.len(), 1);
    }

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
            supported_profiles: vec![],
            capabilities: vec![],
            pricing: None,
            nat_type: None,
            transport_method: None,
            relay_capable: None,
            sdk_language: None,
            implementation_name: None,
            implementation_version: None,
            sdk_compatibility_version: None,
            sdk_version: None,
            consumer_cosignature_ready: false,
            backend: None,
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
            operator_pubkey: None,
            operator_display_name: None,
            operator_fingerprint: None,
            operator_verified: false,
            operator_trust_tier: None,
            public_listing: false,
            operator_url: None,
            policy_manifest: None,
            health_models: None,
            routing_policy: crate::types::RoutingPolicyState::default(),
        }
    }

    fn rec(id: &str, score: f64, available: bool, rep: f64, intents: &[&str]) -> NodeRecord {
        NodeRecord {
            node: node(id, score, available, rep),
            intents: intents.iter().map(|s| s.to_string()).collect(),
            capabilities: vec![],
            capability_profiles: std::collections::HashMap::new(),
            availability: vec![],
            node_token: None,
            node_hmac_key: None,
            proxy_token: None,
        }
    }

    const CHAT: &str = "urn:iicp:intent:llm:chat:v1";

    #[tokio::test]
    async fn discover_projects_profiles_for_the_selected_capability_only() {
        let mut record = rec(
            "profiled",
            0.9,
            true,
            0.8,
            &[CHAT, "urn:iicp:intent:embed:v1"],
        );
        record.capability_profiles.insert(
            CHAT.to_string(),
            vec!["urn:iicp:profile:service-lifecycle:v1".to_string()],
        );
        record.capability_profiles.insert(
            "urn:iicp:intent:embed:v1".to_string(),
            vec!["urn:iicp:profile:embedding-batch-v1".to_string()],
        );
        let repo = InMemoryRepo::new(vec![record]);
        let nodes = repo
            .discover(&DiscoverQuery {
                intent: CHAT.to_string(),
                ..DiscoverQuery::default()
            })
            .await;
        assert_eq!(
            nodes[0].supported_profiles,
            vec!["urn:iicp:profile:service-lifecycle:v1"]
        );
    }

    #[tokio::test]
    async fn list_public_lists_available_excludes_unavailable() {
        // Registry parity (ADR-017 / iicp-dir §3.10a): the public listing surfaces
        // *available* nodes and is NOT gated on `public_listing` (that flag only
        // controls operator_url exposure). Regression guard for the federation bug
        // where `MySqlRepo::list_public` filtered `WHERE public_listing = 1` and a
        // node replicated from the seed (public_listing defaulting to 0) never showed.
        let repo = InMemoryRepo::new(vec![
            rec("up", 0.9, true, 0.8, &[CHAT]),
            rec("down", 0.5, false, 0.8, &[CHAT]), // unavailable → must be excluded
        ]);
        let listed: Vec<String> = repo
            .list_public(0, 50)
            .await
            .into_iter()
            .map(|n| n.node_id)
            .collect();
        assert!(
            listed.contains(&"up".to_string()),
            "available node must be listed"
        );
        assert!(
            !listed.contains(&"down".to_string()),
            "unavailable node must not be listed: {listed:?}"
        );
    }

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
    async fn outcome_v2_does_not_decay_with_elapsed_time() {
        let repo = InMemoryRepo::new(vec![
            rec("hi", 0.9, true, 0.9, &[CHAT]),
            rec("lo", 0.5, true, 0.28, &[CHAT]),
        ]);
        let count = repo.decay_reputation_pass().await;
        assert_eq!(count, 0);
        let hi = repo.get("hi").await.unwrap();
        assert!((hi.reputation_score - 0.9).abs() < 1e-6);
        let lo = repo.get("lo").await.unwrap();
        assert!((lo.reputation_score - 0.28).abs() < 1e-6);
    }

    // SECURITY (#404): operator_pubkey is the directory-private operator identity (ADR-045)
    // and MUST NEVER be serialized into any Node response (/v1/node/:id, discover, bootstrap,
    // peers). Fails if the skip_serializing guard regresses — which would leak a bound node's
    // operator key (e.g. the maintainer's #1 founder key) on the public node-detail endpoint.
    #[test]
    fn node_serialization_never_includes_operator_pubkey() {
        let mut n = node("550e8400-e29b-41d4-a716-446655440000", 0.9, true, 0.9);
        n.operator_pubkey = Some("SECRET_OPERATOR_KEY".into());
        n.operator_verified = true;
        let json = serde_json::to_string(&n).unwrap();
        assert!(
            !json.contains("operator_pubkey"),
            "operator_pubkey key must not be serialized: {json}"
        );
        assert!(
            !json.contains("SECRET_OPERATOR_KEY"),
            "operator_pubkey value must not leak: {json}"
        );
    }

    // Registry node-detail prefix lookup (PHP parity). #404 behavior test: fails if the
    // handler resolves by exact id only (the bug — exact get() can't find a UUID by its
    // 8-hex prefix) or returns unavailable nodes.
    #[tokio::test]
    async fn node_by_prefix_resolves_uuid_prefix_exact_and_available_only() {
        let full = "b33d00e5-1111-4222-8333-444455556666";
        let a = rec(full, 0.9, true, 0.9, &[CHAT]);
        let unavail = rec(
            "c0ffee00-0000-4000-8000-000000000000",
            0.9,
            false,
            0.9,
            &[CHAT],
        );
        let repo = InMemoryRepo::new(vec![a, unavail]);

        // 8-hex UUID prefix resolves to the full-id available node (the website's path).
        assert_eq!(
            repo.node_by_prefix("b33d00e5").await.map(|n| n.node_id),
            Some(full.to_string())
        );
        // Exact full id still resolves.
        assert_eq!(
            repo.node_by_prefix(full).await.map(|n| n.node_id),
            Some(full.to_string())
        );
        // A non-matching prefix → None.
        assert!(repo.node_by_prefix("deadbeef").await.is_none());
        // An unavailable node is NOT returned by its prefix (available-only, PHP parity).
        assert!(repo.node_by_prefix("c0ffee00").await.is_none());
    }

    // WQ-057 — quote candidate set. #404: fails if the intent/availability/reputation
    // scoping of the multiplier list is wrong (which would mis-price the quote).
    #[tokio::test]
    async fn quote_multipliers_scopes_by_intent_availability_reputation() {
        let mut a = rec("a", 0.9, true, 0.9, &[CHAT]);
        a.node.credit_cost_multiplier = 1.0;
        let mut b = rec("b", 0.9, true, 0.9, &[CHAT]);
        b.node.credit_cost_multiplier = 3.0;
        let mut low_rep = rec("c", 0.9, true, 0.5, &[CHAT]); // reputation below floor
        low_rep.node.credit_cost_multiplier = 5.0;
        let mut other = rec("d", 0.9, true, 0.9, &["urn:iicp:intent:other:x:v1"]); // wrong intent
        other.node.credit_cost_multiplier = 9.0;
        let mut down = rec("e", 0.9, false, 0.9, &[CHAT]); // unavailable
        down.node.credit_cost_multiplier = 7.0;
        let repo = InMemoryRepo::new(vec![a, b, low_rep, other, down]);

        let mut m = repo.quote_multipliers(CHAT, 0.7).await;
        m.sort_by(|x, y| x.partial_cmp(y).unwrap());
        // Only a (1.0) and b (3.0): c below rep floor, d wrong intent, e unavailable.
        assert_eq!(m, vec![1.0, 3.0]);
    }

    // #466 v1 — operator wallet rollup. #404 behavior test: fails if the operator-scoping
    // (counting the wrong operator's nodes) or the null-when-unbound guard is wrong.
    #[tokio::test]
    async fn operator_wallet_scopes_by_operator_and_nulls_when_unbound() {
        let mut a = rec("node-a", 0.9, true, 0.9, &[CHAT]);
        a.node.operator_pubkey = Some("OP1".into());
        let mut b = rec("node-b", 0.9, true, 0.9, &[CHAT]);
        b.node.operator_pubkey = Some("OP1".into());
        let mut c = rec("node-c", 0.9, true, 0.9, &[CHAT]);
        c.node.operator_pubkey = Some("OP2".into());
        let d = rec("node-d", 0.9, true, 0.9, &[CHAT]); // unbound (operator_pubkey None)
        let repo = InMemoryRepo::new(vec![a, b, c, d]);

        // OP1 owns node-a + node-b (count 2); OP2's node-c and unbound node-d excluded.
        assert_eq!(repo.operator_wallet("node-a").await, Some((0.0, 2)));
        let rich = repo.operator_wallet_summary("node-a").await.unwrap();
        assert_eq!(rich.node_count, 2);
        assert_eq!(rich.total_balance, 0.0);
        assert!(rich.reconciles);
        assert_eq!(rich.operator_fingerprint, operator_fingerprint("OP1"));
        // OP2 owns only node-c.
        assert_eq!(repo.operator_wallet("node-c").await, Some((0.0, 1)));
        // Unbound node and unknown node → null wallet.
        assert_eq!(repo.operator_wallet("node-d").await, None);
        assert_eq!(repo.operator_wallet("nope").await, None);
    }
}

// SPDX-License-Identifier: Apache-2.0
//! MySQL-backed node repository — the Phase 1 data layer (PARITY: M3b).
//!
//! Drops in behind the same `NodeRepository` trait as `InMemoryRepo` so all
//! HTTP handlers remain unchanged. Activated when `DATABASE_URL` is set at
//! startup. Falls back to `InMemoryRepo` when it is not.

use async_trait::async_trait;
use sha2::Digest;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};

use crate::repo::{
    operator_fingerprint, AuditResult, ConformanceBadge, CreditError, CreditSummary,
    CreditTransaction, DiscoverQuery, EffectiveCreditBalance, EventRow, FounderEntry,
    IntentSummary, NodeRecord, NodeRepository, OperatorLifecycleError, OperatorLifecycleResult,
    OperatorWalletSummary, PendingFounderEntry, ProbeResult, ProxyObservation, RegistryStats,
    WalletDebitResult,
};
use crate::reputation;
use crate::types::Node;

// ── EMA helper ───────────────────────────────────────────────────────────────

/// Apply proxy-observed latency EMA to nodes.avg_latency_ms (iicp-telemetry §4.3).
/// Called only when the Sybil quorum gate has already been satisfied (distinct_proxies ≥ 3).
/// Alpha = 0.1 normally; reduced to 0.01 when the reporting proxy is a sustained outlier
/// (≥ 10 observations AND this report exceeds 3× the 24-hour median).
async fn update_latency_ema(pool: &Pool<MySql>, node_id: &str, proxy_id: &str, latency: u32) {
    let proxy_obs: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*) FROM proxy_telemetry WHERE node_id = ? AND proxy_node_id = ?",
    )
    .bind(node_id)
    .bind(proxy_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let proxy_obs_count = proxy_obs.map(|(n,)| n).unwrap_or(0);

    let outlier_weight: f64 = if proxy_obs_count >= 10 {
        let recent: Vec<(f64,)> = sqlx::query_as(
            "SELECT latency_ms_observed FROM proxy_telemetry \
             WHERE node_id = ? AND latency_ms_observed IS NOT NULL \
             AND created_at >= NOW() - INTERVAL 24 HOUR ORDER BY latency_ms_observed",
        )
        .bind(node_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        median_outlier_weight(latency as f64, &recent)
    } else {
        1.0
    };

    let cur: Option<(f64,)> = sqlx::query_as("SELECT avg_latency_ms FROM nodes WHERE node_id = ?")
        .bind(node_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    let alpha = 0.1 * outlier_weight;
    let new_ema = match cur.map(|(v,)| v) {
        Some(c) if c > 0.0 => alpha * latency as f64 + (1.0 - alpha) * c,
        _ => latency as f64,
    };
    let _ = sqlx::query("UPDATE nodes SET avg_latency_ms = ? WHERE node_id = ?")
        .bind((new_ema * 100.0).round() / 100.0)
        .bind(node_id)
        .execute(pool)
        .await;
}

/// Returns 0.1 if `value` is a 3× outlier relative to the sorted sample, else 1.0.
fn median_outlier_weight(value: f64, sorted_sample: &[(f64,)]) -> f64 {
    if sorted_sample.len() < 2 {
        return 1.0;
    }
    let n = sorted_sample.len();
    let median = if n.is_multiple_of(2) {
        (sorted_sample[n / 2 - 1].0 + sorted_sample[n / 2].0) / 2.0
    } else {
        sorted_sample[n / 2].0
    };
    if median > 0.0 && value > 3.0 * median {
        0.1
    } else {
        1.0
    }
}

// ── DB row ────────────────────────────────────────────────────────────────────

/// Raw row from the `nodes` table. FLOAT columns map to f32 in MySQL via sqlx;
/// they are widened to f64 in `From<NodeRow> for Node`.
#[derive(sqlx::FromRow)]
struct NodeRow {
    id: String,
    endpoint: String,
    region: String,
    reputation_score: f32,
    available: bool,
    load: f32,
    active_jobs: u32,
    max_concurrent: u32,
    tasks_total: u32,
    avg_latency_ms: f32,
    exposure_mode: Option<String>,
    transport_endpoint: Option<String>,
    // #400 — discover field parity with PHP (NodeScorer emits these).
    #[sqlx(default)]
    credit_cost_multiplier: f32,
    #[sqlx(default)]
    pricing_model: Option<String>,
    #[sqlx(default)]
    attested: bool,
    // #385 Phase-B — failure count for the success-ratio health signal.
    #[sqlx(default)]
    tasks_failed: u32,
    // #385 Phase-B — reachability health signal inputs (PHP NodeHealthService
    // reachabilityScore fallback). sqlx(default) guards any SELECT that omits them.
    #[sqlx(default)]
    public_reachable: bool,
    #[sqlx(default)]
    relay_capable: bool,
    // #531 adoption telemetry — SDK provenance reported at registration.
    #[sqlx(default)]
    sdk_language: Option<String>,
    #[sqlx(default)]
    sdk_version: Option<String>,
    // ADR-045 Phase A (#407) — verified operator identity binding (PHP parity, #385).
    #[sqlx(default)]
    operator_pubkey: Option<String>,
    #[sqlx(default)]
    operator_verified: bool,
    #[sqlx(default)]
    operator_trust_tier: Option<String>,
    // WQ-058 / ADR-017 REG-01 — operator public-listing opt-in + advertised URL.
    #[sqlx(default)]
    public_listing: bool,
    #[sqlx(default)]
    operator_url: Option<String>,
    // #494 — runtime model list from the node's last heartbeat. JSON-encoded array.
    // null = not yet reported (backward compat); []/"[]" = no models live.
    #[sqlx(default)]
    health_models: Option<String>,
}

fn tier_from_score(s: f64) -> String {
    // PHP NodeScorer thresholds (S.12 §5.1.1 REP2, CIP spec v0.6.9).
    // "bronze" is the floor tier for all sub-Silver nodes; "none" is retired (2026-05-30).
    if s >= 0.85 {
        "platinum".into()
    } else if s >= 0.65 {
        "gold".into()
    } else if s >= 0.40 {
        "silver".into()
    } else {
        "bronze".into()
    }
}

/// Pure idle-determination for the 90-day TTL credit sink (the rule the sweep applies).
///
/// A node is "idle" — its unspent balance forfeit — when its newest earn's `expires_at`
/// is strictly in the past AND it still holds a positive balance. A node with no earn rows
/// carrying a TTL (`max_earn_expires_at_unix == None`) is NOT swept: its TTL is
/// indeterminable, so we never expire on a guess (matches the PHP `expireIdleNodeCredits`
/// which keys off determinable earn TTLs). Extracted as a pure fn so the rule is unit-tested
/// in-process (the SQL sweep in `expire_idle_node_credits` encodes the same predicate).
fn credit_ttl_idle(max_earn_expires_at_unix: Option<i64>, balance: f64, now_unix: i64) -> bool {
    matches!(max_earn_expires_at_unix, Some(exp) if exp < now_unix) && balance > 0.0
}

impl From<NodeRow> for Node {
    fn from(r: NodeRow) -> Self {
        let rep = r.reputation_score as f64;
        let lat = r.avg_latency_ms as f64;
        Node {
            node_id: r.id,
            endpoint: r.endpoint,
            region: r.region,
            score: rep,
            available: r.available,
            load: r.load as f64,
            active_jobs: r.active_jobs,
            max_concurrent: r.max_concurrent,
            reputation_score: rep,
            latency_estimate_ms: if lat > 0.0 { Some(lat as u32) } else { None },
            completed_tasks_count: r.tasks_total as u64,
            // ADR-044 health vector computed from full telemetry — deferred to Phase 2.
            health_label: None,
            exposure_mode: r.exposure_mode,
            reputation_tier: Some(tier_from_score(rep)),
            transport_endpoint: r.transport_endpoint,
            // allow_remote_inference not yet tracked — default CIP-None (S.12 §5.2 REP1).
            cip_conformance_level: Some("CIP-None".to_string()),
            models: vec![],
            pricing: None,
            // Phase 5 fields — MySQL columns pending Phase 5 migration; default None/empty.
            nat_type: None,
            transport_method: None,
            // #385 — relay_capable now persisted (PHP discover emits it; NodeScorer:221).
            relay_capable: Some(r.relay_capable),
            sdk_language: r.sdk_language,
            sdk_version: r.sdk_version,
            address_family: None, // set at query time by detect_address_family
            cip_policy: Some(serde_json::json!({
                "allow_remote_inference": false, "allow_tool_execution": false,
                "allow_file_access": false, "pricing_credits_per_1000": null
            })),
            quantization: vec![],
            inference_engine: vec![],
            public_key: None,
            transport_metadata: None,
            // #400 — discover field parity. credit_cost_multiplier defaults to
            // 1.0 when the column was absent (sqlx default → 0.0 → coerce to 1.0).
            credit_cost_multiplier: if r.credit_cost_multiplier > 0.0 {
                r.credit_cost_multiplier as f64
            } else {
                1.0
            },
            pricing_model: r.pricing_model.or_else(|| Some("per_token".to_string())),
            attested: r.attested,
            tasks_failed: r.tasks_failed as u64, // #385 Phase-B success signal
            transport: vec![],                   // #397 — set at discover time (server-derived)
            // #385 Phase-B — reachability health signal (PHP reachabilityScore fallback).
            reachability_signal: crate::health::reachability_from_flags(
                r.public_reachable,
                r.relay_capable,
            ),
            // ADR-045 Phase A (#407/#385) — verified operator identity binding, persisted
            // (migration 005); `#[sqlx(default)]` keeps SELECTs that omit the columns safe.
            operator_pubkey: r.operator_pubkey,
            operator_display_name: None,
            operator_fingerprint: None,
            operator_verified: r.operator_verified,
            operator_trust_tier: r.operator_trust_tier,
            public_listing: r.public_listing,
            operator_url: r.operator_url,
            // #494 — decode JSON-encoded health_models from DB (null → None, "[]" → Some([])).
            health_models: r
                .health_models
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}

// ── MySqlRepo ─────────────────────────────────────────────────────────────────

pub struct MySqlRepo {
    pool: Pool<MySql>,
}

impl MySqlRepo {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

/// Initialise a connection pool from `DATABASE_URL`.
/// Callers are responsible for running `sqlx::migrate!("./migrations").run(&pool)` before
/// use — this must happen from main.rs because the macro resolves paths relative to the
/// calling file (a proc-macro limitation).
pub async fn init_pool(url: &str) -> Result<Pool<MySql>, sqlx::Error> {
    MySqlPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
}

// ── discover constants (mirrors repo.rs) ─────────────────────────────────────
const MIN_SCORE: f64 = 0.1;
const DEFAULT_LIMIT: u32 = 10;
const MAX_LIMIT: u32 = 50;

#[async_trait]
impl NodeRepository for MySqlRepo {
    /// Discovery: JOIN nodes + capabilities, filter, sort by reputation DESC, truncate.
    /// Mirrors InMemoryRepo::discover + PHP NodeRegistry::discover.
    async fn discover(&self, q: &DiscoverQuery) -> Vec<Node> {
        let min_rep = q.min_reputation.unwrap_or(MIN_SCORE).max(MIN_SCORE) as f32;
        let limit = match q.limit {
            0 => DEFAULT_LIMIT,
            n if n as u32 > MAX_LIMIT => MAX_LIMIT,
            n => n as u32,
        };
        let rows: Vec<NodeRow> = sqlx::query_as(
            r#"SELECT n.id, n.endpoint, n.region, n.reputation_score, n.available,
                      n.load, n.active_jobs, n.max_concurrent, n.tasks_total,
                      n.avg_latency_ms, n.exposure_mode, n.transport_endpoint,
                      n.credit_cost_multiplier, n.pricing_model, n.attested, n.tasks_failed,
                      n.public_reachable, n.relay_capable
               FROM nodes n
               INNER JOIN capabilities c ON c.node_id = n.id
               WHERE c.intent = ?
                 AND n.available = 1
                 AND n.reputation_score >= ?
                 AND (n.last_seen IS NULL OR n.last_seen >= NOW() - INTERVAL 90 SECOND)
               ORDER BY n.reputation_score DESC
               LIMIT ?"#,
        )
        .bind(&q.intent)
        .bind(min_rep)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().map(Node::from).collect()
    }

    /// Register (or re-register) a node. Uses INSERT … ON DUPLICATE KEY UPDATE so that
    /// re-registering with the same node_id is idempotent and preserves reputation_score
    /// (ADR-026 anti-laundering). Capabilities are delete-then-insert (atomic within the
    /// same implicit transaction; a real transaction wraps this in Phase 2 hardening).
    async fn register(&self, rec: NodeRecord) {
        // Bcrypt-hash node_token and proxy_token concurrently (cost 12 = PHP default).
        let plain_token = rec.node_token.clone().unwrap_or_default();
        let plain_proxy = rec.proxy_token.clone().unwrap_or_default();
        let (token_hash, proxy_hash) = tokio::join!(
            tokio::task::spawn_blocking({
                let t = plain_token.clone();
                move || bcrypt::hash(&t, 12).unwrap_or(t)
            }),
            tokio::task::spawn_blocking({
                let p = plain_proxy.clone();
                move || bcrypt::hash(&p, 12).unwrap_or(p)
            }),
        );
        let token_hash = token_hash.unwrap_or(plain_token);
        let proxy_hash = proxy_hash.unwrap_or(plain_proxy);
        let hmac_key = rec.node_hmac_key.clone().unwrap_or_default();

        let _ = sqlx::query(
            r#"INSERT INTO nodes
                 (id, endpoint, region, available, relay_capable, node_token_hash, node_hmac_key,
                  proxy_token_hash, max_concurrent, tokens_per_min, reputation_score, status,
                  operator_pubkey, operator_verified, operator_trust_tier,
                  public_listing, operator_url)
               VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, 0, ?, 'active', ?, ?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE
                 endpoint           = VALUES(endpoint),
                 region             = VALUES(region),
                 available          = 1,
                 relay_capable      = VALUES(relay_capable),
                 status             = 'active',
                 node_token_hash    = VALUES(node_token_hash),
                 node_hmac_key      = VALUES(node_hmac_key),
                 proxy_token_hash   = VALUES(proxy_token_hash),
                 -- ADR-045 Phase A (#407/#385) — re-register rebinds the operator identity.
                 operator_pubkey     = VALUES(operator_pubkey),
                 operator_verified   = VALUES(operator_verified),
                 operator_trust_tier = VALUES(operator_trust_tier),
                 -- WQ-058 / ADR-017 REG-01 — re-register updates the public-listing opt-in.
                 public_listing      = VALUES(public_listing),
                 operator_url        = VALUES(operator_url)
                 -- reputation_score intentionally NOT updated (ADR-026 anti-laundering)"#,
        )
        .bind(&rec.node.node_id)
        .bind(&rec.node.endpoint)
        .bind(&rec.node.region)
        .bind(rec.node.relay_capable.unwrap_or(false))
        .bind(&token_hash)
        .bind(&hmac_key)
        .bind(&proxy_hash)
        .bind(rec.node.max_concurrent)
        .bind(reputation::STARTING_SCORE as f32)
        .bind(&rec.node.operator_pubkey)
        .bind(rec.node.operator_verified)
        .bind(&rec.node.operator_trust_tier)
        .bind(rec.node.public_listing)
        .bind(&rec.node.operator_url)
        .execute(&self.pool)
        .await;

        // Replace capabilities: delete + re-insert (the node_id FK CASCADE keeps referential
        // integrity; the round-trip is safe because capabilities are operationally immutable
        // between re-registrations in the current spec).
        let _ = sqlx::query("DELETE FROM capabilities WHERE node_id = ?")
            .bind(&rec.node.node_id)
            .execute(&self.pool)
            .await;

        for intent in &rec.intents {
            let _ = sqlx::query(
                "INSERT INTO capabilities (node_id, intent, models, max_tokens) VALUES (?, ?, '[]', 0)"
            )
            .bind(&rec.node.node_id)
            .bind(intent)
            .execute(&self.pool)
            .await;
        }
    }

    /// Heartbeat: update load/available/last_seen and apply the reputation delta (RT-01
    /// capped by `reputation::apply_delta`). Returns the new score, or None if unknown.
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
        health_models: Option<Vec<String>>,
    ) -> Option<f64> {
        // RT-01b (#381): fetch velocity window alongside score.
        let row: Option<(f32, f32, Option<chrono::NaiveDateTime>)> = sqlx::query_as(
            "SELECT reputation_score, rep_hourly_gain, rep_hourly_window_start \
             FROM nodes WHERE id = ?",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        let (old_score_f32, hourly_gain_f32, window_start) = row?;

        // RT-01b: compute effective delta with hourly velocity ceiling (0.20/h/node)
        const MAX_HOURLY_GAIN: f64 = 0.20;
        let (effective_delta, new_hourly_gain, reset_window) = if delta > 0.0 {
            let window_expired = window_start
                .map(|ws| {
                    let now = chrono::Utc::now().naive_utc();
                    (now - ws).num_seconds() >= 3600
                })
                .unwrap_or(true);

            let current_gain = if window_expired {
                0.0f64
            } else {
                hourly_gain_f32 as f64
            };

            let remaining = (MAX_HOURLY_GAIN - current_gain).max(0.0);
            let capped = delta.min(remaining);
            (
                capped,
                current_gain + capped,
                window_expired || window_start.is_none(),
            )
        } else {
            (delta, hourly_gain_f32 as f64, false)
        };

        let new_score = reputation::apply_delta(old_score_f32 as f64, effective_delta);

        // #494 — encode health_models as JSON when the SDK reported a live list.
        let health_models_json: Option<String> = health_models
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "[]".to_string()));

        let _ = sqlx::query(
            "UPDATE nodes SET `load` = ?, available = ?, active_jobs = ?, \
             reputation_score = ?, tasks_total = tasks_total + ?, \
             tasks_failed = tasks_failed + ?, \
             rep_hourly_gain = ?, \
             rep_hourly_window_start = CASE WHEN ? = 1 THEN NOW() ELSE rep_hourly_window_start END, \
             health_models = COALESCE(?, health_models), \
             status = 'active', last_seen = NOW() WHERE id = ?",
        )
        .bind(load as f32)
        .bind(available)
        .bind(active_jobs)
        .bind(new_score as f32)
        .bind(tasks_delta)
        .bind(tasks_failed_delta)
        .bind(new_hourly_gain as f32)
        .bind(reset_window as i32)
        .bind(health_models_json)
        .bind(node_id)
        .execute(&self.pool)
        .await;

        Some(new_score)
    }

    /// Fetch a single node by id for the node-detail endpoint (iicp-dir §3.4.x).
    async fn get(&self, node_id: &str) -> Option<Node> {
        let row: Option<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                      max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                      credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable,
                      operator_pubkey, operator_verified, operator_trust_tier
               FROM nodes WHERE id = ?"#,
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        row.map(Node::from)
    }

    async fn node_by_prefix(&self, prefix: &str) -> Option<Node> {
        // PHP RegistryController::show parity — exact id OR id-prefix (UUID 8-hex prefix or
        // custom name), AVAILABLE only, exact match preferred. The website resolves node
        // detail by 8-hex prefix, so exact-only get() would 404 those.
        let row: Option<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                      max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                      credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable,
                      operator_pubkey, operator_verified, operator_trust_tier
               FROM nodes
               WHERE (id = ? OR id LIKE CONCAT(?, '%')) AND available = 1
               ORDER BY (id = ?) DESC
               LIMIT 1"#,
        )
        .bind(prefix)
        .bind(prefix)
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        row.map(Node::from)
    }

    /// Active nodes within the 90-second liveness window (iicp-dir §3.9b).
    async fn active_count(&self) -> u32 {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COUNT(DISTINCT id) FROM nodes \
             WHERE available = 1 \
             AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND)",
        )
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        row.map(|(n,)| n as u32).unwrap_or(0)
    }

    /// Bootstrap: return recently-seen active nodes sorted by last_seen desc (iicp-dir §3.7).
    async fn bootstrap(&self, limit: usize) -> Vec<Node> {
        let rows: Vec<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                      max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                      credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, sdk_language, sdk_version
               FROM nodes
               WHERE available = 1
                 AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND)
               ORDER BY last_seen DESC
               LIMIT ?"#,
        )
        .bind(limit as u32)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter().map(Node::from).collect()
    }

    /// Active provider set (available + heartbeat-fresh) — full, unlimited, for
    /// the `/v1/stats` `mesh_health` aggregate (ADR-044). Same liveness predicate
    /// as `bootstrap`/`active_count`, no LIMIT.
    async fn active_nodes(&self) -> Vec<Node> {
        let rows: Vec<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                      max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                      credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable
               FROM nodes
               WHERE available = 1
                 AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND)"#,
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter().map(Node::from).collect()
    }

    /// Deregister: hard-delete the node row. Capabilities are removed via CASCADE.
    /// Credits (on nodes.credit_balance) are lost — matching PHP deregister behavior.
    async fn deregister(&self, node_id: &str) -> bool {
        let result = sqlx::query("DELETE FROM nodes WHERE id = ?")
            .bind(node_id)
            .execute(&self.pool)
            .await;
        result.map(|r| r.rows_affected() > 0).unwrap_or(false)
    }

    /// Token verification via bcrypt::verify (matches PHP password_verify).
    /// Fetches the stored bcrypt hash by node_id, then runs verify in a blocking thread
    /// (bcrypt is intentionally CPU-intensive — must not block the tokio runtime thread).
    async fn verify_node_token(&self, node_id: &str, token: &str) -> bool {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT node_token_hash FROM nodes WHERE id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        let Some((hash,)) = row else {
            return false;
        };
        let token_owned = token.to_string();
        tokio::task::spawn_blocking(move || bcrypt::verify(&token_owned, &hash).unwrap_or(false))
            .await
            .unwrap_or(false)
    }

    /// Peer exchange: return active nodes NOT in known_ids (iicp-dir §3.5).
    /// Used by `POST /v1/peers`. SQL uses NOT IN — safe because known_ids is bounded
    /// by the handler (max 20 entries per the spec limit).
    async fn peers_excluding(&self, known_ids: &[String], limit: usize) -> Vec<Node> {
        let cap = match limit {
            0 => 10u32,
            n if n > 20 => 20u32,
            n => n as u32,
        };
        // Build the NOT IN clause dynamically — known_ids is caller-bounded (max 20).
        if known_ids.is_empty() {
            let rows: Vec<NodeRow> = sqlx::query_as(
                r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                          max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                          credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable
                   FROM nodes
                   WHERE available = 1
                     AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND)
                   ORDER BY last_seen DESC
                   LIMIT ?"#,
            )
            .bind(cap)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
            return rows.into_iter().map(Node::from).collect();
        }

        // Fetch all candidates and filter in Rust to avoid dynamic SQL binding complexity.
        // known_ids is bounded (max 20) so this is safe — no unbounded IN clause.
        let rows: Vec<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                      max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                      credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable
               FROM nodes
               WHERE available = 1
                 AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND)
               ORDER BY last_seen DESC
               LIMIT 100"#,
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .filter(|r| !known_ids.contains(&r.id))
            .take(cap as usize)
            .map(Node::from)
            .collect()
    }

    /// Expire stale nodes — mark available=0 and status='dormant' for nodes whose
    /// last_seen is older than 90 seconds. Called every 60s by the background task.
    /// Mirrors PHP `ExpireStaleNodes` command; returns count of nodes affected.
    async fn expire_stale(&self) -> Vec<String> {
        // Fetch IDs before updating so EVICT events can be emitted per node (#508).
        let ids: Vec<(String,)> = sqlx::query_as(
            "SELECT id FROM nodes \
             WHERE status = 'active' \
               AND last_seen IS NOT NULL \
               AND last_seen < NOW() - INTERVAL 90 SECOND",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        if ids.is_empty() {
            return vec![];
        }

        let id_list: Vec<&str> = ids.iter().map(|(id,)| id.as_str()).collect();
        let placeholders = id_list.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "UPDATE nodes SET available = 0, status = 'dormant', dormant_since = NOW() \
             WHERE id IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql);
        for id in &id_list {
            q = q.bind(*id);
        }
        let _ = q.execute(&self.pool).await;

        ids.into_iter().map(|(id,)| id).collect()
    }

    /// Reputation decay — apply -0.005 per pass (hourly), floor 0.30.
    /// Single UPDATE touches only nodes above the floor (iicp-semantics §11 decay rule).
    async fn decay_reputation_pass(&self) -> u32 {
        let result = sqlx::query(
            "UPDATE nodes \
             SET reputation_score = GREATEST(0.30, reputation_score - 0.005) \
             WHERE status = 'active' AND reputation_score > 0.30",
        )
        .execute(&self.pool)
        .await;
        result.map(|r| r.rows_affected() as u32).unwrap_or(0)
    }

    /// Public node listing (ADR-017 registry, iicp-dir §3.10a). Mirrors the PHP
    /// `RegistryController::index` filter: active + available nodes (NOT gated on
    /// `public_listing` — that flag only controls `operator_url` exposure, REG-01).
    /// A node registered via the federation event log (`last_seen` still NULL) counts
    /// as active, so replicated nodes surface here. Endpoint is NOT returned.
    async fn list_public(&self, offset: u64, limit: usize) -> Vec<Node> {
        let cap = limit.min(100) as u32;
        let rows: Vec<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                      max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                      credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, public_listing, operator_url
               FROM nodes
               WHERE available = 1
                 AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND)
               ORDER BY last_seen DESC
               LIMIT ? OFFSET ?"#,
        )
        .bind(cap)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .map(|r| {
                let mut n = Node::from(r);
                n.endpoint = String::new(); // ADR-017: endpoint not exposed in public listing
                n
            })
            .collect()
    }

    /// Registry aggregate stats (iicp-dir §3.10b).
    async fn registry_stats(&self) -> RegistryStats {
        let total: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM nodes")
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten();
        let active: Option<(i64,)> =
            sqlx::query_as("SELECT COUNT(*) FROM nodes WHERE available = 1 AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND)")
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        // Regional distribution over active nodes, ordered by count desc (PHP buildStats).
        let region_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT COALESCE(region, '') AS region, COUNT(*) AS cnt FROM nodes \
             WHERE available = 1 AND (last_seen IS NULL OR last_seen >= NOW() - INTERVAL 90 SECOND) \
             GROUP BY region ORDER BY cnt DESC, region ASC",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        // Intent coverage — distinct active nodes per intent URN, ordered by count desc.
        let intent_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT capabilities.intent AS intent, COUNT(DISTINCT nodes.id) AS cnt \
             FROM capabilities JOIN nodes ON nodes.id = capabilities.node_id \
             WHERE nodes.available = 1 AND (nodes.last_seen IS NULL OR nodes.last_seen >= NOW() - INTERVAL 90 SECOND) \
             GROUP BY capabilities.intent ORDER BY cnt DESC, intent ASC",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let regions: Vec<String> = region_rows.iter().map(|(r, _)| r.clone()).collect();
        let region_breakdown: std::collections::HashMap<String, u32> = region_rows
            .into_iter()
            .map(|(r, c)| (r, c as u32))
            .collect();
        let intents_supported: Vec<String> = intent_rows.iter().map(|(i, _)| i.clone()).collect();
        let intent_coverage: std::collections::HashMap<String, u32> = intent_rows
            .into_iter()
            .map(|(i, c)| (i, c as u32))
            .collect();

        let total_n = total.map(|(n,)| n as u64).unwrap_or(0);
        let active_n = active.map(|(n,)| n as u64).unwrap_or(0);
        RegistryStats {
            total_nodes: total_n,
            active_nodes: active_n,
            regions,
            region_breakdown,
            intent_coverage,
            intents_supported,
        }
    }

    /// Credit balance from the denormalized nodes.credit_balance column (W-042 D1prime).
    async fn credit_balance(&self, node_id: &str) -> Option<f64> {
        // CAST AS DOUBLE: credit_balance is DECIMAL(15,4); sqlx cannot decode DECIMAL
        // straight into f64, so the bare SELECT errored → None → spurious 404 on every
        // credits endpoint. The cast yields a DOUBLE that decodes cleanly. (#456)
        let row: Option<(f64,)> =
            sqlx::query_as("SELECT CAST(credit_balance AS DOUBLE) FROM nodes WHERE id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        row.map(|(b,)| b)
    }

    async fn credit_summary(&self, node_id: &str) -> Option<CreditSummary> {
        let balance = self.credit_balance(node_id).await?;
        // CAST AS DOUBLE so the DECIMAL(15,4) sum decodes straight into f64 (matches the
        // credit_balance read path); COALESCE handles the no-rows NULL → 0.
        let earned: (f64,) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(amount), 0) AS DOUBLE) FROM credit_transactions \
             WHERE node_id = ? AND type = 'credit'",
        )
        .bind(node_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0.0,));
        let spent: (f64,) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(amount), 0) AS DOUBLE) FROM credit_transactions \
             WHERE node_id = ? AND type = 'debit'",
        )
        .bind(node_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0.0,));
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM credit_transactions WHERE node_id = ?")
                .bind(node_id)
                .fetch_one(&self.pool)
                .await
                .unwrap_or((0,));
        Some(CreditSummary {
            balance,
            total_earned: earned.0,
            total_spent: spent.0,
            tx_count: count.0 as u64,
        })
    }

    async fn operator_wallet(&self, node_id: &str) -> Option<(f64, u32)> {
        // #466 v1 — resolve the node's operator_pubkey; null wallet if unbound. Mirrors PHP
        // CreditsController::operatorWallet (keyed on operator_pubkey presence, not verified).
        let op: Option<(Option<String>,)> =
            sqlx::query_as("SELECT operator_pubkey FROM nodes WHERE id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        let operator_pubkey = op.and_then(|(p,)| p).filter(|p| !p.is_empty())?;

        // Aggregate balance + count over the operator's non-archived nodes. CAST AS DOUBLE so
        // the DECIMAL(15,4) sum decodes into f64 (same fix as credit_balance/credit_summary).
        let agg: (f64, i64) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(credit_balance), 0) AS DOUBLE), COUNT(*) \
             FROM nodes WHERE operator_pubkey = ? AND status != 'archived'",
        )
        .bind(&operator_pubkey)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0.0, 0));
        Some((agg.0, agg.1 as u32))
    }

    async fn operator_wallet_summary(&self, node_id: &str) -> Option<OperatorWalletSummary> {
        let op: Option<(Option<String>,)> =
            sqlx::query_as("SELECT operator_pubkey FROM nodes WHERE id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        let operator_pubkey = op.and_then(|(p,)| p).filter(|p| !p.is_empty())?;

        let agg: (f64, i64) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(credit_balance), 0) AS DOUBLE), COUNT(*) \
             FROM nodes WHERE operator_pubkey = ? AND status != 'archived'",
        )
        .bind(&operator_pubkey)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0.0, 0));

        let earned: (f64,) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(ct.amount), 0) AS DOUBLE) \
             FROM credit_transactions ct JOIN nodes n ON n.id = ct.node_id \
             WHERE n.operator_pubkey = ? AND n.status != 'archived' AND ct.type = 'credit'",
        )
        .bind(&operator_pubkey)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0.0,));
        let spent: (f64,) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(ct.amount), 0) AS DOUBLE) \
             FROM credit_transactions ct JOIN nodes n ON n.id = ct.node_id \
             WHERE n.operator_pubkey = ? AND n.status != 'archived' AND ct.type = 'debit'",
        )
        .bind(&operator_pubkey)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0.0,));
        let tx_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM credit_transactions ct JOIN nodes n ON n.id = ct.node_id \
             WHERE n.operator_pubkey = ? AND n.status != 'archived'",
        )
        .bind(&operator_pubkey)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        Some(OperatorWalletSummary {
            total_balance: agg.0,
            total_earned: earned.0,
            total_spent: spent.0,
            tx_count: tx_count.0 as u64,
            node_count: agg.1 as u32,
            reconciles: (agg.0 - (earned.0 - spent.0)).abs() < 0.0001,
            operator_fingerprint: operator_fingerprint(&operator_pubkey),
        })
    }

    async fn effective_credit_balance(&self, node_id: &str) -> Option<EffectiveCreditBalance> {
        let consumer_balance = self.credit_balance(node_id).await?;
        let op: Option<(Option<String>,)> =
            sqlx::query_as("SELECT operator_pubkey FROM nodes WHERE id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        let Some(operator_pubkey) = op.and_then(|(p,)| p).filter(|p| !p.is_empty()) else {
            return Some(EffectiveCreditBalance {
                consumer_balance,
                effective_balance: consumer_balance,
                balance_scope: "node",
                operator_wallet_balance: None,
            });
        };

        let wallet: (f64,) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(n.credit_balance), 0) AS DOUBLE) \
             FROM nodes n WHERE n.operator_pubkey = ? AND n.status != 'archived' \
             AND n.credit_balance > 0 AND ( \
               EXISTS (SELECT 1 FROM credit_transactions ct WHERE ct.node_id = n.id AND ct.type = 'credit' AND ct.expires_at IS NULL) \
               OR (SELECT MAX(ct.expires_at) FROM credit_transactions ct WHERE ct.node_id = n.id AND ct.type = 'credit' AND ct.expires_at IS NOT NULL) IS NULL \
               OR (SELECT MAX(ct.expires_at) FROM credit_transactions ct WHERE ct.node_id = n.id AND ct.type = 'credit' AND ct.expires_at IS NOT NULL) > NOW() \
             )",
        )
        .bind(&operator_pubkey)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0.0,));

        Some(EffectiveCreditBalance {
            consumer_balance,
            effective_balance: wallet.0,
            balance_scope: "operator_wallet",
            operator_wallet_balance: Some(wallet.0),
        })
    }

    /// Archive dormant nodes older than `days_threshold` days.
    /// Transitions status → 'archived'. PHP: NodeLifecycleCommand.
    async fn archive_dormant(&self, days_threshold: u32) -> u32 {
        let result = sqlx::query(
            "UPDATE nodes SET status = 'archived' \
             WHERE status = 'dormant' \
               AND dormant_since IS NOT NULL \
               AND dormant_since < NOW() - INTERVAL ? DAY",
        )
        .bind(days_threshold)
        .execute(&self.pool)
        .await;
        result.map(|r| r.rows_affected() as u32).unwrap_or(0)
    }

    /// Distinct intents with active node counts, sorted by node_count desc.
    async fn list_intents(&self) -> Vec<IntentSummary> {
        #[derive(sqlx::FromRow)]
        struct Row {
            intent: String,
            node_count: i64,
        }
        let rows: Vec<Row> = sqlx::query_as(
            r#"SELECT c.intent, COUNT(DISTINCT n.id) AS node_count
               FROM capabilities c
               INNER JOIN nodes n ON n.id = c.node_id
               WHERE n.available = 1
                 AND (n.last_seen IS NULL OR n.last_seen >= NOW() - INTERVAL 90 SECOND)
               GROUP BY c.intent
               ORDER BY node_count DESC"#,
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .map(|r| IntentSummary {
                intent: r.intent,
                node_count: r.node_count as u32,
            })
            .collect()
    }

    async fn node_hmac_key(&self, node_id: &str) -> Option<String> {
        let row: Option<(String,)> = sqlx::query_as("SELECT node_hmac_key FROM nodes WHERE id = ?")
            .bind(node_id)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten();
        row.map(|(k,)| k).filter(|k| !k.is_empty())
    }

    /// Nonce replay check — looks up the nonce in credit_transactions.
    async fn is_nonce_used(&self, nonce: &str) -> bool {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT COUNT(*) FROM credit_transactions WHERE nonce = ?")
                .bind(nonce)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        row.map(|(n,)| n > 0).unwrap_or(false)
    }

    /// Record a credit award atomically:
    /// 1. Check nonce not already used (RT-02).
    /// 2. Insert a credit_transactions row.
    /// 3. Increment nodes.credit_balance.
    /// Returns new balance or CreditError.
    async fn record_credit_award(
        &self,
        node_id: &str,
        amount: f64,
        task_id: &str,
        nonce: &str,
    ) -> Result<f64, CreditError> {
        // Atomic nonce check + insert + balance update via BEGIN/COMMIT.
        let mut tx = self.pool.begin().await.map_err(|_| CreditError::DbError)?;

        let existing: Option<(i64,)> =
            sqlx::query_as("SELECT COUNT(*) FROM credit_transactions WHERE nonce = ?")
                .bind(nonce)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| CreditError::DbError)?;
        if existing.map(|(n,)| n > 0).unwrap_or(false) {
            return Err(CreditError::NonceReplay);
        }

        // WQ-056 / billing §11: an earn stamps the credit TTL horizon (NOW() + 90 DAY).
        // The nightly run_expire_credits_loop sweeps nodes whose newest earn is past TTL.
        sqlx::query(
            "INSERT INTO credit_transactions (node_id, amount, type, task_id, nonce, reason, expires_at) \
             VALUES (?, ?, 'credit', ?, ?, 'cip_award', NOW() + INTERVAL 90 DAY)",
        )
        .bind(node_id)
        .bind(amount)
        .bind(task_id)
        .bind(nonce)
        .execute(&mut *tx)
        .await
        .map_err(|_| CreditError::DbError)?;

        sqlx::query("UPDATE nodes SET credit_balance = credit_balance + ? WHERE id = ?")
            .bind(amount)
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| CreditError::DbError)?;

        tx.commit().await.map_err(|_| CreditError::DbError)?;

        // Fetch updated balance. CAST AS DOUBLE — credit_balance is DECIMAL(15,4) and sqlx
        // cannot decode DECIMAL straight into f64, so a bare SELECT errored → None → the award
        // (already committed above) wrongly returned CreditError → 500, and the signed
        // CREDIT_AWARD event was never emitted (#459 bug A). Same fix as credit_balance().
        let row: Option<(f64,)> =
            sqlx::query_as("SELECT CAST(credit_balance AS DOUBLE) FROM nodes WHERE id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        row.map(|(b,)| Ok(b))
            .unwrap_or(Err(CreditError::NodeNotFound))
    }

    async fn debit_for_consumer(
        &self,
        consumer_node_id: &str,
        amount: f64,
        task_id: &str,
        reason: &str,
    ) -> WalletDebitResult {
        let op: Option<(Option<String>,)> =
            sqlx::query_as("SELECT operator_pubkey FROM nodes WHERE id = ?")
                .bind(consumer_node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();

        let Some(operator_pubkey) = op.and_then(|(p,)| p).filter(|p| !p.is_empty()) else {
            let Ok(mut tx) = self.pool.begin().await else {
                return WalletDebitResult {
                    debited: false,
                    spent: 0.0,
                    scope: "node",
                    reason: Some("db_error"),
                    debit_count: 0,
                };
            };
            let updated = sqlx::query(
                "UPDATE nodes SET credit_balance = credit_balance - ? \
                 WHERE id = ? AND credit_balance + 0.0001 >= ?",
            )
            .bind(amount)
            .bind(consumer_node_id)
            .bind(amount)
            .execute(&mut *tx)
            .await
            .map(|r| r.rows_affected() > 0)
            .unwrap_or(false);
            if !updated {
                let _ = tx.rollback().await;
                return WalletDebitResult {
                    debited: false,
                    spent: 0.0,
                    scope: "node",
                    reason: Some("insufficient_balance"),
                    debit_count: 0,
                };
            }
            let inserted = sqlx::query(
                "INSERT INTO credit_transactions (node_id, amount, type, task_id, reason) \
                 VALUES (?, ?, 'debit', ?, ?)",
            )
            .bind(consumer_node_id)
            .bind(amount)
            .bind(task_id)
            .bind(reason)
            .execute(&mut *tx)
            .await
            .is_ok();
            if inserted && tx.commit().await.is_ok() {
                return WalletDebitResult {
                    debited: true,
                    spent: amount,
                    scope: "node",
                    reason: None,
                    debit_count: 1,
                };
            }
            return WalletDebitResult {
                debited: false,
                spent: 0.0,
                scope: "node",
                reason: Some("db_error"),
                debit_count: 0,
            };
        };

        let Ok(mut tx) = self.pool.begin().await else {
            return WalletDebitResult {
                debited: false,
                spent: 0.0,
                scope: "operator_wallet",
                reason: Some("db_error"),
                debit_count: 0,
            };
        };

        let candidates: Vec<(String, f64, Option<i64>)> = sqlx::query_as(
            "SELECT n.id, CAST(n.credit_balance AS DOUBLE), \
                    UNIX_TIMESTAMP((SELECT MIN(ct.expires_at) FROM credit_transactions ct \
                                    WHERE ct.node_id = n.id AND ct.type = 'credit' \
                                      AND ct.expires_at IS NOT NULL AND ct.expires_at > NOW())) AS horizon \
             FROM nodes n WHERE n.operator_pubkey = ? AND n.status != 'archived' \
             AND n.credit_balance > 0 AND ( \
               EXISTS (SELECT 1 FROM credit_transactions ct WHERE ct.node_id = n.id AND ct.type = 'credit' AND ct.expires_at IS NULL) \
               OR (SELECT MAX(ct.expires_at) FROM credit_transactions ct WHERE ct.node_id = n.id AND ct.type = 'credit' AND ct.expires_at IS NOT NULL) IS NULL \
               OR (SELECT MAX(ct.expires_at) FROM credit_transactions ct WHERE ct.node_id = n.id AND ct.type = 'credit' AND ct.expires_at IS NOT NULL) > NOW() \
             ) ORDER BY horizon IS NULL, horizon, n.id FOR UPDATE",
        )
        .bind(&operator_pubkey)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();

        let available: f64 = candidates.iter().map(|(_, balance, _)| *balance).sum();
        if available + 0.0001 < amount {
            let _ = tx.rollback().await;
            return WalletDebitResult {
                debited: false,
                spent: 0.0,
                scope: "operator_wallet",
                reason: Some("insufficient_operator_wallet_balance"),
                debit_count: 0,
            };
        }

        let mut remaining = amount;
        let mut debit_count = 0_u32;
        for (node_id, balance, _) in candidates {
            if remaining <= 0.00005 {
                break;
            }
            let take = remaining.min(balance);
            let tx_reason = if node_id == consumer_node_id {
                reason.to_string()
            } else {
                format!(
                    "{reason}:operator_wallet:consumer={}",
                    &consumer_node_id[..consumer_node_id.len().min(8)]
                )
            };
            let ok_update =
                sqlx::query("UPDATE nodes SET credit_balance = credit_balance - ? WHERE id = ?")
                    .bind(take)
                    .bind(&node_id)
                    .execute(&mut *tx)
                    .await
                    .is_ok();
            let ok_insert = sqlx::query(
                "INSERT INTO credit_transactions (node_id, amount, type, task_id, reason) \
                 VALUES (?, ?, 'debit', ?, ?)",
            )
            .bind(&node_id)
            .bind(take)
            .bind(task_id)
            .bind(tx_reason)
            .execute(&mut *tx)
            .await
            .is_ok();
            if !ok_update || !ok_insert {
                let _ = tx.rollback().await;
                return WalletDebitResult {
                    debited: false,
                    spent: 0.0,
                    scope: "operator_wallet",
                    reason: Some("db_error"),
                    debit_count: 0,
                };
            }
            remaining -= take;
            debit_count += 1;
        }

        if remaining <= 0.0001 && tx.commit().await.is_ok() {
            WalletDebitResult {
                debited: true,
                spent: amount,
                scope: "operator_wallet",
                reason: None,
                debit_count,
            }
        } else {
            WalletDebitResult {
                debited: false,
                spent: 0.0,
                scope: "operator_wallet",
                reason: Some("db_error"),
                debit_count: 0,
            }
        }
    }

    async fn expire_idle_node_credits(&self) -> (u64, f64) {
        // WQ-056 / billing §11.3 — the 90-day TTL sink. Idle = a node whose newest earn's
        // expires_at is past AND credit_balance > 0 (see credit_ttl_idle). Sweep: zero the
        // balance + write one ttl_expire debit per node. Idempotent (a swept node is at 0,
        // so a re-run finds nothing); a fresh earn resets the TTL forward, removing it.
        // Fetch candidates (balance > 0) with their newest-earn TTL + the DB's own clock
        // (both as unix seconds, so there is no Rust↔DB clock skew), then apply the
        // load-bearing pure predicate `credit_ttl_idle` to decide. UNIX_TIMESTAMP(NULL)
        // → NULL → None (a node with no determinable earn TTL is never swept).
        let candidates: Vec<(String, f64, Option<i64>, i64)> = sqlx::query_as(
            "SELECT n.id, CAST(n.credit_balance AS DOUBLE), \
                    UNIX_TIMESTAMP((SELECT MAX(ct.expires_at) FROM credit_transactions ct \
                                    WHERE ct.node_id = n.id AND ct.type = 'credit')), \
                    UNIX_TIMESTAMP() \
             FROM nodes n \
             WHERE n.credit_balance > 0",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let mut expired_nodes: u64 = 0;
        let mut expired_credits: f64 = 0.0;
        for (node_id, balance, max_earn_expires_unix, now_unix) in candidates {
            if !credit_ttl_idle(max_earn_expires_unix, balance, now_unix) {
                continue;
            }
            let Ok(mut tx) = self.pool.begin().await else {
                continue;
            };
            // Re-read + zero under the transaction; insert the ttl_expire debit for the
            // swept amount (mirrors the PHP expire row; preserves balance==earned−debits).
            let ok = sqlx::query(
                "UPDATE nodes SET credit_balance = 0 WHERE id = ? AND credit_balance > 0",
            )
            .bind(&node_id)
            .execute(&mut *tx)
            .await
            .map(|r| r.rows_affected() > 0)
            .unwrap_or(false);
            if !ok {
                let _ = tx.rollback().await;
                continue;
            }
            let inserted = sqlx::query(
                "INSERT INTO credit_transactions (node_id, amount, type, reason) \
                 VALUES (?, ?, 'debit', 'ttl_expire')",
            )
            .bind(&node_id)
            .bind(balance)
            .execute(&mut *tx)
            .await
            .is_ok();
            if inserted && tx.commit().await.is_ok() {
                expired_nodes += 1;
                expired_credits += balance;
            }
        }
        (expired_nodes, expired_credits)
    }

    async fn credit_transactions(
        &self,
        node_id: &str,
        offset: u64,
        limit: usize,
    ) -> Vec<CreditTransaction> {
        #[derive(sqlx::FromRow)]
        struct TxRow {
            id: u64,
            amount: f64,
            #[sqlx(rename = "type")]
            tx_type: String,
            task_id: Option<String>,
            reason: Option<String>,
            created_at: Option<chrono::NaiveDateTime>,
        }
        let cap = limit.min(100) as u32;
        let rows: Vec<TxRow> = sqlx::query_as(
            r#"SELECT id, amount, type, task_id, reason, created_at
               FROM credit_transactions
               WHERE node_id = ?
               ORDER BY created_at DESC
               LIMIT ? OFFSET ?"#,
        )
        .bind(node_id)
        .bind(cap)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .map(|r| CreditTransaction {
                id: r.id,
                amount: r.amount,
                tx_type: r.tx_type,
                task_id: r.task_id,
                reason: r.reason,
                created_at: r.created_at.map(|t| t.to_string()).unwrap_or_default(),
            })
            .collect()
    }

    /// Audit report: RT-05 griefing cap + RT-05b reporter eligibility (#379, #383).
    /// - RT-05b bypass 1: reporter must be ≥3 days old and have reputation ≥0.55.
    /// - RT-05b bypass 2: nodes.reputation_score is already updated here (PHP parity).
    async fn apply_audit_report(
        &self,
        target_node_id: &str,
        reporter_node_id: &str,
        _finding: &str,
    ) -> AuditResult {
        const MAX_REPORTERS: i64 = 2;
        const DELTA: f64 = -0.05;
        const AUDIT_MIN_AGE_DAYS: i64 = 3;
        const AUDIT_MIN_REPUTATION: f64 = 0.55;

        // RT-05b (#383): check reporter eligibility (age + reputation)
        let reporter_row: Option<(f32, Option<chrono::NaiveDateTime>)> =
            sqlx::query_as("SELECT reputation_score, created_at FROM nodes WHERE id = ?")
                .bind(reporter_node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();

        let reporter_eligible = reporter_row
            .map(|(rep, created_at)| {
                let age_ok = created_at
                    .map(|c| {
                        let now = chrono::Utc::now().naive_utc();
                        (now - c).num_days() >= AUDIT_MIN_AGE_DAYS
                    })
                    .unwrap_or(false);
                (rep as f64) >= AUDIT_MIN_REPUTATION && age_ok
            })
            .unwrap_or(false);

        if !reporter_eligible {
            let score_row: Option<(f32,)> =
                sqlx::query_as("SELECT reputation_score FROM nodes WHERE id = ?")
                    .bind(target_node_id)
                    .fetch_optional(&self.pool)
                    .await
                    .ok()
                    .flatten();
            return AuditResult {
                applied: false,
                new_score: score_row.map(|(s,)| s as f64).unwrap_or(0.0),
                reason: "reporter_ineligible",
            };
        }

        // Count distinct reporters for this target in the last 24h.
        let count_row: Option<(i64,)> = sqlx::query_as(
            r#"SELECT COUNT(DISTINCT JSON_UNQUOTE(JSON_EXTRACT(payload, '$.reporter_node_id')))
               FROM node_events
               WHERE node_id = ? AND event_type = 'AUDIT_REPORT' AND ts_ms >= UNIX_TIMESTAMP(NOW() - INTERVAL 24 HOUR) * 1000"#,
        )
        .bind(target_node_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        let reporter_count = count_row.map(|(n,)| n).unwrap_or(0);
        if reporter_count >= MAX_REPORTERS {
            let score_row: Option<(f32,)> =
                sqlx::query_as("SELECT reputation_score FROM nodes WHERE id = ?")
                    .bind(target_node_id)
                    .fetch_optional(&self.pool)
                    .await
                    .ok()
                    .flatten();
            return AuditResult {
                applied: false,
                new_score: score_row.map(|(s,)| s as f64).unwrap_or(0.0),
                reason: "reporter_cap_reached",
            };
        }

        // Fetch current score.
        let score_row: Option<(f32,)> =
            sqlx::query_as("SELECT reputation_score FROM nodes WHERE id = ?")
                .bind(target_node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        let Some((old_score,)) = score_row else {
            return AuditResult {
                applied: false,
                new_score: 0.0,
                reason: "target_not_found",
            };
        };

        let new_score = crate::reputation::apply_delta(old_score as f64, DELTA);
        let _ = sqlx::query("UPDATE nodes SET reputation_score = ? WHERE id = ?")
            .bind(new_score as f32)
            .bind(target_node_id)
            .execute(&self.pool)
            .await;

        // Log the event to node_events for the reporter-count query above.
        let payload = serde_json::json!({ "reporter_node_id": reporter_node_id }).to_string();
        let _ = sqlx::query(
            "INSERT INTO node_events (event_id, seq, event_type, node_id, ts_ms, payload) \
             VALUES (UUID(), 0, 'AUDIT_REPORT', ?, UNIX_TIMESTAMP(NOW()) * 1000, ?)",
        )
        .bind(target_node_id)
        .bind(&payload)
        .execute(&self.pool)
        .await;

        AuditResult {
            applied: true,
            new_score,
            reason: "applied",
        }
    }

    async fn verify_probe_token(&self, token_sha256_hex: &str) -> bool {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COUNT(*) FROM probe_tokens WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > NOW())"
        )
        .bind(token_sha256_hex)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        if row.map(|(n,)| n > 0).unwrap_or(false) {
            let _ =
                sqlx::query("UPDATE probe_tokens SET last_seen_at = NOW() WHERE token_hash = ?")
                    .bind(token_sha256_hex)
                    .execute(&self.pool)
                    .await;
            true
        } else {
            false
        }
    }

    async fn record_probe_batch(&self, _token_sha256_hex: &str, probes: &[ProbeResult]) -> u32 {
        let mut count = 0u32;
        for p in probes {
            let probed_at = p.probed_at.as_deref().unwrap_or("");
            let level = if p.level.is_empty() { "info" } else { &p.level };
            let result = sqlx::query(
                "INSERT INTO iicp_telemetry_probes \
                 (run_id, probe_id, probe_type, test_id, level, passed, latency_ms, detail, node_id) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&p.run_id)
            .bind(&p.probe_id)
            .bind(&p.probe_type)
            .bind(p.test_id.as_deref())
            .bind(level)
            .bind(p.passed)
            .bind(p.latency_ms)
            .bind(p.detail.as_deref())
            .bind(p.node_id.as_deref()) // #373 — per-node attribution (null for infra probes)
            .execute(&self.pool)
            .await;
            if result.is_ok() {
                count += 1;
            }
            let _ = probed_at; // timestamp handling deferred to Phase 2
        }
        count
    }

    async fn quote_multipliers(&self, intent: &str, min_reputation: f64) -> Vec<f64> {
        let rows: Vec<(f64,)> = sqlx::query_as(
            r#"SELECT CAST(n.credit_cost_multiplier AS DOUBLE)
               FROM nodes n
               INNER JOIN capabilities c ON c.node_id = n.id
               WHERE c.intent = ? AND n.available = 1 AND n.reputation_score >= ?
                 AND (n.last_seen IS NULL OR n.last_seen >= NOW() - INTERVAL 90 SECOND)"#,
        )
        .bind(intent)
        .bind(min_reputation)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter().map(|(m,)| m).collect()
    }

    /// ProxyTokenAuth: verify bearer token against nodes.proxy_token_hash via bcrypt.
    /// PHP parity: returns false when the node is unknown or has no proxy_token_hash set.
    async fn verify_proxy_token(&self, proxy_node_id: &str, token: &str) -> bool {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT proxy_token_hash FROM nodes WHERE id = ?")
                .bind(proxy_node_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        match row {
            Some((hash,)) if !hash.is_empty() => {
                let token_owned = token.to_string();
                tokio::task::spawn_blocking(move || {
                    bcrypt::verify(&token_owned, &hash).unwrap_or(false)
                })
                .await
                .unwrap_or(false)
            }
            _ => false, // unknown node or no proxy_token_hash — reject (PHP parity)
        }
    }

    /// Record a proxy telemetry observation. Deduplicates by (node_id, proxy_node_id, time_bucket).
    /// Returns the distinct proxy count for the node in the last 7 days (Sybil quorum).
    async fn record_proxy_telemetry(&self, obs: &ProxyObservation) -> (bool, u32) {
        let time_bucket = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 60) * 60)
            .unwrap_or(0);

        let status = if obs.status.is_empty() {
            "ok"
        } else {
            &obs.status
        };
        // PHP returns early on duplicate (accepted=false); match by checking rows_affected.
        // ON DUPLICATE KEY UPDATE in MySQL returns 2 on update, 1 on insert, 0 on no-change.
        let insert_result = sqlx::query(
            r#"INSERT INTO proxy_telemetry
               (node_id, proxy_node_id, time_bucket, latency_ms_observed,
                tokens_observed, status, qos_advertised, qos_met)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE
                 latency_ms_observed = VALUES(latency_ms_observed),
                 tokens_observed     = VALUES(tokens_observed),
                 status              = VALUES(status)"#,
        )
        .bind(&obs.node_id)
        .bind(&obs.proxy_node_id)
        .bind(time_bucket)
        .bind(obs.latency_ms_observed)
        .bind(obs.tokens_observed)
        .bind(status)
        .bind(obs.qos_advertised)
        .bind(obs.qos_met)
        .execute(&self.pool)
        .await;
        let is_new = insert_result
            .map(|r| r.rows_affected() == 1)
            .unwrap_or(false);

        // Sybil quorum gate (spec §T4.3, RT-03b #382): count distinct proxies in last 7 days
        // that are ≥3 days old AND have reputation ≥0.55 (independence requirements).
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT COUNT(DISTINCT pt.proxy_node_id) \
             FROM proxy_telemetry pt \
             INNER JOIN nodes n ON pt.proxy_node_id = n.id \
             WHERE pt.node_id = ? \
               AND pt.created_at >= NOW() - INTERVAL 7 DAY \
               AND n.created_at <= NOW() - INTERVAL 3 DAY \
               AND n.reputation_score >= 0.55",
        )
        .bind(&obs.node_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        let quorum = row.map(|(n,)| n as u32).unwrap_or(0);

        // EMA update: only when new row inserted (not a duplicate) AND quorum ≥3.
        // PHP skips EMA on duplicate (returns early). Rust mirrors that via is_new guard.
        if is_new && quorum >= 3 {
            if let Some(latency) = obs.latency_ms_observed {
                update_latency_ema(&self.pool, &obs.node_id, &obs.proxy_node_id, latency).await;
            }
        }

        (is_new, quorum)
    }

    async fn list_badges(&self, tier: Option<&str>) -> Vec<ConformanceBadge> {
        #[derive(sqlx::FromRow)]
        struct Row {
            badge_id: String,
            tier: String,
            status: String,
            subject_did: Option<String>,
            suite_version: String,
            passed_at: Option<chrono::NaiveDateTime>,
            expires_at: Option<chrono::NaiveDateTime>,
            test_results_url: Option<String>,
        }
        let rows: Vec<Row> = if let Some(t) = tier {
            sqlx::query_as(
                "SELECT badge_id, tier, status, subject_did, suite_version, passed_at, expires_at, test_results_url FROM conformance_badges WHERE tier = ? ORDER BY created_at DESC"
            )
            .bind(t)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default()
        } else {
            sqlx::query_as(
                "SELECT badge_id, tier, status, subject_did, suite_version, passed_at, expires_at, test_results_url FROM conformance_badges ORDER BY created_at DESC"
            )
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default()
        };
        rows.into_iter()
            .map(|r| ConformanceBadge {
                badge_id: r.badge_id,
                tier: r.tier,
                status: r.status,
                subject_did: r.subject_did,
                suite_version: r.suite_version,
                passed_at: r.passed_at.map(|t| t.to_string()),
                expires_at: r.expires_at.map(|t| t.to_string()),
                test_results_url: r.test_results_url,
            })
            .collect()
    }

    async fn submit_conformance(&self, tier: &str, subject_did: Option<&str>) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let _ = sqlx::query(
            "INSERT INTO conformance_badges (badge_id, tier, subject_did, suite_version, status) VALUES (?, ?, ?, '', 'pending')"
        )
        .bind(&id)
        .bind(tier)
        .bind(subject_did)
        .execute(&self.pool)
        .await;
        id
    }

    async fn get_badge(&self, tier: &str) -> Option<ConformanceBadge> {
        self.list_badges(Some(tier)).await.into_iter().next()
    }

    async fn upsert_health_observation(
        &self,
        node_id: &str,
        evaluator_did: &str,
        score: f64,
        evaluated_at_ms: i64,
    ) -> bool {
        // Monotonic staleness rule (ADR-048): an older evaluated_at_ms never overwrites a
        // newer stored snapshot. The IF/GREATEST guards make a stale replay a no-op (0 rows
        // affected → false); a fresh insert is 1, a newer update is 2 → both true.
        let result = sqlx::query(
            "INSERT INTO node_health_observations \
                (node_id, evaluator_did, score, evaluated_at_ms, created_at, updated_at) \
             VALUES (?, ?, ?, ?, NOW(), NOW()) \
             ON DUPLICATE KEY UPDATE \
                score = IF(VALUES(evaluated_at_ms) > evaluated_at_ms, VALUES(score), score), \
                evaluated_at_ms = GREATEST(evaluated_at_ms, VALUES(evaluated_at_ms)), \
                updated_at = IF(VALUES(evaluated_at_ms) > evaluated_at_ms, NOW(), updated_at)",
        )
        .bind(node_id)
        .bind(evaluator_did)
        .bind(score)
        .bind(evaluated_at_ms)
        .execute(&self.pool)
        .await;
        result.map(|r| r.rows_affected() > 0).unwrap_or(false)
    }

    async fn all_health_observations(&self) -> Vec<(String, String, f64, i64)> {
        sqlx::query_as(
            "SELECT node_id, evaluator_did, score, CAST(evaluated_at_ms AS SIGNED) \
             FROM node_health_observations",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
    }

    async fn set_reputation_score(&self, node_id: &str, score: f64) -> bool {
        // #441: absolute set from a REPUTATION_DECAY event (clamped to [0,1], like the seed).
        sqlx::query("UPDATE nodes SET reputation_score = ? WHERE id = ?")
            .bind(score.clamp(0.0, 1.0))
            .bind(node_id)
            .execute(&self.pool)
            .await
            .map(|r| r.rows_affected() > 0)
            .unwrap_or(false)
    }

    async fn set_credit_balance(&self, node_id: &str, balance: f64) -> bool {
        // #441: absolute set from a CREDIT_AWARD event (the seed already computed new_balance).
        sqlx::query("UPDATE nodes SET credit_balance = ? WHERE id = ?")
            .bind(balance)
            .bind(node_id)
            .execute(&self.pool)
            .await
            .map(|r| r.rows_affected() > 0)
            .unwrap_or(false)
    }

    async fn upsert_replica(
        &self,
        replica_id: &str,
        did: &str,
        endpoint: &str,
        trust_tier: &str,
    ) -> bool {
        // #441: upsert by DID (mirrors PHP Replica::updateOrCreate(['did'=>...])). The replica
        // didn't issue the token, so replica_token_hash stays ''. 90-day expiry like PHP.
        sqlx::query(
            "INSERT INTO replicas \
                (replica_id, did, endpoint, trust_tier, replica_token_hash, expires_at, last_seen_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, '', NOW() + INTERVAL 90 DAY, NOW(), NOW(), NOW()) \
             ON DUPLICATE KEY UPDATE \
                replica_id = VALUES(replica_id), endpoint = VALUES(endpoint), \
                trust_tier = VALUES(trust_tier), last_seen_at = NOW(), updated_at = NOW()",
        )
        .bind(replica_id)
        .bind(did)
        .bind(endpoint)
        .bind(trust_tier)
        .execute(&self.pool)
        .await
        .map(|r| r.rows_affected() > 0)
        .unwrap_or(false)
    }

    async fn all_replicas(&self) -> Vec<(String, String, String, String, i64)> {
        // UNIX_TIMESTAMP returns NULL when created_at is NULL; fall back to 0.
        sqlx::query_as(
            "SELECT replica_id, did, endpoint, trust_tier, \
             CAST(COALESCE(UNIX_TIMESTAMP(created_at) * 1000, 0) AS SIGNED) \
             FROM replicas",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
    }

    async fn append_signed_event(
        &self,
        secret_key_hex: &str,
        event_type: &str,
        node_id: &str,
        payload: &serde_json::Value,
    ) -> Option<i64> {
        // Next monotonic seq (parity with PHP NodeEventLogger: max(seq)+1).
        // CAST AS SIGNED: seq is BIGINT UNSIGNED; sqlx's strict decode fails decoding an
        // unsigned column into i64, and the `.ok()?` silently swallowed it → early-return
        // None → NO event ever persisted (the signed event log stayed empty). (#459 bug C)
        // Next monotonic seq + the predecessor's signature, for the hash-chain (#458). The
        // tip row (MAX(seq)) is the immediate predecessor; its signature seeds this event's
        // prev_hash. NULL/empty (no prior signed event) → chain starts at GENESIS_ROOT.
        let (max_seq, prev_sig): (i64, Option<String>) = sqlx::query_as(
            "SELECT CAST(COALESCE(MAX(seq), 0) AS SIGNED), \
             (SELECT signature FROM node_events ORDER BY seq DESC LIMIT 1) FROM node_events",
        )
        .fetch_one(&self.pool)
        .await
        .ok()?;
        let seq = max_seq + 1;
        let prev_hash = crate::federation::prev_hash_from(prev_sig.as_deref());
        let event_id = uuid::Uuid::new_v4().to_string();
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let sig = crate::federation::sign_event(
            secret_key_hex,
            &event_id,
            event_type,
            seq,
            ts_ms,
            payload,
            &prev_hash,
        );
        sqlx::query(
            "INSERT INTO node_events (event_id, seq, event_type, node_id, ts_ms, payload, prev_hash, signature) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&event_id)
        .bind(seq)
        .bind(event_type)
        .bind(node_id)
        .bind(ts_ms)
        .bind(payload.to_string())
        .bind(&prev_hash)
        .bind(&sig)
        .execute(&self.pool)
        .await
        .ok()?;
        Some(seq)
    }

    async fn upsert_operator(
        &self,
        operator_pubkey: &str,
        display_name: Option<&str>,
        attested_created_at: Option<&str>,
        integrity_hash: Option<&str>,
    ) {
        // First insert pins integrity_hash + the directory-observed first_seen_ms (authoritative
        // for founder ordinals); a later (delegated, key-proven) register updates only the
        // mutable display_name. Fail-safe — errors are swallowed (never abort registration).
        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
                .bind(operator_pubkey)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        if exists.is_some() {
            if let Some(dn) = display_name {
                let _ = sqlx::query(
                    "UPDATE operators SET display_name = ?, updated_at = NOW() WHERE operator_pubkey = ?",
                )
                .bind(dn)
                .bind(operator_pubkey)
                .execute(&self.pool)
                .await;
            }
            return;
        }
        let first_seen_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let _ = sqlx::query(
            "INSERT INTO operators (operator_pubkey, display_name, attested_created_at, \
             operator_integrity_hash, first_seen_ms, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, NOW(), NOW())",
        )
        .bind(operator_pubkey)
        .bind(display_name)
        .bind(attested_created_at)
        .bind(integrity_hash)
        .bind(first_seen_ms)
        .execute(&self.pool)
        .await;
    }

    async fn operator_display_name(&self, operator_pubkey: &str) -> Option<String> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT display_name FROM operators WHERE operator_pubkey = ? LIMIT 1")
                .bind(operator_pubkey)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        row.and_then(|r| r.0)
    }

    async fn operator_display_name_claimed_by_other(
        &self,
        operator_pubkey: &str,
        normalized_display_name: &str,
    ) -> bool {
        // MySQL LOWER(TRIM(REGEXP_REPLACE())) parity with PHP's whitespace-folded comparison.
        // Lifecycle history is deliberately retained, but only an active identity may
        // reserve a public operator handle. A rotated predecessor must not block its
        // successor's first re-registration after key migration.
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM operators \
             WHERE operator_pubkey <> ? AND identity_status = 'active' AND display_name IS NOT NULL \
             AND LOWER(TRIM(REGEXP_REPLACE(display_name, '[[:space:]]+', ' '))) = ? \
             LIMIT 1",
        )
        .bind(operator_pubkey)
        .bind(normalized_display_name)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        row.is_some()
    }

    async fn rename_operator(&self, operator_pubkey: &str, display_name: &str) -> bool {
        // Existence check first (never create here) — and so a rename to the SAME name
        // still returns true (MySQL UPDATE reports 0 rows_affected when unchanged).
        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? AND identity_status = 'active' LIMIT 1")
                .bind(operator_pubkey)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        if exists.is_none() {
            return false;
        }
        let _ = sqlx::query(
            "UPDATE operators SET display_name = ?, updated_at = NOW() WHERE operator_pubkey = ?",
        )
        .bind(display_name)
        .bind(operator_pubkey)
        .execute(&self.pool)
        .await;
        true
    }

    async fn operator_identity_active(&self, operator_pubkey: &str) -> Option<bool> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT identity_status FROM operators WHERE operator_pubkey = ? LIMIT 1",
        )
        .bind(operator_pubkey)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        row.map(|(status,)| status == "active")
    }

    async fn rotate_operator_identity(
        &self,
        old_operator_pubkey: &str,
        new_operator_pubkey: &str,
        requested_epoch: Option<u32>,
        reason_class: &str,
    ) -> Result<OperatorLifecycleResult, OperatorLifecycleError> {
        if old_operator_pubkey == new_operator_pubkey {
            return Err(OperatorLifecycleError::Invalid);
        }
        let mut tx = self.pool.begin().await.map_err(|_| OperatorLifecycleError::Storage)?;
        let old: Option<(Option<String>, Option<String>, Option<String>, Option<i64>, Option<i64>, Option<String>, Option<String>, Option<String>, Option<u32>)> = sqlx::query_as(
            "SELECT display_name, attested_created_at, operator_integrity_hash, first_seen_ms, ordinal, tier, badge, provenance, rotation_epoch \
             FROM operators WHERE operator_pubkey = ? AND identity_status = 'active' FOR UPDATE",
        )
        .bind(old_operator_pubkey)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| OperatorLifecycleError::Storage)?;
        let Some((display_name, attested_created_at, integrity_hash, first_seen_ms, ordinal, tier, badge, provenance, prior_epoch)) = old else {
            let exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
                .bind(old_operator_pubkey).fetch_optional(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
            return Err(if exists.is_some() { OperatorLifecycleError::Inactive } else { OperatorLifecycleError::Unknown });
        };
        let successor_exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
            .bind(new_operator_pubkey).fetch_optional(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        if successor_exists.is_some() {
            return Err(OperatorLifecycleError::SuccessorExists);
        }
        let epoch = prior_epoch.unwrap_or(0).saturating_add(1).max(requested_epoch.unwrap_or(0));
        sqlx::query(
            "INSERT INTO operators (operator_pubkey, identity_status, display_name, attested_created_at, operator_integrity_hash, first_seen_ms, ordinal, tier, badge, provenance, created_at, updated_at) \
             VALUES (?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
        )
        .bind(new_operator_pubkey).bind(display_name).bind(attested_created_at).bind(integrity_hash)
        .bind(first_seen_ms).bind(ordinal).bind(tier).bind(badge).bind(provenance)
        .execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        let linked = sqlx::query("UPDATE nodes SET operator_pubkey = ?, operator_verified = 1, updated_at = NOW() WHERE operator_pubkey = ?")
            .bind(new_operator_pubkey).bind(old_operator_pubkey).execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?.rows_affected() as u32;
        use ct_codecs::{Base64, Decoder};
        let successor_raw = Base64::decode_to_vec(new_operator_pubkey, None)
            .map_err(|_| OperatorLifecycleError::Invalid)?;
        if successor_raw.len() != 32 {
            return Err(OperatorLifecycleError::Invalid);
        }
        let successor_hash = hex::encode(sha2::Sha256::digest(successor_raw));
        sqlx::query(
            "UPDATE operators SET identity_status = 'rotated', successor_operator_pubkey_sha256 = ?, rotation_epoch = ?, identity_reason_class = ?, updated_at = NOW() WHERE operator_pubkey = ?",
        )
        .bind(successor_hash).bind(epoch).bind(reason_class).bind(old_operator_pubkey)
        .execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        tx.commit().await.map_err(|_| OperatorLifecycleError::Storage)?;
        Ok(OperatorLifecycleResult { linked_nodes: linked, rotation_epoch: Some(epoch), revoked_at_unix: None })
    }

    async fn revoke_operator_identity(
        &self,
        operator_pubkey: &str,
        reason_class: &str,
    ) -> Result<OperatorLifecycleResult, OperatorLifecycleError> {
        let mut tx = self.pool.begin().await.map_err(|_| OperatorLifecycleError::Storage)?;
        let active: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? AND identity_status = 'active' FOR UPDATE")
            .bind(operator_pubkey).fetch_optional(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        if active.is_none() {
            let exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
                .bind(operator_pubkey).fetch_optional(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
            return Err(if exists.is_some() { OperatorLifecycleError::Inactive } else { OperatorLifecycleError::Unknown });
        }
        let linked = sqlx::query("UPDATE nodes SET operator_verified = 0, operator_trust_tier = NULL, updated_at = NOW() WHERE operator_pubkey = ?")
            .bind(operator_pubkey).execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?.rows_affected() as u32;
        sqlx::query("UPDATE operators SET identity_status = 'revoked', identity_revoked_at = NOW(), identity_reason_class = ?, updated_at = NOW() WHERE operator_pubkey = ?")
            .bind(reason_class).bind(operator_pubkey).execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        tx.commit().await.map_err(|_| OperatorLifecycleError::Storage)?;
        Ok(OperatorLifecycleResult { linked_nodes: linked, rotation_epoch: None, revoked_at_unix: Some(chrono::Utc::now().timestamp()) })
    }

    async fn set_operator_recognition(
        &self,
        operator_pubkey: &str,
        ordinal: i64,
        tier: Option<&str>,
        badge: Option<&str>,
    ) {
        let _ = sqlx::query(
            "UPDATE operators SET ordinal = ?, tier = ?, badge = ?, updated_at = NOW() \
             WHERE operator_pubkey = ?",
        )
        .bind(ordinal)
        .bind(tier)
        .bind(badge)
        .bind(operator_pubkey)
        .execute(&self.pool)
        .await;
    }

    async fn list_founders(&self, limit: u32) -> Vec<FounderEntry> {
        let rows: Vec<(Option<String>, i64, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT display_name, CAST(ordinal AS SIGNED), tier, badge FROM operators \
             WHERE ordinal IS NOT NULL ORDER BY ordinal ASC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(|(display_name, ordinal, tier, badge)| FounderEntry {
                display_name,
                ordinal,
                tier,
                badge,
            })
            .collect()
    }

    /// Provisional founders (board `pending` section): operators with no ordinal whose
    /// genuine served node passes the same trailing-24h gate the PHP lock-in detector uses
    /// (operator_verified + public_reachable + active/available OR seen within 24h).
    async fn list_pending_founders(&self, limit: u32) -> Vec<PendingFounderEntry> {
        let rows: Vec<(Option<String>, i64)> = sqlx::query_as(
            "SELECT o.display_name, CAST(o.first_seen_ms AS SIGNED) FROM operators o \
             WHERE o.ordinal IS NULL AND o.first_seen_ms IS NOT NULL \
               AND EXISTS (SELECT 1 FROM nodes n \
                           WHERE n.operator_pubkey = o.operator_pubkey \
                             AND n.public_reachable = 1 AND n.operator_verified = 1 \
                             AND ((n.status = 'active' AND n.available = 1) \
                                  OR n.last_seen >= NOW() - INTERVAL 1 DAY)) \
             ORDER BY o.first_seen_ms ASC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(|(display_name, first_seen_ms)| PendingFounderEntry {
                display_name,
                first_seen_ms,
            })
            .collect()
    }

    async fn events_since(&self, since_seq: i64, limit: u32) -> Vec<EventRow> {
        // CAST payload to CHAR — sqlx is built without the `json` feature here, so the JSON
        // column is read as text and parsed with serde_json.
        let rows: Vec<(
            i64,
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT CAST(seq AS SIGNED), event_id, event_type, node_id, \
                        CAST(ts_ms AS SIGNED), CAST(payload AS CHAR), prev_hash, signature \
                 FROM node_events WHERE seq > ? ORDER BY seq ASC LIMIT ?",
        )
        .bind(since_seq)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .map(
                |(seq, event_id, event_type, node_id, ts_ms, payload, prev_hash, sig)| EventRow {
                    seq,
                    event_id,
                    event_type,
                    node_id,
                    ts_ms,
                    payload: payload
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or(serde_json::Value::Null),
                    prev_hash,
                    sig,
                },
            )
            .collect()
    }

    async fn snapshot_records(&self) -> Vec<NodeRecord> {
        // All nodes (the active_nodes row-map without the liveness WHERE) + their intents.
        let rows: Vec<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, reputation_score, available, `load`, active_jobs,
                      max_concurrent, tasks_total, avg_latency_ms, exposure_mode, transport_endpoint,
                      credit_cost_multiplier, pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable
               FROM nodes"#,
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        let caps: Vec<(String, String)> =
            sqlx::query_as("SELECT node_id, intent FROM capabilities")
                .fetch_all(&self.pool)
                .await
                .unwrap_or_default();
        let mut intents: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for (nid, intent) in caps {
            intents.entry(nid).or_default().push(intent);
        }
        rows.into_iter()
            .map(|r| {
                let node = Node::from(r);
                let node_intents = intents.get(&node.node_id).cloned().unwrap_or_default();
                NodeRecord {
                    node,
                    intents: node_intents,
                    node_token: None,
                    node_hmac_key: None,
                    proxy_token: None,
                }
            })
            .collect()
    }

    async fn rotate_reputation_windows(&self) -> u32 {
        // Reset rolling window for nodes where recent_window_start < NOW() - 90 days.
        // Snapshot current rolling fields to reputation_score history is implicit — the
        // full snapshot-to-reputation_archive path is a Phase 5 hardening item.
        let result = sqlx::query(
            "UPDATE nodes \
             SET tasks_total_recent = 0, \
                 tasks_failed_recent = 0, \
                 avg_latency_ms_recent = 0.0, \
                 recent_window_start = NOW() \
             WHERE recent_window_start IS NOT NULL \
               AND recent_window_start < NOW() - INTERVAL 90 DAY",
        )
        .execute(&self.pool)
        .await;
        result.map(|r| r.rows_affected() as u32).unwrap_or(0)
    }

    async fn prune_heartbeat_events(&self, retain_days: u32) -> u32 {
        let result = sqlx::query(
            "DELETE FROM node_events WHERE event_type = 'HEARTBEAT' \
             AND ts_ms < (UNIX_TIMESTAMP(NOW() - INTERVAL ? DAY) * 1000)",
        )
        .bind(retain_days)
        .execute(&self.pool)
        .await;
        result.map(|r| r.rows_affected() as u32).unwrap_or(0)
    }

    async fn observe_address(&self, node_id: &str, ip: &str, request_type: &str) {
        let _ = sqlx::query(
            "INSERT INTO node_address_history (node_id, ip_address, request_type) VALUES (?, ?, ?)",
        )
        .bind(node_id)
        .bind(ip)
        .bind(request_type)
        .execute(&self.pool)
        .await;
    }

    async fn get_observed_ip(&self, node_id: &str) -> Option<String> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT ip_address FROM node_address_history WHERE node_id = ? \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        row.map(|(ip,)| ip)
    }

    async fn update_pricing(&self, node_id: &str, multiplier: f64, model: Option<&str>) {
        let clamped = multiplier.clamp(0.0, 1000.0);
        let _ = sqlx::query(
            "UPDATE nodes SET credit_cost_multiplier = ?, pricing_model = COALESCE(?, pricing_model) \
             WHERE id = ?",
        )
        .bind(clamped as f32)
        .bind(model)
        .bind(node_id)
        .execute(&self.pool)
        .await;
    }

    async fn log_event(&self, node_id: &str, event_type: &str, payload: &str) {
        let _ = sqlx::query(
            "INSERT INTO node_events (event_id, seq, event_type, node_id, ts_ms, payload) \
             VALUES (UUID(), 0, ?, ?, UNIX_TIMESTAMP(NOW()) * 1000, ?)",
        )
        .bind(event_type)
        .bind(node_id)
        .bind(payload)
        .execute(&self.pool)
        .await;
    }

    async fn last_probe_at(&self) -> Option<String> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT DATE_FORMAT(probed_at, '%Y-%m-%dT%H:%i:%sZ') \
             FROM iicp_telemetry_probes ORDER BY probed_at DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        row.map(|(t,)| t)
    }

    /// Active per-node reachability probing — #373 Phase B parity with PHP `iicp:probe-nodes`.
    /// Returns (node_id, endpoint) pairs for available nodes, ordered by last_seen DESC.
    async fn get_probeable_nodes(&self, limit: u32) -> Vec<(String, String)> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, endpoint FROM nodes \
             WHERE available = 1 AND last_seen IS NOT NULL \
             ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        rows
    }

    /// Record a directory-internal reachability probe result in iicp_telemetry_probes.
    /// probe_token_id is NULL (directory-internal; nullable since 2026_06_01_300000 migration).
    async fn record_probe_result(&self, node_id: &str, passed: bool, test_id: &str) {
        let _ = sqlx::query(
            "INSERT INTO iicp_telemetry_probes \
             (probe_token_id, node_id, run_id, probe_id, probe_type, test_id, level, passed, probed_at) \
             VALUES (NULL, ?, ?, 'dir-node-reachability', 'reachability', ?, 'MUST', ?, NOW())",
        )
        .bind(node_id)
        .bind(format!("dir-probe-{}", &uuid::Uuid::new_v4().to_string()[..8]))
        .bind(test_id)
        .bind(passed)
        .execute(&self.pool)
        .await;
    }

    async fn probe_active_count_and_regions(&self) -> (i64, Vec<String>) {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM probe_tokens \
             WHERE last_seen_at IS NOT NULL \
               AND last_seen_at >= NOW() - INTERVAL 2 HOUR",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        let regions: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT region FROM probe_tokens \
             WHERE region IS NOT NULL \
               AND last_seen_at IS NOT NULL \
               AND last_seen_at >= NOW() - INTERVAL 2 HOUR \
             ORDER BY region",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        (count.0, regions.into_iter().map(|(r,)| r).collect())
    }

    async fn probe_aggregate_24h(&self) -> crate::repo::ProbeAggregate24h {
        // Read most-recent value per metric for window='24h' from iicp_telemetry_aggregates.
        let rows: Vec<(String, Option<f64>)> = sqlx::query_as(
            "SELECT t1.metric, t1.value \
             FROM iicp_telemetry_aggregates t1 \
             INNER JOIN ( \
                 SELECT metric, MAX(computed_at) AS max_at \
                 FROM iicp_telemetry_aggregates \
                 WHERE window = '24h' \
                 GROUP BY metric \
             ) t2 ON t1.metric = t2.metric AND t1.computed_at = t2.max_at \
             WHERE t1.window = '24h'",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let mut agg = crate::repo::ProbeAggregate24h::default();
        for (metric, value) in rows {
            match metric.as_str() {
                "discover_p50_ms" => agg.discover_p50_ms = value,
                "discover_p95_ms" => agg.discover_p95_ms = value,
                "heartbeat_p50_ms" => agg.heartbeat_p50_ms = value,
                "reachability_pct" => agg.reachability_pct = value,
                "conformance_passed" => agg.conformance_passed = value.unwrap_or(0.0) as i64,
                "conformance_failed" => agg.conformance_failed = value.unwrap_or(0.0) as i64,
                _ => {}
            }
        }

        // task_success_rate_pct: PHP D2-READ — sum tasks_total/tasks_failed across all nodes.
        let totals: Option<(Option<i64>, Option<i64>)> =
            sqlx::query_as("SELECT SUM(tasks_total), SUM(tasks_failed) FROM nodes")
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        if let Some((total, failed)) = totals {
            let total = total.unwrap_or(0);
            let failed = failed.unwrap_or(0);
            if total > 0 {
                agg.task_success_rate_pct =
                    Some((((total - failed) as f64 / total as f64) * 1000.0).round() / 10.0);
            }
        }

        agg
    }

    async fn probe_top_failures(&self) -> Vec<crate::repo::TopFailure> {
        let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
            "SELECT test_id, \
                    SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) AS passed, \
                    SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) AS failed, \
                    COUNT(*) AS total \
             FROM iicp_telemetry_probes \
             WHERE probed_at >= NOW() - INTERVAL 24 HOUR \
               AND test_id IS NOT NULL \
             GROUP BY test_id \
             HAVING SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END) > 0 \
             ORDER BY failed DESC \
             LIMIT 5",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .map(|(test_id, passed, failed, total)| {
                let fail_rate = if total > 0 {
                    (failed as f64 / total as f64 * 10000.0).round() / 10000.0
                } else {
                    0.0
                };
                crate::repo::TopFailure {
                    test_id,
                    passed,
                    failed,
                    total,
                    fail_rate,
                }
            })
            .collect()
    }

    /// Free credit allocation gate: two-tier guard (RT-02b, #380).
    /// 1. Per-node_id gate on nodes.free_credit_last_allocation_at (6h window).
    /// 2. Per-source-IP gate on credit_ip_gates.last_allocation_at (6h window).
    /// Both checks and writes are atomic within a single transaction.
    async fn maybe_allocate_free_credits(&self, node_id: &str, ip: &str) -> f64 {
        const FREE_AMOUNT: f64 = 100.0;

        // Check IP gate first (read) — blocks even if node_id gate would pass
        let ip_blocked: bool = sqlx::query_scalar(
            "SELECT COUNT(*) > 0 FROM credit_ip_gates \
             WHERE ip_address = ? \
               AND last_allocation_at IS NOT NULL \
               AND last_allocation_at > NOW() - INTERVAL 6 HOUR",
        )
        .bind(ip)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false);

        if ip_blocked {
            return 0.0;
        }

        // Per-node_id gate: atomic UPDATE with WHERE (race-safe)
        let node_result = sqlx::query(
            "UPDATE nodes \
             SET credit_balance = credit_balance + ?, \
                 free_credit_last_allocation_at = NOW() \
             WHERE id = ? \
               AND (free_credit_last_allocation_at IS NULL \
                    OR free_credit_last_allocation_at < NOW() - INTERVAL 6 HOUR)",
        )
        .bind(FREE_AMOUNT)
        .bind(node_id)
        .execute(&self.pool)
        .await;

        match node_result {
            Ok(r) if r.rows_affected() > 0 => {
                // Node gate passed — update IP gate (upsert)
                let _ = sqlx::query(
                    "INSERT INTO credit_ip_gates (ip_address, last_allocation_at, allocation_count, created_at, updated_at) \
                     VALUES (?, NOW(), 1, NOW(), NOW()) \
                     ON DUPLICATE KEY UPDATE \
                       last_allocation_at = NOW(), \
                       allocation_count = allocation_count + 1, \
                       updated_at = NOW()",
                )
                .bind(ip)
                .execute(&self.pool)
                .await;
                FREE_AMOUNT
            }
            _ => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{credit_ttl_idle, median_outlier_weight};

    fn s(vals: &[f64]) -> Vec<(f64,)> {
        vals.iter().map(|&v| (v,)).collect()
    }

    // WQ-056 / billing §11.3 — the idle-determination rule the TTL sweep applies.
    // #404 behavior tests: each fails if the predicate (the "fix") is wrong/absent.
    const NOW: i64 = 1_780_000_000;

    #[test]
    fn ttl_idle_expired_earn_with_balance_is_swept() {
        // newest earn expired 1 day ago + positive balance → idle (forfeit).
        assert!(credit_ttl_idle(Some(NOW - 86_400), 40.0, NOW));
    }

    #[test]
    fn ttl_idle_fresh_earn_is_not_swept() {
        // newest earn TTL still in the future → active, even with a balance.
        assert!(!credit_ttl_idle(Some(NOW + 86_400), 40.0, NOW));
    }

    #[test]
    fn ttl_idle_zero_balance_is_not_swept() {
        // expired TTL but nothing to forfeit → not idle (keeps the sweep idempotent).
        assert!(!credit_ttl_idle(Some(NOW - 86_400), 0.0, NOW));
    }

    #[test]
    fn ttl_idle_no_earn_rows_is_not_swept() {
        // no determinable earn TTL → never expire on a guess (matches PHP).
        assert!(!credit_ttl_idle(None, 40.0, NOW));
    }

    #[test]
    fn outlier_weight_normal() {
        // latency = 100ms, median = 100ms → not an outlier
        let sample = s(&[80.0, 100.0, 120.0]);
        assert!((median_outlier_weight(100.0, &sample) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn outlier_weight_suppressed() {
        // latency = 400ms, median = 100ms → 4× → outlier → weight=0.1
        let sample = s(&[80.0, 100.0, 120.0]);
        assert!((median_outlier_weight(400.0, &sample) - 0.1).abs() < 1e-9);
    }

    #[test]
    fn outlier_weight_insufficient_sample() {
        // single-element sample → not enough for outlier check
        let sample = s(&[50.0]);
        assert!((median_outlier_weight(999.0, &sample) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn outlier_weight_even_sample_median() {
        // even n: median of [100,200] = 150; 400 < 3*150=450 → not outlier
        let sample = s(&[100.0, 200.0]);
        assert!((median_outlier_weight(400.0, &sample) - 1.0).abs() < 1e-9);
        // 500 > 3*150=450 → outlier
        assert!((median_outlier_weight(500.0, &sample) - 0.1).abs() < 1e-9);
    }
}

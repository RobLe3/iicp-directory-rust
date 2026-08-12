// SPDX-License-Identifier: Apache-2.0
//! MySQL-backed node repository — the Phase 1 data layer (PARITY: M3b).
//!
//! Drops in behind the same `NodeRepository` trait as `InMemoryRepo` so all
//! HTTP handlers remain unchanged. Activated when `DATABASE_URL` is set at
//! startup. Falls back to `InMemoryRepo` when it is not.

use async_trait::async_trait;
use sha2::Digest;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool, QueryBuilder, Row};

use crate::repo::{
    operator_fingerprint, verify_liveness_response, AuditResult, ConformanceBadge, CreditError,
    CreditSummary, CreditTransaction, DiscoverQuery, EffectiveCreditBalance, EventRow,
    FounderEntry, IntentSummary, NodeRecord, NodeRepository, OperatorLifecycleError,
    OperatorLifecycleResult, OperatorSelfServiceError, OperatorWalletSummary, PendingFounderEntry,
    ProbeResult, ProxyObservation, RegistryStats, RepoError, WalletDebitResult,
};
use crate::reputation;
use crate::types::Node;

fn is_transient_transaction_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database| database.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .is_some_and(|database| matches!(database.number(), 1205 | 1213))
}

enum CreditMutationError {
    NonceReplay,
    NodeNotFound,
    Database(sqlx::Error),
}

enum DebitMutationError {
    Insufficient(&'static str),
    Database {
        scope: &'static str,
        error: sqlx::Error,
    },
}

impl DebitMutationError {
    fn database(scope: &'static str, error: sqlx::Error) -> Self {
        Self::Database { scope, error }
    }
}

fn failed_debit(scope: &'static str, reason: &'static str) -> WalletDebitResult {
    WalletDebitResult {
        debited: false,
        spent: 0.0,
        scope,
        reason: Some(reason),
        debit_count: 0,
    }
}

async fn debit_node_once(
    pool: &Pool<MySql>,
    consumer_node_id: &str,
    amount: f64,
    task_id: &str,
    reason: &str,
) -> Result<WalletDebitResult, DebitMutationError> {
    const SCOPE: &str = "node";
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| DebitMutationError::database(SCOPE, error))?;
    let updated = sqlx::query(
        "UPDATE nodes n JOIN credits c ON c.node_id = n.id \
         SET n.credit_balance = n.credit_balance - ?, \
             c.balance = c.balance - ?, c.updated_at = NOW() \
         WHERE n.id = ? AND n.credit_balance + 0.0001 >= ? \
           AND c.balance + 0.0001 >= ? \
           AND ABS(n.credit_balance - c.balance) <= 0.0001",
    )
    .bind(amount)
    .bind(amount)
    .bind(consumer_node_id)
    .bind(amount)
    .bind(amount)
    .execute(&mut *tx)
    .await
    .map_err(|error| DebitMutationError::database(SCOPE, error))?;
    if updated.rows_affected() == 0 {
        return Err(DebitMutationError::Insufficient("insufficient_balance"));
    }
    sqlx::query(
        "INSERT INTO credit_transactions (node_id, amount, type, task_id, reason) \
         VALUES (?, ?, 'debit', ?, ?)",
    )
    .bind(consumer_node_id)
    .bind(amount)
    .bind(task_id)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(|error| DebitMutationError::database(SCOPE, error))?;
    tx.commit()
        .await
        .map_err(|error| DebitMutationError::database(SCOPE, error))?;
    Ok(WalletDebitResult {
        debited: true,
        spent: amount,
        scope: SCOPE,
        reason: None,
        debit_count: 1,
    })
}

async fn debit_operator_wallet_once(
    pool: &Pool<MySql>,
    consumer_node_id: &str,
    operator_pubkey: &str,
    amount: f64,
    task_id: &str,
    reason: &str,
) -> Result<WalletDebitResult, DebitMutationError> {
    const SCOPE: &str = "operator_wallet";
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| DebitMutationError::database(SCOPE, error))?;
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
    .bind(operator_pubkey)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| DebitMutationError::database(SCOPE, error))?;

    let available: f64 = candidates.iter().map(|(_, balance, _)| *balance).sum();
    if available + 0.0001 < amount {
        return Err(DebitMutationError::Insufficient(
            "insufficient_operator_wallet_balance",
        ));
    }

    let mut remaining = amount;
    let mut debit_count = 0_u32;
    for (node_id, balance, _) in candidates {
        if remaining <= 0.00005 {
            break;
        }
        let take = remaining.min(balance);
        let ledger: Option<(f64,)> = sqlx::query_as(
            "SELECT CAST(balance AS DOUBLE) FROM credits WHERE node_id = ? FOR UPDATE",
        )
        .bind(&node_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| DebitMutationError::database(SCOPE, error))?;
        if ledger.is_none_or(|(ledger_balance,)| (ledger_balance - balance).abs() > 0.0001) {
            return Err(DebitMutationError::database(
                SCOPE,
                sqlx::Error::Protocol("credit ledger and node balance disagree".to_string()),
            ));
        }
        let tx_reason = if node_id == consumer_node_id {
            reason.to_string()
        } else {
            format!(
                "{reason}:operator_wallet:consumer={}",
                &consumer_node_id[..consumer_node_id.len().min(8)]
            )
        };
        let updated = sqlx::query(
            "UPDATE nodes n JOIN credits c ON c.node_id = n.id \
             SET n.credit_balance = n.credit_balance - ?, \
                 c.balance = c.balance - ?, c.updated_at = NOW() \
             WHERE n.id = ? AND ABS(n.credit_balance - c.balance) <= 0.0001",
        )
        .bind(take)
        .bind(take)
        .bind(&node_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| DebitMutationError::database(SCOPE, error))?;
        if updated.rows_affected() == 0 {
            return Err(DebitMutationError::database(
                SCOPE,
                sqlx::Error::Protocol("credit ledger changed while locked".to_string()),
            ));
        }
        sqlx::query(
            "INSERT INTO credit_transactions (node_id, amount, type, task_id, reason) \
             VALUES (?, ?, 'debit', ?, ?)",
        )
        .bind(&node_id)
        .bind(take)
        .bind(task_id)
        .bind(tx_reason)
        .execute(&mut *tx)
        .await
        .map_err(|error| DebitMutationError::database(SCOPE, error))?;
        remaining -= take;
        debit_count += 1;
    }

    if remaining > 0.0001 {
        return Err(DebitMutationError::database(
            SCOPE,
            sqlx::Error::Protocol("operator wallet allocation was incomplete".to_string()),
        ));
    }
    tx.commit()
        .await
        .map_err(|error| DebitMutationError::database(SCOPE, error))?;
    Ok(WalletDebitResult {
        debited: true,
        spent: amount,
        scope: SCOPE,
        reason: None,
        debit_count,
    })
}

async fn expire_idle_credit_once(
    pool: &Pool<MySql>,
    node_id: &str,
    expected_balance: f64,
) -> Result<Option<f64>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE nodes n JOIN credits c ON c.node_id = n.id \
         SET n.credit_balance = 0, c.balance = 0, c.updated_at = NOW() \
         WHERE n.id = ? AND n.credit_balance = ? \
           AND ABS(n.credit_balance - c.balance) <= 0.0001",
    )
    .bind(node_id)
    .bind(expected_balance)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(None);
    }
    sqlx::query(
        "INSERT INTO credit_transactions (node_id, amount, type, reason) \
         VALUES (?, ?, 'debit', 'ttl_expire')",
    )
    .bind(node_id)
    .bind(expected_balance)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(expected_balance))
}

async fn record_credit_award_once(
    pool: &Pool<MySql>,
    node_id: &str,
    amount: f64,
    task_id: &str,
    nonce: &str,
) -> Result<f64, CreditMutationError> {
    let mut tx = pool.begin().await.map_err(CreditMutationError::Database)?;
    let node_balance: Option<(f64,)> =
        sqlx::query_as("SELECT CAST(credit_balance AS DOUBLE) FROM nodes WHERE id = ? FOR UPDATE")
            .bind(node_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(CreditMutationError::Database)?;
    let Some((node_balance,)) = node_balance else {
        return Err(CreditMutationError::NodeNotFound);
    };

    sqlx::query(
        "INSERT INTO credits (node_id, balance, created_at, updated_at) \
         VALUES (?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE node_id = VALUES(node_id)",
    )
    .bind(node_id)
    .bind(node_balance)
    .execute(&mut *tx)
    .await
    .map_err(CreditMutationError::Database)?;
    let (ledger_balance,): (f64,) =
        sqlx::query_as("SELECT CAST(balance AS DOUBLE) FROM credits WHERE node_id = ? FOR UPDATE")
            .bind(node_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(CreditMutationError::Database)?;
    if (ledger_balance - node_balance).abs() > 0.0001 {
        return Err(CreditMutationError::Database(sqlx::Error::Protocol(
            "credit ledger and node balance disagree".to_string(),
        )));
    }

    let insert = sqlx::query(
        "INSERT INTO credit_transactions \
         (node_id, amount, type, task_id, nonce, reason, expires_at) \
         VALUES (?, ?, 'credit', ?, ?, 'cip_award', NOW() + INTERVAL 90 DAY)",
    )
    .bind(node_id)
    .bind(amount)
    .bind(task_id)
    .bind(nonce)
    .execute(&mut *tx)
    .await;
    if let Err(error) = insert {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            return Err(CreditMutationError::NonceReplay);
        }
        return Err(CreditMutationError::Database(error));
    }

    let new_balance = ((ledger_balance + amount) * 10_000.0).round() / 10_000.0;
    sqlx::query("UPDATE credits SET balance = ?, updated_at = NOW() WHERE node_id = ?")
        .bind(new_balance)
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .map_err(CreditMutationError::Database)?;
    sqlx::query("UPDATE nodes SET credit_balance = ? WHERE id = ?")
        .bind(new_balance)
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .map_err(CreditMutationError::Database)?;
    tx.commit().await.map_err(CreditMutationError::Database)?;
    Ok(new_balance)
}

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

/// Raw row from the `nodes` table. Numeric SELECTs cast FLOAT/DOUBLE columns to
/// DOUBLE so this row works against both the standalone and Laravel schemas.
#[derive(sqlx::FromRow)]
struct NodeRow {
    id: String,
    endpoint: String,
    region: String,
    reputation_score: f64,
    available: bool,
    load: f64,
    active_jobs: u32,
    max_concurrent: u32,
    tasks_total: u32,
    avg_latency_ms: f64,
    exposure_mode: Option<String>,
    transport_endpoint: Option<String>,
    // #400 — discover field parity with PHP (NodeScorer emits these).
    #[sqlx(default)]
    credit_cost_multiplier: f64,
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
    implementation_name: Option<String>,
    #[sqlx(default)]
    implementation_version: Option<String>,
    #[sqlx(default)]
    sdk_compatibility_version: Option<String>,
    #[sqlx(default)]
    sdk_version: Option<String>,
    #[sqlx(default)]
    supported_receipt_profiles: Option<String>,
    #[sqlx(default)]
    backend: Option<String>,
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
    #[sqlx(default)]
    policy_manifest: Option<String>,
    // #494 — runtime model list from the node's last heartbeat. JSON-encoded array.
    // null = not yet reported (backward compat); []/"[]" = no models live.
    #[sqlx(default)]
    health_models: Option<String>,
    #[sqlx(default)]
    capability_models: Option<String>,
    #[sqlx(default)]
    capability_supported_profiles: Option<String>,
    #[sqlx(default)]
    backend_stability: Option<String>,
    #[sqlx(default)]
    pricing_credits_per_1000: Option<f64>,
    #[sqlx(default)]
    cx_public_key: Option<String>,
    #[sqlx(default)]
    availability_score: f64,
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
        let rep = r.reputation_score;
        let lat = r.avg_latency_ms;
        Node {
            node_id: r.id,
            endpoint: r.endpoint,
            region: r.region,
            score: rep,
            available: r.available,
            load: r.load,
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
            models: r
                .capability_models
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_default(),
            supported_profiles: r
                .capability_supported_profiles
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_default(),
            pricing: None,
            // Phase 5 fields — MySQL columns pending Phase 5 migration; default None/empty.
            nat_type: None,
            transport_method: None,
            // #385 — relay_capable now persisted (PHP discover emits it; NodeScorer:221).
            relay_capable: Some(r.relay_capable),
            sdk_language: r.sdk_language,
            implementation_name: r.implementation_name,
            implementation_version: r.implementation_version,
            sdk_compatibility_version: r
                .sdk_compatibility_version
                .clone()
                .or_else(|| r.sdk_version.clone()),
            sdk_version: r.sdk_compatibility_version.or(r.sdk_version),
            consumer_cosignature_ready: r
                .supported_receipt_profiles
                .as_deref()
                .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
                .is_some_and(|profiles| profiles.iter().any(|p| p == "consumer_cosignature_v1")),
            backend: r.backend,
            address_family: None, // set at query time by detect_address_family
            cip_policy: Some(serde_json::json!({
                "allow_remote_inference": false, "allow_tool_execution": false,
                "allow_file_access": false, "pricing_credits_per_1000": null
            })),
            quantization: vec![],
            inference_engine: vec![],
            public_key: r
                .cx_public_key
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok()),
            transport_metadata: None,
            // #400 — discover field parity. credit_cost_multiplier defaults to
            // 1.0 when the column was absent (sqlx default → 0.0 → coerce to 1.0).
            credit_cost_multiplier: if r.credit_cost_multiplier > 0.0 {
                r.credit_cost_multiplier
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
            policy_manifest: r
                .policy_manifest
                .as_deref()
                .and_then(|value| serde_json::from_str(value).ok()),
            // #494 — decode JSON-encoded health_models from DB (null → None, "[]" → Some([])).
            health_models: r
                .health_models
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
            routing_policy: crate::types::RoutingPolicyState {
                availability_score: if r.availability_score > 0.0 {
                    r.availability_score
                } else {
                    1.0
                },
                backend_state: r
                    .backend_stability
                    .as_deref()
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                    .and_then(|value| {
                        value
                            .get("backend_state")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    }),
                pricing_credits_per_1000: r.pricing_credits_per_1000,
            },
        }
    }
}

async fn capability_profile_union(pool: &Pool<MySql>, node_id: &str) -> Vec<String> {
    let rows: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT CAST(supported_profiles AS CHAR) FROM capabilities WHERE node_id = ?",
    )
    .bind(node_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let mut profiles: Vec<String> = rows
        .into_iter()
        .flat_map(|(raw,)| {
            raw.as_deref()
                .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
                .unwrap_or_default()
        })
        .collect();
    profiles.sort();
    profiles.dedup();
    profiles
}

// ── MySqlRepo ─────────────────────────────────────────────────────────────────

pub struct MySqlRepo {
    pool: Pool<MySql>,
}

impl MySqlRepo {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_arguments)]
    async fn heartbeat_once(
        &self,
        node_id: &str,
        load: f64,
        available: bool,
        active_jobs: u32,
        tasks_delta: u32,
        tasks_failed_delta: u32,
        delta: f64,
        health_models: Option<&[String]>,
    ) -> Result<Option<f64>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // RT-01b (#381): fetch velocity window alongside score. Laravel stores
        // rep_hourly_gain as DECIMAL(8,4), so cast it for sqlx decoding.
        let row: Option<(f64, f64, Option<chrono::NaiveDateTime>)> = sqlx::query_as(
            "SELECT CAST(reputation_score AS DOUBLE), CAST(rep_hourly_gain AS DOUBLE), \
                    CAST(rep_hourly_window_start AS DATETIME) \
             FROM nodes WHERE id = ? FOR UPDATE",
        )
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((old_score, hourly_gain, window_start)) = row else {
            return Ok(None);
        };

        const MAX_HOURLY_GAIN: f64 = 0.20;
        let (effective_delta, new_hourly_gain, reset_window) = if delta > 0.0 {
            let window_expired = window_start
                .map(|ws| {
                    let now = chrono::Utc::now().naive_utc();
                    (now - ws).num_seconds() >= 3600
                })
                .unwrap_or(true);
            let current_gain = if window_expired { 0.0 } else { hourly_gain };
            let capped = delta.min((MAX_HOURLY_GAIN - current_gain).max(0.0));
            (
                capped,
                current_gain + capped,
                window_expired || window_start.is_none(),
            )
        } else {
            (delta, hourly_gain, false)
        };
        let new_score = reputation::apply_delta(old_score, effective_delta);
        let health_models_json = health_models
            .map(|models| serde_json::to_string(models).unwrap_or_else(|_| "[]".to_string()));

        // The locked SELECT above establishes existence. MySQL reports zero
        // affected rows when an otherwise successful heartbeat writes exactly
        // the stored values (including a same-second `NOW()`), so row count is
        // not an existence or commit signal here.
        sqlx::query(
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
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(new_score))
    }
}

/// Initialise a connection pool from `DATABASE_URL`. Schema bootstrap and
/// compatibility verification are handled separately by `schema::ensure_schema`.
pub async fn init_pool(url: &str) -> Result<Pool<MySql>, sqlx::Error> {
    MySqlPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await
}

struct MysqlDsrSubject {
    operator_pubkey: String,
    node_ids: Vec<String>,
    fingerprint: String,
    pubkey_sha256: String,
    selector: serde_json::Value,
    subject_hash: String,
}

async fn mysql_operator_dsr(
    pool: &Pool<MySql>,
    operator_pubkey: &str,
    action: &str,
    tracking_id: &str,
) -> Result<serde_json::Value, OperatorSelfServiceError> {
    let subject = load_mysql_dsr_subject(pool, operator_pubkey).await?;
    if action == "export" {
        return mysql_dsr_export(pool, &subject, tracking_id).await;
    }
    mutate_mysql_dsr(pool, operator_pubkey, action, tracking_id, &subject).await
}

async fn load_mysql_dsr_subject(
    pool: &Pool<MySql>,
    operator_pubkey: &str,
) -> Result<MysqlDsrSubject, OperatorSelfServiceError> {
    use sha2::{Digest, Sha256};
    let active: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM operators \
         WHERE operator_pubkey = ? AND identity_status = 'active' LIMIT 1",
    )
    .bind(operator_pubkey)
    .fetch_optional(pool)
    .await
    .map_err(|_| OperatorSelfServiceError::Storage)?;
    let Some(_) = active else {
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
                .bind(operator_pubkey)
                .fetch_optional(pool)
                .await
                .map_err(|_| OperatorSelfServiceError::Storage)?;
        return Err(if exists.is_some() {
            OperatorSelfServiceError::Inactive
        } else {
            OperatorSelfServiceError::Unknown
        });
    };
    let fingerprint = operator_fingerprint(operator_pubkey);
    let pubkey_sha256 = hex::encode(Sha256::digest(operator_pubkey.as_bytes()));
    // Preserve the Laravel service's established insertion order for the
    // subject-hash preimage (`sha256`, then `fingerprint`). The response object
    // itself is semantically unordered, but the stored audit hash is a byte
    // contract and therefore must not depend on serde map ordering.
    let selector_json = format!(
        r#"{{"operator_pubkey":{{"sha256":{},"fingerprint":{}}}}}"#,
        serde_json::to_string(&pubkey_sha256).unwrap_or_default(),
        serde_json::to_string(&fingerprint).unwrap_or_default(),
    );
    let selector =
        serde_json::from_str(&selector_json).map_err(|_| OperatorSelfServiceError::Storage)?;
    let subject_hash = hex::encode(Sha256::digest(selector_json.as_bytes()));
    let node_ids = sqlx::query_scalar("SELECT id FROM nodes WHERE operator_pubkey = ? ORDER BY id")
        .bind(operator_pubkey)
        .fetch_all(pool)
        .await
        .map_err(|_| OperatorSelfServiceError::Storage)?;
    Ok(MysqlDsrSubject {
        operator_pubkey: operator_pubkey.to_string(),
        node_ids,
        fingerprint,
        pubkey_sha256,
        selector,
        subject_hash,
    })
}

/// Executable DsrRelatedRecordsV1 export surface shared with the Laravel seed.
async fn mysql_dsr_export(
    pool: &Pool<MySql>,
    subject: &MysqlDsrSubject,
    tracking_id: &str,
) -> Result<serde_json::Value, OperatorSelfServiceError> {
    let operators = mysql_dsr_operator_rows(pool, subject).await?;
    let nodes = mysql_dsr_node_rows(pool, subject).await?;
    let capabilities = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('node_id',node_id,'intent',intent,'models',models,'max_tokens',max_tokens,'quantization',quantization,'inference_engine',inference_engine,'input_modalities',input_modalities,'supported_profiles',supported_profiles) AS CHAR) AS row_json FROM capabilities",
        "node_id",
        &subject.node_ids,
        "node_id, id",
    ).await?;
    let credits = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('node_id',node_id,'balance',CAST(balance AS CHAR),'free_credit_last_allocation_at',free_credit_last_allocation_at,'created_at',created_at,'updated_at',updated_at) AS CHAR) AS row_json FROM credits",
        "node_id",
        &subject.node_ids,
        "node_id",
    ).await?;
    let credit_transactions = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('id',id,'node_id',node_id,'amount',CAST(amount AS CHAR),'type',type,'task_id',task_id,'reason',reason,'expires_at',expires_at,'created_at',created_at) AS CHAR) AS row_json FROM credit_transactions",
        "node_id",
        &subject.node_ids,
        "node_id, id",
    ).await?;
    let reputations = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('node_id',node_id,'score',score,'tasks_total',tasks_total,'tasks_failed',tasks_failed,'completed_tasks_count',completed_tasks_count,'avg_latency_ms',avg_latency_ms,'observed_latency_ms',observed_latency_ms) AS CHAR) AS row_json FROM reputations",
        "node_id",
        &subject.node_ids,
        "node_id",
    ).await?;
    let node_address_history = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('id',id,'node_id',node_id,'ip_address',ip_address,'request_type',request_type,'observed_at',observed_at) AS CHAR) AS row_json FROM node_address_history",
        "node_id",
        &subject.node_ids,
        "node_id, id",
    ).await?;
    let telemetry_probes = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('id',id,'node_id',node_id,'run_id',run_id,'probe_id',probe_id,'probe_type',probe_type,'test_id',test_id,'level',level,'passed',passed,'latency_ms',latency_ms,'probed_at',probed_at) AS CHAR) AS row_json FROM iicp_telemetry_probes",
        "node_id",
        &subject.node_ids,
        "node_id, id",
    ).await?;
    let proxy_telemetry = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('id',id,'node_id',node_id,'proxy_node_id',proxy_node_id,'time_bucket',time_bucket,'latency_ms_observed',latency_ms_observed,'tokens_observed',tokens_observed,'status',status,'qos_advertised',qos_advertised,'qos_met',qos_met) AS CHAR) AS row_json FROM proxy_telemetry",
        "node_id",
        &subject.node_ids,
        "node_id, id",
    ).await?;
    let node_events = mysql_dsr_node_event_rows(pool, &subject.node_ids).await?;
    let data_subject_actions = mysql_dsr_prior_actions(pool, &subject.subject_hash).await?;
    Ok(serde_json::json!({
        "schema": "iicp.dsr.export.v1",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "tracking_id": tracking_id,
        "selector": subject.selector,
        "subject_hash": subject.subject_hash,
        "retention_notice": crate::repo::DSR_RETENTION_REASON,
        "records": {
            "operators": operators,
            "nodes": nodes,
            "capabilities": capabilities,
            "credits": credits,
            "credit_transactions": credit_transactions,
            "reputations": reputations,
            "node_address_history": node_address_history,
            "telemetry_probes": telemetry_probes,
            "proxy_telemetry": proxy_telemetry,
            "node_events": node_events,
            "data_subject_actions": data_subject_actions
        }
    }))
}

async fn mysql_dsr_operator_rows(
    pool: &Pool<MySql>,
    subject: &MysqlDsrSubject,
) -> Result<Vec<serde_json::Value>, OperatorSelfServiceError> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT CAST(JSON_OBJECT('id',id,'display_name',display_name,'attested_created_at',attested_created_at,'operator_integrity_hash',operator_integrity_hash,'first_seen_ms',first_seen_ms,'ordinal',ordinal,'tier',tier,'badge',badge,'provenance',provenance,'terms_version',terms_version,'terms_accepted_at',IF(terms_accepted_at IS NULL,NULL,DATE_FORMAT(terms_accepted_at,'%Y-%m-%dT%H:%i:%s+00:00')),'dpa_version',dpa_version,'dpa_accepted_at',IF(dpa_accepted_at IS NULL,NULL,DATE_FORMAT(dpa_accepted_at,'%Y-%m-%dT%H:%i:%s+00:00')),'acceptance_method',acceptance_method,'created_at',IF(created_at IS NULL,NULL,DATE_FORMAT(created_at,'%Y-%m-%dT%H:%i:%s+00:00')),'updated_at',IF(updated_at IS NULL,NULL,DATE_FORMAT(updated_at,'%Y-%m-%dT%H:%i:%s+00:00'))) AS CHAR) FROM operators WHERE operator_pubkey = ? LIMIT 1",
    )
    .bind(&subject.operator_pubkey)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        eprintln!("IICP DSR storage failure at operator export: {error}");
        OperatorSelfServiceError::Storage
    })?;
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let mut value: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
        eprintln!("IICP DSR JSON decode failure at operator export: {error}");
        OperatorSelfServiceError::Storage
    })?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "operator_fingerprint".into(),
            subject.fingerprint.clone().into(),
        );
        object.insert(
            "operator_pubkey_sha256".into(),
            subject.pubkey_sha256.clone().into(),
        );
    }
    Ok(vec![value])
}

async fn mysql_dsr_node_rows(
    pool: &Pool<MySql>,
    subject: &MysqlDsrSubject,
) -> Result<Vec<serde_json::Value>, OperatorSelfServiceError> {
    let mut rows = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('id',id,'endpoint',endpoint,'region',region,'status',status,'available',available,'public_listing',public_listing,'operator_url',operator_url,'operator_contact',operator_contact,'operator_verified',operator_verified,'operator_trust_tier',operator_trust_tier,'observed_source_ip',observed_source_ip,'last_seen',IF(last_seen IS NULL,NULL,DATE_FORMAT(last_seen,'%Y-%m-%dT%H:%i:%s+00:00')),'dormant_since',IF(dormant_since IS NULL,NULL,DATE_FORMAT(dormant_since,'%Y-%m-%dT%H:%i:%s+00:00')),'policy_manifest',policy_manifest,'sdk_language',sdk_language,'implementation_name',implementation_name,'implementation_version',implementation_version,'sdk_compatibility_version',COALESCE(sdk_compatibility_version,sdk_version),'sdk_version',COALESCE(sdk_compatibility_version,sdk_version),'secret_fields_present',JSON_OBJECT('node_token_hash',node_token_hash IS NOT NULL,'proxy_token_hash',proxy_token_hash IS NOT NULL,'node_hmac_key',node_hmac_key IS NOT NULL)) AS CHAR) AS row_json FROM nodes",
        "id",
        &subject.node_ids,
        "id",
    ).await?;
    for row in &mut rows {
        let Some(object) = row.as_object_mut() else {
            continue;
        };
        object.insert(
            "operator_fingerprint".into(),
            subject.fingerprint.clone().into(),
        );
        for field in ["available", "public_listing", "operator_verified"] {
            normalize_mysql_bool(object, field);
        }
        if let Some(secrets) = object
            .get_mut("secret_fields_present")
            .and_then(serde_json::Value::as_object_mut)
        {
            for field in ["node_token_hash", "proxy_token_hash", "node_hmac_key"] {
                normalize_mysql_bool(secrets, field);
            }
        }
        if let Some(manifest) = object.get_mut("policy_manifest") {
            redact_dsr_payload(manifest);
        }
    }
    Ok(rows)
}

fn normalize_mysql_bool(object: &mut serde_json::Map<String, serde_json::Value>, field: &str) {
    if let Some(value) = object.get_mut(field) {
        if let Some(number) = value.as_i64() {
            *value = serde_json::Value::Bool(number != 0);
        } else if let Some(number) = value.as_u64() {
            *value = serde_json::Value::Bool(number != 0);
        }
    }
}

fn redact_dsr_payload(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let keys = object.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let Some(item) = object.get_mut(&key) else {
            continue;
        };
        if matches!(
            key.as_str(),
            "node_token"
                | "node_token_hash"
                | "proxy_token"
                | "proxy_token_hash"
                | "node_hmac_key"
                | "current_node_token"
        ) {
            *item = serde_json::Value::String("[redacted]".into());
            continue;
        }
        if matches!(
            key.as_str(),
            "operator_pubkey" | "public_key" | "did_public_key"
        ) {
            if let Some(raw) = item.as_str().map(str::to_string) {
                use sha2::{Digest, Sha256};
                if key == "operator_pubkey" {
                    object.insert(
                        "operator_fingerprint".into(),
                        operator_fingerprint(&raw).into(),
                    );
                } else {
                    object.insert(
                        format!("{key}_sha256"),
                        hex::encode(Sha256::digest(raw.as_bytes())).into(),
                    );
                }
                object.insert(key, serde_json::Value::String("[redacted]".into()));
            }
            continue;
        }
        if item.is_object() {
            redact_dsr_payload(item);
        } else if let Some(array) = item.as_array_mut() {
            for nested in array {
                redact_dsr_payload(nested);
            }
        }
    }
}

async fn mysql_dsr_node_table_rows(
    pool: &Pool<MySql>,
    select: &'static str,
    filter_column: &'static str,
    node_ids: &[String],
    order_by: &'static str,
) -> Result<Vec<serde_json::Value>, OperatorSelfServiceError> {
    if node_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut query = QueryBuilder::<MySql>::new(select);
    query.push(" WHERE ").push(filter_column).push(" IN (");
    let mut separated = query.separated(",");
    for node_id in node_ids {
        separated.push_bind(node_id);
    }
    separated.push_unseparated(") ORDER BY ");
    query.push(order_by).push(" LIMIT 500");
    let rows = query.build().fetch_all(pool).await.map_err(|error| {
        eprintln!("IICP DSR storage failure at related-record export ({order_by}): {error}");
        OperatorSelfServiceError::Storage
    })?;
    decode_dsr_json_rows(rows)
}

fn decode_dsr_json_rows(
    rows: Vec<sqlx::mysql::MySqlRow>,
) -> Result<Vec<serde_json::Value>, OperatorSelfServiceError> {
    rows.into_iter()
        .map(|row| {
            let raw: String = row.try_get("row_json").map_err(|error| {
                eprintln!("IICP DSR row decode failure: {error}");
                OperatorSelfServiceError::Storage
            })?;
            serde_json::from_str(&raw).map_err(|error| {
                eprintln!("IICP DSR JSON decode failure: {error}");
                OperatorSelfServiceError::Storage
            })
        })
        .collect()
}

async fn mysql_dsr_node_event_rows(
    pool: &Pool<MySql>,
    node_ids: &[String],
) -> Result<Vec<serde_json::Value>, OperatorSelfServiceError> {
    let mut rows = mysql_dsr_node_table_rows(
        pool,
        "SELECT CAST(JSON_OBJECT('event_id',event_id,'seq',seq,'event_type',event_type,'node_id',node_id,'ts_ms',ts_ms,'payload',payload,'prev_hash',prev_hash,'signature_present',signature IS NOT NULL,'created_at',created_at) AS CHAR) AS row_json FROM node_events",
        "node_id",
        node_ids,
        "seq",
    ).await?;
    for row in &mut rows {
        let Some(object) = row.as_object_mut() else {
            continue;
        };
        normalize_mysql_bool(object, "signature_present");
        if let Some(payload) = object.get_mut("payload") {
            redact_dsr_payload(payload);
        }
    }
    Ok(rows)
}

async fn mysql_dsr_prior_actions(
    pool: &Pool<MySql>,
    subject_hash: &str,
) -> Result<Vec<serde_json::Value>, OperatorSelfServiceError> {
    let rows = sqlx::query(
        "SELECT CAST(JSON_OBJECT('tracking_id',tracking_id,'action',action,'subject_hash',subject_hash,'affected_counts',affected_counts,'retention_reason',retention_reason,'applied_at',applied_at) AS CHAR) AS row_json FROM data_subject_actions WHERE subject_hash = ? ORDER BY id LIMIT 500",
    )
    .bind(subject_hash)
    .fetch_all(pool)
    .await
    .map_err(|error| {
        eprintln!("IICP DSR storage failure at prior-action export: {error}");
        OperatorSelfServiceError::Storage
    })?;
    decode_dsr_json_rows(rows)
}

async fn mutate_mysql_dsr(
    pool: &Pool<MySql>,
    operator_pubkey: &str,
    action: &str,
    tracking_id: &str,
    subject: &MysqlDsrSubject,
) -> Result<serde_json::Value, OperatorSelfServiceError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| OperatorSelfServiceError::Storage)?;
    let mut counts = mysql_dsr_affected_counts(&mut tx, &subject.node_ids).await?;
    apply_mysql_dsr_restriction(&mut tx, operator_pubkey, action).await?;
    if action == "anonymize" {
        let deleted =
            apply_mysql_dsr_anonymization(&mut tx, operator_pubkey, tracking_id, &subject.node_ids)
                .await?;
        if let Some(object) = counts.as_object_mut() {
            object.insert("deleted_node_address_history".into(), deleted.0.into());
            object.insert("deleted_telemetry_probes".into(), deleted.1.into());
            object.insert("deleted_proxy_telemetry".into(), deleted.2.into());
        }
    }
    insert_mysql_dsr_action(
        &mut tx,
        tracking_id,
        action,
        &subject.subject_hash,
        &subject.selector,
        &counts,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|_| OperatorSelfServiceError::Storage)?;
    Ok(serde_json::json!({
        "action": action, "dry_run": false, "tracking_id": tracking_id,
        "selector": subject.selector, "subject_hash": subject.subject_hash,
        "affected_counts": counts, "retention_reason": crate::repo::DSR_RETENTION_REASON
    }))
}

async fn mysql_dsr_affected_counts(
    tx: &mut sqlx::Transaction<'_, MySql>,
    node_ids: &[String],
) -> Result<serde_json::Value, OperatorSelfServiceError> {
    Ok(serde_json::json!({
        "nodes": node_ids.len(),
        "operators": 1,
        "credits": mysql_dsr_count(tx, "credits", node_ids).await?,
        "credit_transactions": mysql_dsr_count(tx, "credit_transactions", node_ids).await?,
        "node_events_retained": mysql_dsr_count(tx, "node_events", node_ids).await?,
        "node_address_history": mysql_dsr_count(tx, "node_address_history", node_ids).await?,
        "telemetry_probes": mysql_dsr_count(tx, "iicp_telemetry_probes", node_ids).await?,
        "proxy_telemetry": mysql_dsr_count(tx, "proxy_telemetry", node_ids).await?,
    }))
}

async fn mysql_dsr_count(
    tx: &mut sqlx::Transaction<'_, MySql>,
    table: &'static str,
    node_ids: &[String],
) -> Result<u64, OperatorSelfServiceError> {
    if node_ids.is_empty() {
        return Ok(0);
    }
    let mut query = QueryBuilder::<MySql>::new("SELECT COUNT(*) FROM ");
    query.push(table).push(" WHERE node_id IN (");
    let mut separated = query.separated(",");
    for node_id in node_ids {
        separated.push_bind(node_id);
    }
    separated.push_unseparated(")");
    query
        .build_query_scalar::<i64>()
        .fetch_one(&mut **tx)
        .await
        .map(|count| count.max(0) as u64)
        .map_err(|error| {
            eprintln!("IICP DSR storage failure while counting {table}: {error}");
            OperatorSelfServiceError::Storage
        })
}

async fn apply_mysql_dsr_restriction(
    tx: &mut sqlx::Transaction<'_, MySql>,
    operator_pubkey: &str,
    action: &str,
) -> Result<(), OperatorSelfServiceError> {
    sqlx::query(
        "UPDATE nodes SET available = 0, public_reachable = 0, public_listing = 0, \
         operator_url = NULL, operator_contact = NULL, status = 'archived', dormant_since = NOW(), \
         transport_endpoint = NULL, endpoint_verified_dead_at = NOW(), updated_at = NOW() \
         WHERE operator_pubkey = ?",
    )
    .bind(operator_pubkey)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        eprintln!("IICP DSR storage failure while restricting nodes: {error}");
        OperatorSelfServiceError::Storage
    })?;
    sqlx::query(
        "UPDATE operators SET identity_status = 'restricted', display_name = NULL, attested_created_at = NULL, \
         operator_integrity_hash = NULL, terms_version = NULL, terms_accepted_at = NULL, \
         dpa_version = NULL, dpa_accepted_at = NULL, acceptance_method = NULL, \
         acceptance_nonce_sha256 = NULL, tier = NULL, badge = NULL, \
         provenance = JSON_OBJECT('dsr', ?), updated_at = NOW() WHERE operator_pubkey = ?",
    )
    .bind(if action == "anonymize" {
        "anonymized"
    } else {
        "restricted"
    })
    .bind(operator_pubkey)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        eprintln!("IICP DSR storage failure while restricting operator: {error}");
        OperatorSelfServiceError::Storage
    })?;
    Ok(())
}

async fn apply_mysql_dsr_anonymization(
    tx: &mut sqlx::Transaction<'_, MySql>,
    operator_pubkey: &str,
    tracking_id: &str,
    node_ids: &[String],
) -> Result<(u64, u64, u64), OperatorSelfServiceError> {
    sqlx::query(
        "UPDATE nodes SET endpoint = CONCAT('https://dsr-anonymized.invalid/node-', LEFT(id, 8)), \
         observed_source_ip = NULL, operator_pubkey = NULL, operator_verified = 0, \
         operator_trust_tier = NULL, identity_key = SHA2(CONCAT('dsr:', ?, ':', id), 256), \
         liveness_challenge = NULL, liveness_verified_at = NULL, policy_manifest = NULL, \
         cx_public_key = NULL, gossip_public_key = NULL, \
         node_token_hash = SHA2(CONCAT(UUID(), RAND()), 256), \
         proxy_token_hash = LEFT(SHA2(CONCAT(UUID(), RAND()), 256), 60), \
         node_hmac_key = SHA2(CONCAT(UUID(), RAND()), 256), updated_at = NOW() \
         WHERE operator_pubkey = ?",
    )
    .bind(tracking_id)
    .bind(operator_pubkey)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        eprintln!("IICP DSR storage failure while anonymizing nodes: {error}");
        OperatorSelfServiceError::Storage
    })?;
    let deleted = delete_mysql_dsr_telemetry(tx, node_ids).await?;
    sqlx::query(
        "UPDATE operators SET operator_pubkey = CONCAT('dsr_', LEFT(SHA2(CONCAT('operator:', ?, ':', ?), 256), 60)), identity_status = 'restricted', updated_at = NOW() WHERE operator_pubkey = ?",
    )
    .bind(tracking_id)
    .bind(operator_pubkey)
    .bind(operator_pubkey)
    .execute(&mut **tx)
    .await
    .map_err(|error| {
        eprintln!("IICP DSR storage failure while anonymizing operator: {error}");
        OperatorSelfServiceError::Storage
    })?;
    Ok(deleted)
}

async fn delete_mysql_dsr_telemetry(
    tx: &mut sqlx::Transaction<'_, MySql>,
    node_ids: &[String],
) -> Result<(u64, u64, u64), OperatorSelfServiceError> {
    let address = delete_mysql_dsr_rows(tx, "node_address_history", node_ids).await?;
    let probes = delete_mysql_dsr_rows(tx, "iicp_telemetry_probes", node_ids).await?;
    let proxy = delete_mysql_dsr_rows(tx, "proxy_telemetry", node_ids).await?;
    Ok((address, probes, proxy))
}

async fn delete_mysql_dsr_rows(
    tx: &mut sqlx::Transaction<'_, MySql>,
    table: &'static str,
    node_ids: &[String],
) -> Result<u64, OperatorSelfServiceError> {
    if node_ids.is_empty() {
        return Ok(0);
    }
    let mut query = QueryBuilder::<MySql>::new("DELETE FROM ");
    query.push(table).push(" WHERE node_id IN (");
    let mut separated = query.separated(",");
    for node_id in node_ids {
        separated.push_bind(node_id);
    }
    separated.push_unseparated(")");
    query
        .build()
        .execute(&mut **tx)
        .await
        .map(|result| result.rows_affected())
        .map_err(|error| {
            eprintln!("IICP DSR storage failure while deleting {table}: {error}");
            OperatorSelfServiceError::Storage
        })
}

async fn insert_mysql_dsr_action(
    tx: &mut sqlx::Transaction<'_, MySql>,
    tracking_id: &str,
    action: &str,
    subject_hash: &str,
    selector: &serde_json::Value,
    counts: &serde_json::Value,
) -> Result<(), OperatorSelfServiceError> {
    let result = sqlx::query(
        "INSERT INTO data_subject_actions (tracking_id, action, subject_hash, selector, affected_counts, retention_reason, applied_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW(), NOW())",
    )
    .bind(tracking_id)
    .bind(action)
    .bind(subject_hash)
    .bind(selector.to_string())
    .bind(counts.to_string())
    .bind(crate::repo::DSR_RETENTION_REASON)
    .execute(&mut **tx)
    .await;
    result.map(|_| ()).map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            OperatorSelfServiceError::DuplicateTrackingId
        } else {
            eprintln!("IICP DSR storage failure while recording action: {error}");
            OperatorSelfServiceError::Storage
        }
    })
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
                      n.public_reachable, n.relay_capable, n.backend,
                      n.sdk_language, n.implementation_name, n.implementation_version, n.sdk_compatibility_version, n.sdk_version,
                      CAST(n.supported_receipt_profiles AS CHAR) AS supported_receipt_profiles,
                      CAST(n.health_models AS CHAR) AS health_models,
                      CAST(c.models AS CHAR) AS capability_models,
                      CAST(c.supported_profiles AS CHAR) AS capability_supported_profiles,
                      CAST(n.backend_stability AS CHAR) AS backend_stability,
                      CAST(n.pricing_credits_per_1000 AS DOUBLE) AS pricing_credits_per_1000,
                      CAST(n.cx_public_key AS CHAR) AS cx_public_key,
                      CAST(COALESCE(
                        (SELECT aw.share FROM availability_windows aw
                         WHERE aw.node_id = n.id AND CURTIME() BETWEEN aw.start_time AND aw.end_time
                         ORDER BY aw.id ASC LIMIT 1),
                        CASE WHEN EXISTS (
                          SELECT 1 FROM availability_windows aw2 WHERE aw2.node_id = n.id
                        ) THEN 0.5 ELSE 1.0 END
                      ) AS DOUBLE) AS availability_score,
                      CAST(n.policy_manifest AS CHAR) AS policy_manifest
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
    /// same explicit transaction. No token becomes usable and no capability
    /// becomes partially visible unless the complete registration commits.
    async fn register(&self, rec: NodeRecord) -> Result<(), RepoError> {
        // Bcrypt-hash node_token and proxy_token concurrently (cost 12 = PHP default).
        let (token_hash, proxy_hash) = crate::registration_store::hash_tokens(&rec).await?;
        crate::registration_store::persist(&self.pool, &rec, &token_hash, &proxy_hash).await
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
        for attempt in 0..3 {
            match self
                .heartbeat_once(
                    node_id,
                    load,
                    available,
                    active_jobs,
                    tasks_delta,
                    tasks_failed_delta,
                    delta,
                    health_models.as_deref(),
                )
                .await
            {
                Ok(result) => return result,
                Err(error) if attempt < 2 && is_transient_transaction_error(&error) => continue,
                Err(error) => {
                    eprintln!("heartbeat transaction failed: {error}");
                    return None;
                }
            }
        }
        None
    }

    /// Fetch a single node by id for the node-detail endpoint (iicp-dir §3.4.x).
    async fn get(&self, node_id: &str) -> Option<Node> {
        let row: Option<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                      available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                      tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                      exposure_mode, transport_endpoint,
                      CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                      pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, backend, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles,
                      operator_pubkey, operator_verified, operator_trust_tier, CAST(policy_manifest AS CHAR) AS policy_manifest
               FROM nodes WHERE id = ?"#,
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        let mut node = row.map(Node::from)?;
        node.supported_profiles = capability_profile_union(&self.pool, &node.node_id).await;
        Some(node)
    }

    async fn node_by_prefix(&self, prefix: &str) -> Option<Node> {
        // PHP RegistryController::show parity — exact id OR id-prefix (UUID 8-hex prefix or
        // custom name), AVAILABLE only, exact match preferred. The website resolves node
        // detail by 8-hex prefix, so exact-only get() would 404 those.
        let row: Option<NodeRow> = sqlx::query_as(
            r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                      available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                      tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                      exposure_mode, transport_endpoint,
                      CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                      pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, backend, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles,
                      operator_pubkey, operator_verified, operator_trust_tier, CAST(policy_manifest AS CHAR) AS policy_manifest
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

        let mut node = row.map(Node::from)?;
        node.supported_profiles = capability_profile_union(&self.pool, &node.node_id).await;
        Some(node)
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
            r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                      available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                      tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                      exposure_mode, transport_endpoint,
                      CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                      pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, sdk_language, implementation_name, implementation_version, sdk_compatibility_version, sdk_version, backend, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles, CAST(policy_manifest AS CHAR) AS policy_manifest
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
            r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                      available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                      tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                      exposure_mode, transport_endpoint,
                      CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                      pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, backend, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles, CAST(policy_manifest AS CHAR) AS policy_manifest
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
                r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                          available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                          tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                          exposure_mode, transport_endpoint,
                          CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                          pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, backend, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles, CAST(policy_manifest AS CHAR) AS policy_manifest
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
            r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                      available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                      tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                      exposure_mode, transport_endpoint,
                      CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                      pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, backend, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles, CAST(policy_manifest AS CHAR) AS policy_manifest
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
            r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                      available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                      tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                      exposure_mode, transport_endpoint,
                      CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                      pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, backend, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles, public_listing, operator_url, CAST(policy_manifest AS CHAR) AS policy_manifest
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

    async fn verify_and_rotate_liveness_challenge(
        &self,
        node_id: &str,
        response: Option<&str>,
        next_challenge: &str,
    ) -> Option<bool> {
        let mut transaction = self.pool.begin().await.ok()?;
        let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT liveness_challenge, node_hmac_key FROM nodes WHERE id = ? FOR UPDATE",
        )
        .bind(node_id)
        .fetch_optional(&mut *transaction)
        .await
        .ok()?;
        let (challenge, hmac_key) = row?;
        let verified = challenge.as_deref().is_some_and(|challenge| {
            hmac_key.as_deref().is_some_and(|key| {
                response
                    .is_some_and(|candidate| verify_liveness_response(key, challenge, candidate))
            })
        });
        let result = if verified {
            sqlx::query(
                "UPDATE nodes SET liveness_challenge = ?, liveness_verified_at = NOW() WHERE id = ?",
            )
            .bind(next_challenge)
            .bind(node_id)
            .execute(&mut *transaction)
            .await
        } else {
            sqlx::query("UPDATE nodes SET liveness_challenge = ? WHERE id = ?")
                .bind(next_challenge)
                .bind(node_id)
                .execute(&mut *transaction)
                .await
        };
        result.ok()?;
        transaction.commit().await.ok()?;
        Some(verified)
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
        const ATTEMPTS: usize = 3;
        for attempt in 0..ATTEMPTS {
            match record_credit_award_once(&self.pool, node_id, amount, task_id, nonce).await {
                Ok(balance) => return Ok(balance),
                Err(CreditMutationError::NonceReplay) => return Err(CreditError::NonceReplay),
                Err(CreditMutationError::NodeNotFound) => return Err(CreditError::NodeNotFound),
                Err(CreditMutationError::Database(error))
                    if is_transient_transaction_error(&error) && attempt + 1 < ATTEMPTS =>
                {
                    continue;
                }
                Err(CreditMutationError::Database(error)) => {
                    eprintln!("credit award transaction failed: {error}");
                    return Err(CreditError::DbError);
                }
            }
        }
        Err(CreditError::DbError)
    }

    async fn debit_for_consumer(
        &self,
        consumer_node_id: &str,
        amount: f64,
        task_id: &str,
        reason: &str,
    ) -> WalletDebitResult {
        let op: Result<Option<(Option<String>,)>, sqlx::Error> =
            sqlx::query_as("SELECT operator_pubkey FROM nodes WHERE id = ?")
                .bind(consumer_node_id)
                .fetch_optional(&self.pool)
                .await;
        let operator_pubkey = match op {
            Ok(row) => row.and_then(|(key,)| key).filter(|key| !key.is_empty()),
            Err(error) => {
                eprintln!("credit debit scope lookup failed: {error}");
                return failed_debit("node", "db_error");
            }
        };

        const ATTEMPTS: usize = 3;
        for attempt in 0..ATTEMPTS {
            let result = match operator_pubkey.as_deref() {
                Some(operator) => {
                    debit_operator_wallet_once(
                        &self.pool,
                        consumer_node_id,
                        operator,
                        amount,
                        task_id,
                        reason,
                    )
                    .await
                }
                None => {
                    debit_node_once(&self.pool, consumer_node_id, amount, task_id, reason).await
                }
            };
            match result {
                Ok(result) => return result,
                Err(DebitMutationError::Insufficient(reason)) => {
                    return failed_debit(
                        if operator_pubkey.is_some() {
                            "operator_wallet"
                        } else {
                            "node"
                        },
                        reason,
                    );
                }
                Err(DebitMutationError::Database { error, .. })
                    if is_transient_transaction_error(&error) && attempt + 1 < ATTEMPTS =>
                {
                    continue;
                }
                Err(DebitMutationError::Database { scope, error }) => {
                    eprintln!("credit debit transaction failed: {error}");
                    return failed_debit(scope, "db_error");
                }
            }
        }
        failed_debit(
            if operator_pubkey.is_some() {
                "operator_wallet"
            } else {
                "node"
            },
            "db_error",
        )
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
            const ATTEMPTS: usize = 3;
            for attempt in 0..ATTEMPTS {
                match expire_idle_credit_once(&self.pool, &node_id, balance).await {
                    Ok(Some(expired)) => {
                        expired_nodes += 1;
                        expired_credits += expired;
                        break;
                    }
                    Ok(None) => break,
                    Err(error)
                        if is_transient_transaction_error(&error) && attempt + 1 < ATTEMPTS =>
                    {
                        continue;
                    }
                    Err(error) => {
                        eprintln!("credit expiry transaction failed for {node_id}: {error}");
                        break;
                    }
                }
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

    async fn latest_conformance_run(&self) -> Option<crate::repo::ConformanceRun> {
        let latest: Option<(String, String)> = sqlx::query_as(
            "SELECT run_id, DATE_FORMAT(probed_at, '%Y-%m-%dT%H:%i:%sZ') \
             FROM iicp_telemetry_probes \
             WHERE probe_type = 'conformance' AND run_id IS NOT NULL AND run_id <> '' \
             ORDER BY probed_at DESC, id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        let (run_id, probed_at) = latest?;
        let rows: Vec<(Option<String>, bool)> = sqlx::query_as(
            "SELECT test_id, passed FROM iicp_telemetry_probes \
             WHERE probe_type = 'conformance' AND run_id = ?",
        )
        .bind(&run_id)
        .fetch_all(&self.pool)
        .await
        .ok()?;
        let mut passed = Vec::new();
        let mut failed = Vec::new();
        for (test_id, ok) in rows {
            let Some(test_id) = test_id else { continue };
            if ok {
                passed.push(test_id);
            } else {
                failed.push(test_id);
            }
        }
        passed.sort();
        passed.dedup();
        failed.sort();
        failed.dedup();
        Some(crate::repo::ConformanceRun {
            run_id,
            probed_at,
            passed,
            failed,
        })
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
                trust_tier = 'low', status = 'active', expires_at = NOW() + INTERVAL 90 DAY, \
                last_seen_at = NOW(), updated_at = NOW()",
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

    async fn set_replica_token_hash(&self, replica_id: &str, token_hash: &str) -> bool {
        sqlx::query(
            "UPDATE replicas SET replica_token_hash = ?, expires_at = NOW() + INTERVAL 90 DAY, \
             last_seen_at = NOW(), updated_at = NOW() WHERE replica_id = ?",
        )
        .bind(token_hash)
        .bind(replica_id)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() > 0)
        .unwrap_or(false)
    }

    async fn replica_token_hash(&self, replica_id: &str) -> Option<String> {
        sqlx::query_scalar("SELECT replica_token_hash FROM replicas WHERE replica_id = ?")
            .bind(replica_id)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()
    }

    async fn replica_is_active(&self, replica_id: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM replicas WHERE replica_id = ? AND status = 'active' AND expires_at > NOW()",
        )
        .bind(replica_id).fetch_one(&self.pool).await.unwrap_or(0) > 0
    }

    async fn decommission_replica(&self, replica_id: &str) -> bool {
        use sha2::{Digest, Sha256};
        let tombstone = hex::encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
        sqlx::query(
            "UPDATE replicas SET status = 'decommissioned', expires_at = NOW(), \
             replica_token_hash = ?, last_seen_at = NOW(), updated_at = NOW() WHERE replica_id = ?",
        )
        .bind(tombstone)
        .bind(replica_id)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() > 0)
        .unwrap_or(false)
    }

    async fn decommission_replica_with_event(
        &self,
        replica_id: &str,
        did: &str,
        secret_key_hex: &str,
    ) -> bool {
        let Ok(mut tx) = self.pool.begin().await else {
            return false;
        };
        let active = sqlx::query_as::<_, (String, i8)>(
            "SELECT status, expires_at > NOW() FROM replicas WHERE replica_id = ? FOR UPDATE",
        )
        .bind(replica_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .is_some_and(|(status, unexpired)| status == "active" && unexpired == 1);
        if !active {
            let _ = tx.rollback().await;
            return false;
        }
        let Ok((last_seq, prev_sig)) = sqlx::query_as::<_, (i64, Option<String>)>(
            "SELECT CAST(last_seq AS SIGNED), last_signature FROM node_event_chain_heads WHERE chain_id = 'genesis' FOR UPDATE",
        ).fetch_one(&mut *tx).await else { let _ = tx.rollback().await; return false };
        let seq = last_seq + 1;
        let prev_hash = crate::federation::prev_hash_from(prev_sig.as_deref());
        let event_id = uuid::Uuid::new_v4().to_string();
        let ts_ms = chrono::Utc::now().timestamp_millis();
        let payload = serde_json::json!({"did": did});
        let sig = crate::federation::sign_event(
            secret_key_hex,
            &event_id,
            "REPLICA_DEREGISTERED",
            seq,
            ts_ms,
            &payload,
            &prev_hash,
        );
        use sha2::{Digest, Sha256};
        let tombstone = hex::encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
        let writes = sqlx::query(
            "UPDATE replicas SET status='decommissioned', expires_at=NOW(), replica_token_hash=?, last_seen_at=NOW(), updated_at=NOW() WHERE replica_id=?",
        ).bind(tombstone).bind(replica_id).execute(&mut *tx).await.is_ok()
            && sqlx::query(
                "INSERT INTO node_events (event_id,seq,event_type,node_id,ts_ms,payload,prev_hash,signature) VALUES (?,?,?,?,?,?,?,?)",
            ).bind(&event_id).bind(seq).bind("REPLICA_DEREGISTERED").bind(replica_id)
                .bind(ts_ms).bind(payload.to_string()).bind(&prev_hash).bind(&sig)
                .execute(&mut *tx).await.is_ok()
            && sqlx::query(
                "UPDATE node_event_chain_heads SET last_seq=?, last_signature=?, updated_at=NOW() WHERE chain_id='genesis'",
            ).bind(seq).bind(&sig).execute(&mut *tx).await.is_ok();
        if writes {
            tx.commit().await.is_ok()
        } else {
            let _ = tx.rollback().await;
            false
        }
    }

    async fn all_replicas(&self) -> Vec<(String, String, String, String, i64)> {
        // UNIX_TIMESTAMP returns NULL when created_at is NULL; fall back to 0.
        sqlx::query_as(
            "SELECT replica_id, did, endpoint, trust_tier, \
             CAST(COALESCE(UNIX_TIMESTAMP(created_at) * 1000, 0) AS SIGNED) \
             FROM replicas WHERE status = 'active' AND expires_at > NOW()",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default()
    }

    async fn replica_id_by_did(&self, did: &str) -> Option<String> {
        sqlx::query_scalar("SELECT replica_id FROM replicas WHERE did = ?")
            .bind(did)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()
    }

    async fn append_signed_event(
        &self,
        secret_key_hex: &str,
        event_type: &str,
        node_id: &str,
        payload: &serde_json::Value,
    ) -> Option<i64> {
        const ATTEMPTS: usize = 3;

        for attempt in 0..ATTEMPTS {
            let mut tx = match self.pool.begin().await {
                Ok(tx) => tx,
                Err(error) => {
                    eprintln!("signed event: transaction start failed: {error}");
                    return None;
                }
            };

            // The durable head survives event retention and serializes sequence/signature
            // allocation across all writers. This is the same invariant as PHP
            // NodeEventLogger; an absent row is a schema error, never a MAX(seq) fallback.
            let head: Result<(i64, Option<String>), sqlx::Error> = sqlx::query_as(
                "SELECT CAST(last_seq AS SIGNED), last_signature \
                 FROM node_event_chain_heads WHERE chain_id = 'genesis' FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await;
            let (last_seq, prev_sig) = match head {
                Ok(head) => head,
                Err(error) => {
                    let _ = tx.rollback().await;
                    eprintln!("signed event: chain head unavailable: {error}");
                    return None;
                }
            };

            let seq = last_seq + 1;
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

            let inserted = sqlx::query(
                "INSERT INTO node_events \
                 (event_id, seq, event_type, node_id, ts_ms, payload, prev_hash, signature) \
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
            .execute(&mut *tx)
            .await;
            if let Err(error) = inserted {
                let retry = is_transient_transaction_error(&error) && attempt + 1 < ATTEMPTS;
                let _ = tx.rollback().await;
                if retry {
                    continue;
                }
                eprintln!("signed event: append failed: {error}");
                return None;
            }

            let advanced = sqlx::query(
                "UPDATE node_event_chain_heads \
                 SET last_seq = ?, last_signature = ?, updated_at = NOW() \
                 WHERE chain_id = 'genesis'",
            )
            .bind(seq)
            .bind(&sig)
            .execute(&mut *tx)
            .await;
            if let Err(error) = advanced {
                let retry = is_transient_transaction_error(&error) && attempt + 1 < ATTEMPTS;
                let _ = tx.rollback().await;
                if retry {
                    continue;
                }
                eprintln!("signed event: chain-head update failed: {error}");
                return None;
            }

            match tx.commit().await {
                Ok(()) => return Some(seq),
                Err(error) if is_transient_transaction_error(&error) && attempt + 1 < ATTEMPTS => {
                    continue;
                }
                Err(error) => {
                    eprintln!("signed event: commit failed: {error}");
                    return None;
                }
            }
        }

        None
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
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| OperatorLifecycleError::Storage)?;
        let old: Option<(Option<String>, Option<String>, Option<String>, Option<i64>, Option<i64>, Option<String>, Option<String>, Option<String>, Option<u32>)> = sqlx::query_as(
            "SELECT display_name, attested_created_at, operator_integrity_hash, first_seen_ms, ordinal, tier, badge, provenance, rotation_epoch \
             FROM operators WHERE operator_pubkey = ? AND identity_status = 'active' FOR UPDATE",
        )
        .bind(old_operator_pubkey)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| OperatorLifecycleError::Storage)?;
        let Some((
            display_name,
            attested_created_at,
            integrity_hash,
            first_seen_ms,
            ordinal,
            tier,
            badge,
            provenance,
            prior_epoch,
        )) = old
        else {
            let exists: Option<(i64,)> =
                sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
                    .bind(old_operator_pubkey)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| OperatorLifecycleError::Storage)?;
            return Err(if exists.is_some() {
                OperatorLifecycleError::Inactive
            } else {
                OperatorLifecycleError::Unknown
            });
        };
        let successor_exists: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
                .bind(new_operator_pubkey)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| OperatorLifecycleError::Storage)?;
        if successor_exists.is_some() {
            return Err(OperatorLifecycleError::SuccessorExists);
        }
        let epoch = prior_epoch
            .unwrap_or(0)
            .saturating_add(1)
            .max(requested_epoch.unwrap_or(0));
        sqlx::query(
            "INSERT INTO operators (operator_pubkey, identity_status, display_name, attested_created_at, operator_integrity_hash, first_seen_ms, ordinal, tier, badge, provenance, created_at, updated_at) \
             VALUES (?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
        )
        .bind(new_operator_pubkey).bind(display_name).bind(attested_created_at).bind(integrity_hash)
        .bind(first_seen_ms).bind(ordinal).bind(tier).bind(badge).bind(provenance)
        .execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        let linked = sqlx::query("UPDATE nodes SET operator_pubkey = ?, operator_verified = 1, policy_manifest = NULL, updated_at = NOW() WHERE operator_pubkey = ?")
            .bind(new_operator_pubkey).bind(old_operator_pubkey).execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?.rows_affected() as u32;
        use ct_codecs::{Base64, Decoder};
        let successor_raw = Base64::decode_to_vec(new_operator_pubkey, None)
            .map_err(|_| OperatorLifecycleError::Invalid)?;
        if successor_raw.len() != 32 {
            return Err(OperatorLifecycleError::Invalid);
        }
        let successor_hash = hex::encode(sha2::Sha256::digest(successor_raw));
        let predecessor_raw = Base64::decode_to_vec(old_operator_pubkey, None)
            .map_err(|_| OperatorLifecycleError::Invalid)?;
        if predecessor_raw.len() != 32 {
            return Err(OperatorLifecycleError::Invalid);
        }
        let predecessor_hash = hex::encode(sha2::Sha256::digest(predecessor_raw));
        sqlx::query(
            "INSERT INTO policy_key_lifecycle_records (policy_key_sha256, status, rotation_epoch, revocation_reason_class, superseded_by_policy_key_sha256, created_at, updated_at) \
             VALUES (?, 'superseded', ?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE status = 'superseded', rotation_epoch = VALUES(rotation_epoch), revocation_reason_class = VALUES(revocation_reason_class), superseded_by_policy_key_sha256 = VALUES(superseded_by_policy_key_sha256), updated_at = NOW()",
        )
        .bind(predecessor_hash).bind(epoch).bind(reason_class).bind(&successor_hash)
        .execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        sqlx::query(
            "UPDATE operators SET identity_status = 'rotated', successor_operator_pubkey_sha256 = ?, rotation_epoch = ?, identity_reason_class = ?, updated_at = NOW() WHERE operator_pubkey = ?",
        )
        .bind(successor_hash).bind(epoch).bind(reason_class).bind(old_operator_pubkey)
        .execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        tx.commit()
            .await
            .map_err(|_| OperatorLifecycleError::Storage)?;
        Ok(OperatorLifecycleResult {
            linked_nodes: linked,
            rotation_epoch: Some(epoch),
            revoked_at_unix: None,
        })
    }

    async fn revoke_operator_identity(
        &self,
        operator_pubkey: &str,
        reason_class: &str,
    ) -> Result<OperatorLifecycleResult, OperatorLifecycleError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| OperatorLifecycleError::Storage)?;
        let active: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? AND identity_status = 'active' FOR UPDATE")
            .bind(operator_pubkey).fetch_optional(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        if active.is_none() {
            let exists: Option<(i64,)> =
                sqlx::query_as("SELECT 1 FROM operators WHERE operator_pubkey = ? LIMIT 1")
                    .bind(operator_pubkey)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|_| OperatorLifecycleError::Storage)?;
            return Err(if exists.is_some() {
                OperatorLifecycleError::Inactive
            } else {
                OperatorLifecycleError::Unknown
            });
        }
        let linked = sqlx::query("UPDATE nodes SET operator_verified = 0, operator_trust_tier = NULL, policy_manifest = NULL, updated_at = NOW() WHERE operator_pubkey = ?")
            .bind(operator_pubkey).execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?.rows_affected() as u32;
        use ct_codecs::{Base64, Decoder};
        let policy_raw = Base64::decode_to_vec(operator_pubkey, None)
            .map_err(|_| OperatorLifecycleError::Invalid)?;
        if policy_raw.len() != 32 {
            return Err(OperatorLifecycleError::Invalid);
        }
        let policy_hash = hex::encode(sha2::Sha256::digest(policy_raw));
        sqlx::query(
            "INSERT INTO policy_key_lifecycle_records (policy_key_sha256, status, revoked_at, revocation_reason_class, created_at, updated_at) \
             VALUES (?, 'revoked', NOW(), ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE status = 'revoked', revoked_at = NOW(), revocation_reason_class = VALUES(revocation_reason_class), updated_at = NOW()",
        )
        .bind(policy_hash).bind(reason_class).execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        sqlx::query("UPDATE operators SET identity_status = 'revoked', identity_revoked_at = NOW(), identity_reason_class = ?, updated_at = NOW() WHERE operator_pubkey = ?")
            .bind(reason_class).bind(operator_pubkey).execute(&mut *tx).await.map_err(|_| OperatorLifecycleError::Storage)?;
        tx.commit()
            .await
            .map_err(|_| OperatorLifecycleError::Storage)?;
        Ok(OperatorLifecycleResult {
            linked_nodes: linked,
            rotation_epoch: None,
            revoked_at_unix: Some(chrono::Utc::now().timestamp()),
        })
    }

    async fn accept_operator_governance(
        &self,
        operator_pubkey: &str,
        terms_version: &str,
        dpa_version: &str,
        nonce_sha256: &str,
    ) -> Result<String, OperatorSelfServiceError> {
        let result = sqlx::query(
            "UPDATE operators SET terms_version = ?, terms_accepted_at = NOW(), \
             dpa_version = ?, dpa_accepted_at = NOW(), acceptance_method = \
             'operator_key_challenge', acceptance_nonce_sha256 = ?, updated_at = NOW() \
             WHERE operator_pubkey = ? AND identity_status = 'active'",
        )
        .bind(terms_version)
        .bind(dpa_version)
        .bind(nonce_sha256)
        .bind(operator_pubkey)
        .execute(&self.pool)
        .await
        .map_err(|_| OperatorSelfServiceError::Storage)?;
        if result.rows_affected() == 0 {
            return match self.operator_identity_active(operator_pubkey).await {
                None => Err(OperatorSelfServiceError::Unknown),
                Some(false) => Err(OperatorSelfServiceError::Inactive),
                Some(true) => Err(OperatorSelfServiceError::Storage),
            };
        }
        let accepted_at: Option<String> = sqlx::query_scalar(
            "SELECT CAST(terms_accepted_at AS CHAR) FROM operators WHERE operator_pubkey = ?",
        )
        .bind(operator_pubkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| OperatorSelfServiceError::Storage)?;
        accepted_at.ok_or(OperatorSelfServiceError::Storage)
    }

    async fn operator_dsr(
        &self,
        operator_pubkey: &str,
        action: &str,
        tracking_id: &str,
    ) -> Result<serde_json::Value, OperatorSelfServiceError> {
        mysql_operator_dsr(&self.pool, operator_pubkey, action, tracking_id).await
    }

    async fn record_dispatch_usage(&self, mode: &str) {
        if !matches!(
            mode,
            "public_view" | "legacy_dispatch" | "ticketed_dispatch"
        ) {
            return;
        }
        let _ = sqlx::query(
            "INSERT INTO dispatch_usage_daily (usage_date, mode, request_count, created_at, updated_at) \
             VALUES (UTC_DATE(), ?, 1, NOW(), NOW()) ON DUPLICATE KEY UPDATE \
             request_count = request_count + 1, updated_at = NOW()",
        )
        .bind(mode)
        .execute(&self.pool)
        .await;
    }

    async fn dispatch_usage_summary(&self, days: u32) -> serde_json::Value {
        let days = days.clamp(1, 30);
        let rows: Vec<(String, u64)> = sqlx::query_as(
            "SELECT mode, CAST(SUM(request_count) AS UNSIGNED) FROM dispatch_usage_daily \
             WHERE usage_date >= UTC_DATE() - INTERVAL ? DAY GROUP BY mode",
        )
        .bind(days.saturating_sub(1))
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        let count = |mode: &str| {
            rows.iter()
                .find(|(candidate, _)| candidate == mode)
                .map(|(_, value)| *value)
                .unwrap_or(0)
        };
        crate::repo::dispatch_usage_summary_value(
            days,
            count("ticketed_dispatch"),
            count("legacy_dispatch"),
            count("public_view"),
        )
    }

    async fn policy_key_lifecycle_status(&self, policy_key_sha256: &str) -> Option<String> {
        sqlx::query_scalar(
            "SELECT status FROM policy_key_lifecycle_records WHERE policy_key_sha256 = ? LIMIT 1",
        )
        .bind(policy_key_sha256)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
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
            r#"SELECT id, endpoint, region, CAST(reputation_score AS DOUBLE) AS reputation_score,
                      available, CAST(`load` AS DOUBLE) AS `load`, active_jobs, max_concurrent,
                      tasks_total, CAST(avg_latency_ms AS DOUBLE) AS avg_latency_ms,
                      exposure_mode, transport_endpoint,
                      CAST(credit_cost_multiplier AS DOUBLE) AS credit_cost_multiplier,
                      pricing_model, attested, tasks_failed,
                      public_reachable, relay_capable, CAST(supported_receipt_profiles AS CHAR) AS supported_receipt_profiles, CAST(policy_manifest AS CHAR) AS policy_manifest
               FROM nodes"#,
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        let caps: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT node_id, intent, CAST(supported_profiles AS CHAR) FROM capabilities",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();
        let mut intents: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut capability_profiles = std::collections::HashMap::new();
        for (nid, intent, profiles) in caps {
            intents.entry(nid.clone()).or_default().push(intent.clone());
            let parsed = profiles
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_default();
            capability_profiles.insert((nid, intent), parsed);
        }
        rows.into_iter()
            .map(|r| {
                let node = Node::from(r);
                let node_intents = intents.get(&node.node_id).cloned().unwrap_or_default();
                let node_profiles = node_intents
                    .iter()
                    .map(|intent| {
                        (
                            intent.clone(),
                            capability_profiles
                                .get(&(node.node_id.clone(), intent.clone()))
                                .cloned()
                                .unwrap_or_default(),
                        )
                    })
                    .collect();
                NodeRecord {
                    node,
                    intents: node_intents,
                    capability_profiles: node_profiles,
                    availability: vec![],
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
        // Read exactly one newest value per metric. Historical aggregates remain
        // available for evidence/retention, but they must never be hydrated into
        // application memory. MAX(id) makes equal computed_at timestamps
        // deterministic and matches the bounded PHP 1.10.90 query.
        let rows: Vec<(String, Option<f64>)> = sqlx::query_as(
            "SELECT t1.metric, t1.value \
             FROM iicp_telemetry_aggregates t1 \
             WHERE t1.id IN ( \
                 SELECT MAX(candidate.id) \
                 FROM iicp_telemetry_aggregates candidate \
                 INNER JOIN ( \
                     SELECT metric, MAX(computed_at) AS latest_at \
                     FROM iicp_telemetry_aggregates \
                     WHERE `window` = '24h' \
                     GROUP BY metric \
                 ) latest ON latest.metric = candidate.metric \
                         AND latest.latest_at = candidate.computed_at \
                 WHERE candidate.`window` = '24h' \
                 GROUP BY candidate.metric \
             )",
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
        let Ok(mut tx) = self.pool.begin().await else {
            return 0.0;
        };

        // Materialize both gate rows before locking them.  This closes the
        // absent-row race where two first allocations from the same source IP
        // could both pass independent SELECT checks.
        if sqlx::query(
            "INSERT INTO credits (node_id, balance, free_credit_last_allocation_at, created_at, updated_at) \
             VALUES (?, 0, NULL, NOW(), NOW()) \
             ON DUPLICATE KEY UPDATE node_id = VALUES(node_id)",
        )
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .is_err()
        {
            return 0.0;
        }
        if sqlx::query(
            "INSERT INTO credit_ip_gates (ip_address, last_allocation_at, allocation_count, created_at, updated_at) \
             VALUES (?, NULL, 0, NOW(), NOW()) \
             ON DUPLICATE KEY UPDATE ip_address = VALUES(ip_address)",
        )
        .bind(ip)
        .execute(&mut *tx)
        .await
        .is_err()
        {
            return 0.0;
        }

        let credit_gate: Option<(f64, i64)> = sqlx::query_as(
            "SELECT CAST(balance AS DOUBLE), \
                    IF(free_credit_last_allocation_at IS NOT NULL AND \
                       free_credit_last_allocation_at > NOW() - INTERVAL 6 HOUR, 1, 0) \
             FROM credits WHERE node_id = ? FOR UPDATE",
        )
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        let ip_blocked: Option<(i64,)> = sqlx::query_as(
            "SELECT IF(last_allocation_at IS NOT NULL AND \
                       last_allocation_at > NOW() - INTERVAL 6 HOUR, 1, 0) \
             FROM credit_ip_gates WHERE ip_address = ? FOR UPDATE",
        )
        .bind(ip)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        let Some((balance, node_blocked)) = credit_gate else {
            return 0.0;
        };
        if balance > 0.0 || node_blocked != 0 || ip_blocked.map(|v| v.0 != 0).unwrap_or(true) {
            return 0.0;
        }

        let new_balance = balance + FREE_AMOUNT;
        let writes_ok = sqlx::query(
            "UPDATE credits SET balance = ?, free_credit_last_allocation_at = NOW(), updated_at = NOW() \
             WHERE node_id = ?",
        )
        .bind(new_balance)
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .is_ok()
            && sqlx::query(
                "INSERT INTO credit_transactions \
                 (node_id, amount, type, reason, expires_at, created_at, updated_at) \
                 VALUES (?, ?, 'credit', 'free_allocation', NOW() + INTERVAL 90 DAY, NOW(), NOW())",
            )
            .bind(node_id)
            .bind(FREE_AMOUNT)
            .execute(&mut *tx)
            .await
            .is_ok()
            && sqlx::query(
                "UPDATE nodes SET credit_balance = ?, free_credit_last_allocation_at = NOW() WHERE id = ?",
            )
            .bind(new_balance)
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .map(|r| r.rows_affected() == 1)
            .unwrap_or(false)
            && sqlx::query(
                "UPDATE credit_ip_gates SET last_allocation_at = NOW(), \
                 allocation_count = allocation_count + 1, updated_at = NOW() WHERE ip_address = ?",
            )
            .bind(ip)
            .execute(&mut *tx)
            .await
            .is_ok();

        if writes_ok && tx.commit().await.is_ok() {
            FREE_AMOUNT
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{credit_ttl_idle, init_pool, median_outlier_weight, MySqlRepo};
    use crate::repo::NodeRepository;
    use serde_json::Value;
    use sqlx::mysql::MySqlPoolOptions;
    use std::sync::Arc;
    use std::time::Duration;

    fn s(vals: &[f64]) -> Vec<(f64,)> {
        vals.iter().map(|&v| (v,)).collect()
    }

    fn reputation_hourly_velocity_fixture() -> Value {
        serde_json::from_str(include_str!("../parity/reputation-hourly-velocity-v0.json"))
            .expect("shared RT-01b fixture must be valid JSON")
    }

    fn fixture_f64(fixture: &Value, path: &[&str]) -> f64 {
        let mut value = fixture;
        for key in path {
            value = &value[*key];
        }
        value.as_f64().expect("fixture numeric field")
    }

    fn fixture_i64(fixture: &Value, path: &[&str]) -> i64 {
        let mut value = fixture;
        for key in path {
            value = &value[*key];
        }
        value.as_i64().expect("fixture integer field")
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

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn aggregate_lookup_is_bounded_and_deterministic_for_timestamp_ties() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        sqlx::query(
            "DELETE FROM iicp_telemetry_aggregates \
             WHERE metric IN ('discover_p50_ms', 'discover_p95_ms')",
        )
        .execute(&pool)
        .await
        .expect("clear fixture rows");
        for (metric, value, computed_at) in [
            ("discover_p50_ms", 5.0, "2026-08-12 09:59:59"),
            ("discover_p50_ms", 10.0, "2026-08-12 10:00:00"),
            ("discover_p50_ms", 20.0, "2026-08-12 10:00:00"),
            ("discover_p95_ms", 95.0, "2026-08-12 10:00:00"),
        ] {
            sqlx::query(
                "INSERT INTO iicp_telemetry_aggregates \
                 (`window`, metric, value, sample_count, computed_at) \
                 VALUES ('24h', ?, ?, 1, ?)",
            )
            .bind(metric)
            .bind(value)
            .bind(computed_at)
            .execute(&pool)
            .await
            .expect("insert aggregate fixture");
        }
        let aggregate = MySqlRepo::new(pool).probe_aggregate_24h().await;
        assert_eq!(aggregate.discover_p50_ms, Some(20.0));
        assert_eq!(aggregate.discover_p95_ms, Some(95.0));
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn replica_lifecycle_revokes_and_reactivates_stable_identity() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        let repo = MySqlRepo::new(pool);
        let id = uuid::Uuid::new_v4().to_string();
        let did = format!("did:web:{}.example", uuid::Uuid::new_v4());
        assert!(
            repo.upsert_replica(&id, &did, "https://shadow.example", "low")
                .await
        );
        assert!(repo.set_replica_token_hash(&id, &"a".repeat(64)).await);
        assert!(repo.replica_is_active(&id).await);
        let public_key = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let signing_key = format!("{}{}", "11".repeat(32), public_key);
        assert!(
            repo.decommission_replica_with_event(&id, &did, &signing_key)
                .await
        );
        assert!(!repo.replica_is_active(&id).await);
        assert!(repo.all_replicas().await.iter().all(|row| row.0 != id));
        assert_eq!(
            repo.replica_id_by_did(&did).await.as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            repo.events_since(0, 100)
                .await
                .iter()
                .filter(|event| event.event_type == "REPLICA_DEREGISTERED" && event.node_id == id)
                .count(),
            1
        );
        assert!(
            repo.upsert_replica(&id, &did, "https://new-shadow.example", "low")
                .await
        );
        assert!(repo.replica_is_active(&id).await);
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn concurrent_signed_event_appends_are_gap_free_and_chain_correct() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        let repo = Arc::new(MySqlRepo::new(pool.clone()));
        let public_key = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let secret_key = format!("{}{}", "11".repeat(32), public_key);

        let mut tasks = Vec::new();
        for ordinal in 0..40 {
            let repo = Arc::clone(&repo);
            let secret_key = secret_key.clone();
            tasks.push(tokio::spawn(async move {
                repo.append_signed_event(
                    &secret_key,
                    "REGISTER",
                    "concurrency-fixture",
                    &serde_json::json!({"ordinal": ordinal}),
                )
                .await
                .expect("append must succeed")
            }));
        }
        let mut assigned = Vec::new();
        for task in tasks {
            assigned.push(task.await.expect("append task must join"));
        }
        assigned.sort_unstable();
        assert_eq!(assigned, (1_i64..=40).collect::<Vec<_>>());

        let events = repo.events_since(0, 100).await;
        assert_eq!(events.len(), 40);
        let mut expected_prev = crate::federation::GENESIS_ROOT.to_string();
        for (offset, event) in events.iter().enumerate() {
            assert_eq!(event.seq, offset as i64 + 1);
            assert_eq!(event.prev_hash.as_deref(), Some(expected_prev.as_str()));
            let signature = event.sig.as_deref().expect("event must be signed");
            let message = crate::federation::event_message(
                &event.event_id,
                &event.event_type,
                event.seq,
                event.ts_ms,
                &event.payload,
                &expected_prev,
            );
            assert!(crate::federation::verify_event(
                public_key, signature, &message
            ));
            expected_prev = crate::federation::prev_hash_from(Some(signature));
        }

        let head: (i64, Option<String>) = sqlx::query_as(
            "SELECT CAST(last_seq AS SIGNED), last_signature \
             FROM node_event_chain_heads WHERE chain_id = 'genesis'",
        )
        .fetch_one(&pool)
        .await
        .expect("read chain head");
        assert_eq!(head.0, 40);
        assert_eq!(
            head.1.as_deref(),
            events.last().and_then(|event| event.sig.as_deref())
        );
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn concurrent_heartbeats_share_one_persisted_reputation_budget() {
        let fixture = reputation_hourly_velocity_fixture();
        let initial_reputation = fixture_f64(&fixture, &["inputs", "initial_reputation"]);
        let positive_delta = fixture_f64(&fixture, &["inputs", "positive_delta_per_heartbeat"]);
        let workers = fixture_i64(&fixture, &["inputs", "workers"]);
        let tasks_success_per_worker = u32::try_from(fixture_i64(
            &fixture,
            &["inputs", "tasks_success_per_worker"],
        ))
        .expect("fixture tasks_success_per_worker fits u32");
        let expected_concurrent_score = fixture_f64(&fixture, &["expected", "concurrent_score"]);
        let expected_concurrent_gain =
            fixture_f64(&fixture, &["expected", "concurrent_hourly_gain"]);
        let expected_tasks_total = fixture_i64(&fixture, &["expected", "concurrent_tasks_total"]);
        let same_window_age = fixture_i64(&fixture, &["expected", "same_window_age_seconds"]);
        let same_window_score = fixture_f64(&fixture, &["expected", "same_window_score"]);
        let next_window_age = fixture_i64(&fixture, &["expected", "next_window_age_seconds"]);
        let next_window_score = fixture_f64(
            &fixture,
            &["expected", "next_window_score_after_first_positive"],
        );
        let next_window_gain = fixture_f64(
            &fixture,
            &["expected", "next_window_hourly_gain_after_first_positive"],
        );
        let negative_delta = fixture_f64(&fixture, &["inputs", "negative_delta_after_reload"]);
        let final_score = fixture_f64(
            &fixture,
            &["expected", "final_score_after_reload_and_negative"],
        );
        let final_gain = fixture_f64(&fixture, &["expected", "final_hourly_gain"]);
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        sqlx::query(
            "INSERT INTO nodes \
             (id, endpoint, region, node_token_hash, max_concurrent, tokens_per_min, \
              reputation_score, rep_hourly_gain) \
             VALUES ('reputation-concurrency', 'https://example.invalid/v1', 'test', 'x', 1, 1, ?, 0)",
        )
        .bind(initial_reputation)
        .execute(&pool)
        .await
        .expect("seed node");

        let repo = Arc::new(MySqlRepo::new(pool.clone()));
        let mut tasks = Vec::new();
        for _ in 0..workers {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                repo.heartbeat(
                    "reputation-concurrency",
                    0.1,
                    true,
                    0,
                    tasks_success_per_worker,
                    0,
                    positive_delta,
                    None,
                )
                .await
                .expect("heartbeat must persist")
            }));
        }
        for task in tasks {
            task.await.expect("heartbeat task must join");
        }

        let (score, gain, tasks_total): (f64, f64, i64) = sqlx::query_as(
            "SELECT CAST(reputation_score AS DOUBLE), CAST(rep_hourly_gain AS DOUBLE), \
                    CAST(tasks_total AS SIGNED) FROM nodes WHERE id = 'reputation-concurrency'",
        )
        .fetch_one(&pool)
        .await
        .expect("read reputation state");
        assert!((score - expected_concurrent_score).abs() < 0.0001);
        assert!((gain - expected_concurrent_gain).abs() < 0.0001);
        assert_eq!(tasks_total, expected_tasks_total);

        // 3599 seconds remains in the same saturated window.
        sqlx::query(
            "UPDATE nodes SET rep_hourly_window_start = NOW() - INTERVAL ? SECOND \
             WHERE id = 'reputation-concurrency'",
        )
        .bind(same_window_age)
        .execute(&pool)
        .await
        .expect("set in-window boundary");
        repo.heartbeat(
            "reputation-concurrency",
            0.1,
            true,
            0,
            0,
            0,
            positive_delta,
            None,
        )
        .await
        .expect("in-window heartbeat");
        let score: f64 = sqlx::query_scalar(
            "SELECT CAST(reputation_score AS DOUBLE) FROM nodes WHERE id = 'reputation-concurrency'",
        )
        .fetch_one(&pool)
        .await
        .expect("read in-window score");
        assert!((score - same_window_score).abs() < 0.0001);

        // Exactly 3600 seconds starts a new window. A new repository instance
        // then proves that the persisted budget survives process-level reload.
        sqlx::query(
            "UPDATE nodes SET rep_hourly_window_start = NOW() - INTERVAL ? SECOND \
             WHERE id = 'reputation-concurrency'",
        )
        .bind(next_window_age)
        .execute(&pool)
        .await
        .expect("set expired boundary");
        repo.heartbeat(
            "reputation-concurrency",
            0.1,
            true,
            0,
            0,
            0,
            positive_delta,
            None,
        )
        .await
        .expect("new-window heartbeat");
        let (next_window_observed_score, next_window_observed_gain): (f64, f64) = sqlx::query_as(
            "SELECT CAST(reputation_score AS DOUBLE), CAST(rep_hourly_gain AS DOUBLE) FROM nodes WHERE id = 'reputation-concurrency'",
        )
        .fetch_one(&pool)
        .await
        .expect("read new-window state");
        assert!((next_window_observed_score - next_window_score).abs() < 0.0001);
        assert!((next_window_observed_gain - next_window_gain).abs() < 0.0001);

        let restarted = MySqlRepo::new(pool.clone());
        restarted
            .heartbeat(
                "reputation-concurrency",
                0.1,
                true,
                0,
                0,
                0,
                positive_delta,
                None,
            )
            .await
            .expect("reloaded heartbeat");
        restarted
            .heartbeat(
                "reputation-concurrency",
                0.1,
                true,
                0,
                0,
                1,
                negative_delta,
                None,
            )
            .await
            .expect("negative heartbeat");

        let (score, gain): (f64, f64) = sqlx::query_as(
            "SELECT CAST(reputation_score AS DOUBLE), CAST(rep_hourly_gain AS DOUBLE) \
             FROM nodes WHERE id = 'reputation-concurrency'",
        )
        .fetch_one(&pool)
        .await
        .expect("read final reputation state");
        assert!((score - final_score).abs() < 0.0001);
        assert!((gain - final_gain).abs() < 0.0001);
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn identical_saturated_heartbeats_are_persisted_noops_not_unknown_nodes() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        // One connection keeps MySQL's session timestamp fixed for both calls,
        // forcing the exact same `NOW()` value that triggered the regression.
        let pool = MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        sqlx::query(
            "INSERT INTO nodes \
             (id, endpoint, region, node_token_hash, max_concurrent, tokens_per_min, \
              reputation_score, rep_hourly_gain, rep_hourly_window_start, status, last_seen) \
             VALUES ('heartbeat-noop', 'https://example.invalid/v1', 'test', 'x', 1, 1, \
                     0.70, 0.20, NOW(), 'active', NOW())",
        )
        .execute(&pool)
        .await
        .expect("seed saturated node");
        sqlx::query("SET timestamp = UNIX_TIMESTAMP()")
            .execute(&pool)
            .await
            .expect("freeze MySQL session timestamp");

        let repo = MySqlRepo::new(pool.clone());
        for _ in 0..2 {
            let result = repo
                .heartbeat("heartbeat-noop", 0.0, true, 0, 0, 0, 0.0, None)
                .await;
            // MySQL stores `FLOAT` as IEEE-754 single precision, so a persisted
            // 0.70 is read back as its f32 representation rather than the exact
            // f64 literal. This is a no-op-state assertion, not an exact binary
            // representation assertion.
            assert!(
                result.is_some_and(|score| (score - 0.70).abs() < 0.0001),
                "saturated heartbeat must preserve the stored reputation score: {result:?}"
            );
        }
        let score: f64 = sqlx::query_scalar(
            "SELECT CAST(reputation_score AS DOUBLE) FROM nodes WHERE id = 'heartbeat-noop'",
        )
        .fetch_one(&pool)
        .await
        .expect("read persisted no-op node");
        assert!((score - 0.70).abs() < 0.0001);
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn concurrent_credit_awards_preserve_dual_write_and_ledger_total() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        sqlx::query(
            "INSERT INTO nodes \
             (id, endpoint, region, node_token_hash, max_concurrent, tokens_per_min) \
             VALUES ('credit-concurrency', 'https://example.invalid/v1', 'test', 'x', 1, 1)",
        )
        .execute(&pool)
        .await
        .expect("seed node");
        let repo = Arc::new(MySqlRepo::new(pool.clone()));

        let mut tasks = Vec::new();
        for ordinal in 0..40 {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                repo.record_credit_award(
                    "credit-concurrency",
                    0.25,
                    &format!("task-{ordinal}"),
                    &format!("nonce-{ordinal}"),
                )
                .await
                .expect("award must succeed")
            }));
        }
        for task in tasks {
            task.await.expect("award task must join");
        }

        let (node_balance, ledger_balance, transaction_total, transaction_count): (
            f64,
            f64,
            f64,
            i64,
        ) = sqlx::query_as(
            "SELECT CAST(n.credit_balance AS DOUBLE), CAST(c.balance AS DOUBLE), \
                        CAST(SUM(t.amount) AS DOUBLE), COUNT(*) \
                 FROM nodes n JOIN credits c ON c.node_id = n.id \
                 JOIN credit_transactions t ON t.node_id = n.id AND t.type = 'credit' \
                 WHERE n.id = 'credit-concurrency' GROUP BY n.id, n.credit_balance, c.balance",
        )
        .fetch_one(&pool)
        .await
        .expect("read reconciled ledger");
        assert_eq!(transaction_count, 40);
        assert!((transaction_total - 10.0).abs() < 0.0001);
        assert!((node_balance - 10.0).abs() < 0.0001);
        assert!((ledger_balance - 10.0).abs() < 0.0001);
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn concurrent_node_debits_never_double_spend_or_drift() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        sqlx::query(
            "INSERT INTO nodes \
             (id, endpoint, region, node_token_hash, max_concurrent, tokens_per_min, credit_balance) \
             VALUES ('debit-concurrency', 'https://example.invalid/v1', 'test', 'x', 1, 1, 10)",
        )
        .execute(&pool)
        .await
        .expect("seed node");
        sqlx::query(
            "INSERT INTO credits (node_id, balance, created_at, updated_at) \
             VALUES ('debit-concurrency', 10, NOW(), NOW())",
        )
        .execute(&pool)
        .await
        .expect("seed credit balance");
        let repo = Arc::new(MySqlRepo::new(pool.clone()));

        let mut tasks = Vec::new();
        for ordinal in 0..20 {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                repo.debit_for_consumer(
                    "debit-concurrency",
                    1.0,
                    &format!("task-{ordinal}"),
                    "concurrency-test",
                )
                .await
            }));
        }
        let mut successes = 0;
        for task in tasks {
            successes += u32::from(task.await.expect("debit task must join").debited);
        }
        assert_eq!(successes, 10);

        let (node_balance, ledger_balance, debit_total, debit_count): (f64, f64, f64, i64) =
            sqlx::query_as(
                "SELECT CAST(n.credit_balance AS DOUBLE), CAST(c.balance AS DOUBLE), \
                        CAST(SUM(t.amount) AS DOUBLE), COUNT(*) \
                 FROM nodes n JOIN credits c ON c.node_id = n.id \
                 JOIN credit_transactions t ON t.node_id = n.id AND t.type = 'debit' \
                 WHERE n.id = 'debit-concurrency' GROUP BY n.id, n.credit_balance, c.balance",
            )
            .fetch_one(&pool)
            .await
            .expect("read reconciled ledger");
        assert_eq!(debit_count, 10);
        assert!((debit_total - 10.0).abs() < 0.0001);
        assert!(node_balance.abs() < 0.0001);
        assert!(ledger_balance.abs() < 0.0001);
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn concurrent_operator_wallet_debits_are_all_or_nothing() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        for (id, balance) in [("wallet-consumer", 3.0), ("wallet-peer", 4.0)] {
            sqlx::query(
                "INSERT INTO nodes \
                 (id, endpoint, region, node_token_hash, max_concurrent, tokens_per_min, \
                  credit_balance, operator_pubkey) VALUES (?, 'https://example.invalid/v1', \
                  'test', 'x', 1, 1, ?, 'shared-operator')",
            )
            .bind(id)
            .bind(balance)
            .execute(&pool)
            .await
            .expect("seed wallet node");
            sqlx::query(
                "INSERT INTO credits (node_id, balance, created_at, updated_at) \
                 VALUES (?, ?, NOW(), NOW())",
            )
            .bind(id)
            .bind(balance)
            .execute(&pool)
            .await
            .expect("seed wallet credit");
        }
        let repo = Arc::new(MySqlRepo::new(pool.clone()));
        let mut tasks = Vec::new();
        for ordinal in 0..2 {
            let repo = Arc::clone(&repo);
            tasks.push(tokio::spawn(async move {
                repo.debit_for_consumer(
                    "wallet-consumer",
                    5.0,
                    &format!("wallet-task-{ordinal}"),
                    "wallet-test",
                )
                .await
            }));
        }
        let mut successes = 0;
        for task in tasks {
            successes += u32::from(task.await.expect("wallet task must join").debited);
        }
        assert_eq!(successes, 1);

        let rows: Vec<(f64, f64)> = sqlx::query_as(
            "SELECT CAST(n.credit_balance AS DOUBLE), CAST(c.balance AS DOUBLE) \
             FROM nodes n JOIN credits c ON c.node_id = n.id \
             WHERE n.operator_pubkey = 'shared-operator' ORDER BY n.id",
        )
        .fetch_all(&pool)
        .await
        .expect("read wallet balances");
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|(node, ledger)| (node - ledger).abs() < 0.0001));
        assert!((rows.iter().map(|(node, _)| node).sum::<f64>() - 2.0).abs() < 0.0001);
        let (debit_total,): (f64,) = sqlx::query_as(
            "SELECT CAST(SUM(ct.amount) AS DOUBLE) FROM credit_transactions ct \
             JOIN nodes n ON n.id = ct.node_id \
             WHERE ct.type = 'debit' AND n.operator_pubkey = 'shared-operator'",
        )
        .fetch_one(&pool)
        .await
        .expect("read wallet debit total");
        assert!((debit_total - 5.0).abs() < 0.0001);
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn expiry_racing_with_award_keeps_ledger_reconciled() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&pool)
            .await
            .expect("bootstrap disposable schema");
        sqlx::query(
            "INSERT INTO nodes \
             (id, endpoint, region, node_token_hash, max_concurrent, tokens_per_min, credit_balance) \
             VALUES ('expiry-race', 'https://example.invalid/v1', 'test', 'x', 1, 1, 5)",
        )
        .execute(&pool)
        .await
        .expect("seed node");
        sqlx::query(
            "INSERT INTO credits (node_id, balance, created_at, updated_at) \
             VALUES ('expiry-race', 5, NOW(), NOW())",
        )
        .execute(&pool)
        .await
        .expect("seed balance");
        sqlx::query(
            "INSERT INTO credit_transactions \
             (node_id, amount, type, nonce, reason, expires_at) \
             VALUES ('expiry-race', 5, 'credit', 'expired-seed', 'seed', NOW() - INTERVAL 1 DAY)",
        )
        .execute(&pool)
        .await
        .expect("seed expired earn");
        let repo = Arc::new(MySqlRepo::new(pool.clone()));
        let expire_repo = Arc::clone(&repo);
        let award_repo = Arc::clone(&repo);
        let (expire, award) = tokio::join!(
            tokio::spawn(async move { expire_repo.expire_idle_node_credits().await }),
            tokio::spawn(async move {
                award_repo
                    .record_credit_award("expiry-race", 1.0, "fresh-task", "fresh-award")
                    .await
            })
        );
        expire.expect("expiry task must join");
        award
            .expect("award task must join")
            .expect("award must succeed");

        let (node_balance, ledger_balance): (f64, f64) = sqlx::query_as(
            "SELECT CAST(n.credit_balance AS DOUBLE), CAST(c.balance AS DOUBLE) \
             FROM nodes n JOIN credits c ON c.node_id = n.id WHERE n.id = 'expiry-race'",
        )
        .fetch_one(&pool)
        .await
        .expect("read balances");
        let (credits, debits): (f64, f64) = sqlx::query_as(
            "SELECT CAST(SUM(CASE WHEN type='credit' THEN amount ELSE 0 END) AS DOUBLE), \
                    CAST(SUM(CASE WHEN type='debit' THEN amount ELSE 0 END) AS DOUBLE) \
             FROM credit_transactions WHERE node_id = 'expiry-race'",
        )
        .fetch_one(&pool)
        .await
        .expect("read transaction totals");
        assert!((node_balance - ledger_balance).abs() < 0.0001);
        assert!((node_balance - (credits - debits)).abs() < 0.0001);
        assert!(node_balance == 1.0 || node_balance == 6.0);
    }

    #[tokio::test]
    #[ignore = "requires an empty disposable MySQL database in IICP_TEST_DATABASE_URL"]
    async fn transient_credit_mutations_retry_once_and_reconcile() {
        let url = std::env::var("IICP_TEST_DATABASE_URL")
            .expect("IICP_TEST_DATABASE_URL must identify an empty disposable database");
        let admin_pool = init_pool(&url).await.expect("connect disposable database");
        crate::schema::ensure_schema(&admin_pool)
            .await
            .expect("bootstrap disposable schema");
        let retry_pool = MySqlPoolOptions::new()
            .max_connections(1)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET SESSION innodb_lock_wait_timeout = 1")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("connect retry-test pool");
        let repo = Arc::new(MySqlRepo::new(retry_pool));

        for (id, balance, operator) in [
            ("retry-node", 2.0, None),
            ("retry-wallet-consumer", 2.0, Some("retry-operator")),
            ("retry-wallet-peer", 2.0, Some("retry-operator")),
            ("retry-expiry", 3.0, None),
        ] {
            sqlx::query(
                "INSERT INTO nodes \
                 (id, endpoint, region, node_token_hash, max_concurrent, tokens_per_min, \
                  credit_balance, operator_pubkey) \
                 VALUES (?, 'https://example.invalid/v1', 'test', 'x', 1, 1, ?, ?)",
            )
            .bind(id)
            .bind(balance)
            .bind(operator)
            .execute(&admin_pool)
            .await
            .expect("seed retry node");
            sqlx::query(
                "INSERT INTO credits (node_id, balance, created_at, updated_at) \
                 VALUES (?, ?, NOW(), NOW())",
            )
            .bind(id)
            .bind(balance)
            .execute(&admin_pool)
            .await
            .expect("seed retry credit");
        }
        sqlx::query(
            "INSERT INTO credit_transactions \
             (node_id, amount, type, nonce, reason, expires_at) \
             VALUES ('retry-expiry', 3, 'credit', 'retry-expired-seed', 'seed', \
                     NOW() - INTERVAL 1 DAY)",
        )
        .execute(&admin_pool)
        .await
        .expect("seed expired retry credit");

        let mut node_lock = admin_pool.begin().await.expect("begin node lock");
        sqlx::query("SELECT id FROM nodes WHERE id = 'retry-node' FOR UPDATE")
            .fetch_one(&mut *node_lock)
            .await
            .expect("hold node debit lock");
        let debit_repo = Arc::clone(&repo);
        let node_debit = tokio::spawn(async move {
            debit_repo
                .debit_for_consumer("retry-node", 1.0, "retry-node-task", "retry-test")
                .await
        });
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        node_lock.commit().await.expect("release node debit lock");
        let node_result = node_debit.await.expect("node debit task must join");
        assert!(node_result.debited);
        assert_eq!(node_result.debit_count, 1);

        let mut wallet_lock = admin_pool.begin().await.expect("begin wallet lock");
        sqlx::query("SELECT id FROM nodes WHERE id = 'retry-wallet-consumer' FOR UPDATE")
            .fetch_one(&mut *wallet_lock)
            .await
            .expect("hold operator wallet lock");
        let wallet_repo = Arc::clone(&repo);
        let wallet_debit = tokio::spawn(async move {
            wallet_repo
                .debit_for_consumer(
                    "retry-wallet-consumer",
                    3.0,
                    "retry-wallet-task",
                    "retry-test",
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        wallet_lock
            .commit()
            .await
            .expect("release operator wallet lock");
        let wallet_result = wallet_debit.await.expect("wallet debit task must join");
        assert!(wallet_result.debited);
        assert_eq!(wallet_result.debit_count, 2);

        let mut expiry_lock = admin_pool.begin().await.expect("begin expiry lock");
        sqlx::query("SELECT id FROM nodes WHERE id = 'retry-expiry' FOR UPDATE")
            .fetch_one(&mut *expiry_lock)
            .await
            .expect("hold expiry lock");
        let expiry_repo = Arc::clone(&repo);
        let expiry = tokio::spawn(async move { expiry_repo.expire_idle_node_credits().await });
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        expiry_lock.commit().await.expect("release expiry lock");
        assert_eq!(expiry.await.expect("expiry task must join"), (1, 3.0));

        let rows: Vec<(String, f64, f64)> = sqlx::query_as(
            "SELECT n.id, CAST(n.credit_balance AS DOUBLE), CAST(c.balance AS DOUBLE) \
             FROM nodes n JOIN credits c ON c.node_id = n.id \
             WHERE n.id LIKE 'retry-%' ORDER BY n.id",
        )
        .fetch_all(&admin_pool)
        .await
        .expect("read retry balances");
        assert_eq!(rows.len(), 4);
        assert!(rows
            .iter()
            .all(|(_, node, ledger)| (node - ledger).abs() < 0.0001));

        let retry_transactions: Vec<(String, String, i64, f64)> = sqlx::query_as(
            "SELECT node_id, reason, COUNT(*), CAST(SUM(amount) AS DOUBLE) \
             FROM credit_transactions WHERE node_id LIKE 'retry-%' AND \
             (reason IN ('retry-test', 'ttl_expire') OR task_id = 'retry-wallet-task') \
             GROUP BY node_id, reason ORDER BY node_id, reason",
        )
        .fetch_all(&admin_pool)
        .await
        .expect("read retry transactions");
        assert_eq!(
            retry_transactions
                .iter()
                .map(|(_, _, count, _)| *count)
                .sum::<i64>(),
            4
        );
        assert!(retry_transactions
            .iter()
            .all(|(_, _, count, _)| *count == 1));
        let retry_debit_total: f64 = retry_transactions
            .iter()
            .map(|(_, _, _, amount)| *amount)
            .sum();
        assert!((retry_debit_total - 7.0).abs() < 0.0001);
    }
}

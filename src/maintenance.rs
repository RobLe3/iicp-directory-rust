// SPDX-License-Identifier: Apache-2.0
//! Content-free database maintenance/status operations shared by the server
//! scheduler and explicit operator CLI commands.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{MySql, Pool, QueryBuilder, Row};

pub const DEFAULT_BATCH_SIZE: u32 = 1_000;
pub const DEFAULT_MAX_BATCHES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RetentionPolicy {
    pub probe_days: u32,
    pub aggregate_days: u32,
    pub proxy_days: u32,
    pub dispatch_days: u32,
    pub heartbeat_event_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            probe_days: 14,
            aggregate_days: 30,
            proxy_days: 30,
            dispatch_days: 30,
            heartbeat_event_days: 1,
        }
    }
}

impl RetentionPolicy {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            probe_days: positive_env("IICP_TELEMETRY_PROBE_RETENTION_DAYS", defaults.probe_days),
            aggregate_days: positive_env(
                "IICP_TELEMETRY_AGGREGATE_RETENTION_DAYS",
                defaults.aggregate_days,
            ),
            proxy_days: positive_env("IICP_PROXY_TELEMETRY_RETENTION_DAYS", defaults.proxy_days),
            dispatch_days: positive_env(
                "IICP_DISPATCH_USAGE_RETENTION_DAYS",
                defaults.dispatch_days,
            ),
            heartbeat_event_days: positive_env(
                "IICP_HEARTBEAT_EVENT_RETENTION_DAYS",
                defaults.heartbeat_event_days,
            ),
        }
    }
}

fn positive_env(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[derive(Debug, Clone, Copy)]
struct RetentionTarget {
    name: &'static str,
    table: &'static str,
    column: &'static str,
    days: u32,
}

fn targets(policy: RetentionPolicy) -> [RetentionTarget; 4] {
    [
        RetentionTarget {
            name: "raw_probe_telemetry",
            table: "iicp_telemetry_probes",
            column: "probed_at",
            days: policy.probe_days,
        },
        RetentionTarget {
            name: "probe_aggregates",
            table: "iicp_telemetry_aggregates",
            column: "computed_at",
            days: policy.aggregate_days,
        },
        RetentionTarget {
            name: "proxy_telemetry",
            table: "proxy_telemetry",
            column: "created_at",
            days: policy.proxy_days,
        },
        RetentionTarget {
            name: "dispatch_usage_aggregates",
            table: "dispatch_usage_daily",
            column: "usage_date",
            days: policy.dispatch_days,
        },
    ]
}

#[derive(Debug, Serialize)]
pub struct PruneTableResult {
    pub name: &'static str,
    pub table: &'static str,
    pub exists: bool,
    pub retention_days: u32,
    pub cutoff: Option<String>,
    pub eligible_before: u64,
    pub deleted: u64,
    pub eligible_after: u64,
}

#[derive(Debug, Serialize)]
pub struct PruneSafety {
    pub drops_tables: bool,
    pub touches_credits: bool,
    pub touches_reputation: bool,
    pub touches_nodes_or_operators: bool,
    pub prod_backup_required_before_and_after_deploy: bool,
}

#[derive(Debug, Serialize)]
pub struct PruneReport {
    pub schema: &'static str,
    pub generated_at: String,
    pub dry_run: bool,
    pub batch_size: u32,
    pub max_batches: u32,
    pub tables: Vec<PruneTableResult>,
    pub safety: PruneSafety,
}

/// Count or boundedly delete expired telemetry. `apply=false` is read-only.
pub async fn prune_telemetry(
    pool: &Pool<MySql>,
    policy: RetentionPolicy,
    batch_size: u32,
    max_batches: u32,
    apply: bool,
) -> Result<PruneReport, sqlx::Error> {
    let now = Utc::now();
    let mut tables = Vec::new();
    for target in targets(policy) {
        tables.push(
            process_target(
                pool,
                target,
                now,
                batch_size.max(1),
                max_batches.max(1),
                apply,
            )
            .await?,
        );
    }
    Ok(PruneReport {
        schema: "iicp.db.telemetry_prune.v1",
        generated_at: now.to_rfc3339(),
        dry_run: !apply,
        batch_size: batch_size.max(1),
        max_batches: max_batches.max(1),
        tables,
        safety: PruneSafety {
            drops_tables: false,
            touches_credits: false,
            touches_reputation: false,
            touches_nodes_or_operators: false,
            prod_backup_required_before_and_after_deploy: true,
        },
    })
}

async fn process_target(
    pool: &Pool<MySql>,
    target: RetentionTarget,
    now: DateTime<Utc>,
    batch_size: u32,
    max_batches: u32,
    apply: bool,
) -> Result<PruneTableResult, sqlx::Error> {
    if !table_exists(pool, target.table).await? {
        return Ok(PruneTableResult {
            name: target.name,
            table: target.table,
            exists: false,
            retention_days: target.days,
            cutoff: None,
            eligible_before: 0,
            deleted: 0,
            eligible_after: 0,
        });
    }
    let cutoff = now - Duration::days(i64::from(target.days));
    let eligible_before = eligible_count(pool, target, cutoff).await?;
    let deleted = if apply {
        delete_bounded(pool, target, cutoff, batch_size, max_batches).await?
    } else {
        0
    };
    let eligible_after = if apply {
        eligible_count(pool, target, cutoff).await?
    } else {
        eligible_before
    };
    Ok(PruneTableResult {
        name: target.name,
        table: target.table,
        exists: true,
        retention_days: target.days,
        cutoff: Some(cutoff.format("%Y-%m-%d %H:%M:%S").to_string()),
        eligible_before,
        deleted,
        eligible_after,
    })
}

async fn table_exists(pool: &Pool<MySql>, table: &str) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
    )
    .bind(table)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

async fn eligible_count(
    pool: &Pool<MySql>,
    target: RetentionTarget,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let mut query = QueryBuilder::<MySql>::new("SELECT COUNT(*) FROM ");
    query
        .push(target.table)
        .push(" WHERE ")
        .push(target.column)
        .push(" IS NOT NULL AND ")
        .push(target.column)
        .push(" < ")
        .push_bind(cutoff.naive_utc());
    let count: i64 = query.build_query_scalar().fetch_one(pool).await?;
    Ok(count.max(0) as u64)
}

async fn delete_bounded(
    pool: &Pool<MySql>,
    target: RetentionTarget,
    cutoff: DateTime<Utc>,
    batch_size: u32,
    max_batches: u32,
) -> Result<u64, sqlx::Error> {
    let mut deleted = 0;
    for _ in 0..max_batches {
        let mut select = QueryBuilder::<MySql>::new("SELECT id FROM ");
        select
            .push(target.table)
            .push(" WHERE ")
            .push(target.column)
            .push(" IS NOT NULL AND ")
            .push(target.column)
            .push(" < ")
            .push_bind(cutoff.naive_utc())
            .push(" ORDER BY id LIMIT ")
            .push_bind(batch_size);
        let ids: Vec<u64> = select
            .build()
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|row| row.get::<u64, _>("id"))
            .collect();
        if ids.is_empty() {
            break;
        }
        let count = ids.len();
        let mut delete = QueryBuilder::<MySql>::new("DELETE FROM ");
        delete.push(target.table).push(" WHERE id IN (");
        let mut separated = delete.separated(",");
        for id in ids {
            separated.push_bind(id);
        }
        separated.push_unseparated(")");
        deleted += delete.build().execute(pool).await?.rows_affected();
        if count < batch_size as usize {
            break;
        }
    }
    Ok(deleted)
}

#[derive(Debug, Serialize)]
pub struct MaintenanceTableStatus {
    pub table: &'static str,
    pub exists: bool,
    pub rows: u64,
    pub estimated_bytes: Option<u64>,
    pub oldest: Option<String>,
    pub newest: Option<String>,
    pub retention_days: Option<u32>,
    pub eligible_prune_rows: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct MaintenanceStatusReport {
    pub schema: &'static str,
    pub generated_at: String,
    pub driver: &'static str,
    pub database: String,
    pub retention: RetentionPolicy,
    pub tables: Vec<MaintenanceTableStatus>,
    pub safety: MaintenanceSafety,
}

#[derive(Debug, Serialize)]
pub struct MaintenanceSafety {
    pub dry_run_only: bool,
    pub exports_row_payloads: bool,
    pub drops_tables: bool,
    pub prod_backup_required_before_and_after_deploy: bool,
}

pub async fn maintenance_status(
    pool: &Pool<MySql>,
    policy: RetentionPolicy,
) -> Result<MaintenanceStatusReport, sqlx::Error> {
    let now = Utc::now();
    let database: String = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(pool)
        .await?;
    let mut tables = Vec::new();
    for target in targets(policy) {
        tables
            .push(table_status(pool, target.table, Some((target.column, target.days)), now).await?);
    }
    for table in [
        "node_events",
        "node_address_history",
        "credits",
        "credit_transactions",
        "reputations",
    ] {
        tables.push(table_status(pool, table, None, now).await?);
    }
    Ok(MaintenanceStatusReport {
        schema: "iicp.db.maintenance_status.v1",
        generated_at: now.to_rfc3339(),
        driver: "mysql",
        database,
        retention: policy,
        tables,
        safety: MaintenanceSafety {
            dry_run_only: true,
            exports_row_payloads: false,
            drops_tables: false,
            prod_backup_required_before_and_after_deploy: true,
        },
    })
}

async fn table_status(
    pool: &Pool<MySql>,
    table: &'static str,
    dated: Option<(&'static str, u32)>,
    now: DateTime<Utc>,
) -> Result<MaintenanceTableStatus, sqlx::Error> {
    if !table_exists(pool, table).await? {
        return Ok(MaintenanceTableStatus {
            table,
            exists: false,
            rows: 0,
            estimated_bytes: None,
            oldest: None,
            newest: None,
            retention_days: dated.map(|(_, days)| days),
            eligible_prune_rows: None,
        });
    }
    let rows: i64 = QueryBuilder::<MySql>::new(format!("SELECT COUNT(*) FROM {table}"))
        .build_query_scalar()
        .fetch_one(pool)
        .await?;
    let estimated_bytes: Option<u64> = sqlx::query_scalar(
        "SELECT data_length + index_length FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
    )
    .bind(table)
    .fetch_optional(pool)
    .await?
    .flatten();
    let (oldest, newest, eligible) = if let Some((column, days)) = dated {
        let mut range = QueryBuilder::<MySql>::new("SELECT ");
        range
            .push("CAST(MIN(")
            .push(column)
            .push(") AS CHAR), CAST(MAX(")
            .push(column)
            .push(") AS CHAR) FROM ")
            .push(table);
        let row = range.build().fetch_one(pool).await?;
        let target = RetentionTarget {
            name: "",
            table,
            column,
            days,
        };
        (
            row.try_get::<Option<String>, _>(0)?,
            row.try_get::<Option<String>, _>(1)?,
            Some(eligible_count(pool, target, now - Duration::days(i64::from(days))).await?),
        )
    } else {
        (None, None, None)
    };
    Ok(MaintenanceTableStatus {
        table,
        exists: true,
        rows: rows.max(0) as u64,
        estimated_bytes,
        oldest,
        newest,
        retention_days: dated.map(|(_, days)| days),
        eligible_prune_rows: eligible,
    })
}

#[derive(Debug, Serialize)]
pub struct E050ReadinessReport {
    pub schema: &'static str,
    pub basis: &'static str,
    pub strict_mode_enabled: bool,
    pub token_capability_floor: &'static str,
    pub total_heartbeating: u64,
    pub token_capable: u64,
    pub token_capable_share: f64,
    pub secured_nodes: u64,
    pub hypothetical_tokenless_secured_reregistration_rejections: u64,
    pub content_free: bool,
    pub mutates_state: bool,
    pub authorizes_cutover: bool,
}

pub async fn e050_readiness(
    pool: &Pool<MySql>,
    strict_mode_enabled: bool,
) -> Result<E050ReadinessReport, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT COALESCE(sdk_compatibility_version, sdk_version) AS sdk_version, operator_pubkey, cx_public_key FROM nodes WHERE available = 1 AND status = 'active' AND last_seen >= NOW() - INTERVAL 90 SECOND",
    )
    .fetch_all(pool)
    .await?;
    let total = rows.len() as u64;
    let token_capable = rows
        .iter()
        .filter(|row| {
            token_capable(
                row.try_get::<Option<String>, _>("sdk_version")
                    .ok()
                    .flatten()
                    .as_deref(),
            )
        })
        .count() as u64;
    let secured = rows
        .iter()
        .filter(|row| {
            nonempty(
                row.try_get::<Option<String>, _>("operator_pubkey")
                    .ok()
                    .flatten()
                    .as_deref(),
            ) || nonempty(
                row.try_get::<Option<String>, _>("cx_public_key")
                    .ok()
                    .flatten()
                    .as_deref(),
            )
        })
        .count() as u64;
    Ok(E050ReadinessReport {
        schema: "iicp.e050_readiness.v1",
        basis: "heartbeating_nodes",
        strict_mode_enabled,
        token_capability_floor: "0.7.59",
        total_heartbeating: total,
        token_capable,
        token_capable_share: if total == 0 {
            0.0
        } else {
            ((token_capable as f64 / total as f64) * 1_000_000.0).round() / 1_000_000.0
        },
        secured_nodes: secured,
        hypothetical_tokenless_secured_reregistration_rejections: secured,
        content_free: true,
        mutates_state: false,
        authorizes_cutover: false,
    })
}

fn nonempty(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn token_capable(version: Option<&str>) -> bool {
    let Some(version) = version.map(|value| value.trim_start_matches('v')) else {
        return false;
    };
    let mut parts = version.split('.').take(3).map(|part| {
        part.chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .ok()
    });
    matches!(
        (parts.next().flatten(), parts.next().flatten(), parts.next().flatten()),
        (Some(major), Some(minor), Some(patch)) if (major, minor, patch) >= (0, 7, 59)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_defaults_match_php_authority() {
        assert_eq!(
            RetentionPolicy::default(),
            RetentionPolicy {
                probe_days: 14,
                aggregate_days: 30,
                proxy_days: 30,
                dispatch_days: 30,
                heartbeat_event_days: 1,
            }
        );
    }

    #[test]
    fn e050_version_floor_matches_php() {
        assert!(!token_capable(None));
        assert!(!token_capable(Some("0.7.58")));
        assert!(token_capable(Some("v0.7.59")));
        assert!(token_capable(Some("0.7.90-beta.1")));
        assert!(token_capable(Some("1.0.0")));
    }
}

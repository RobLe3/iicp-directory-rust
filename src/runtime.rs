//! Process startup and database-backed operational command composition.

use std::path::PathBuf;
use std::sync::Arc;

use sqlx::{MySql, Pool};

use crate::cli::Command;
use crate::repo::{InMemoryRepo, NodeRepository};
use crate::validate::Env;
use crate::{db, maintenance, schema};
use iicp_directory_rs::runtime_health::RuntimeHealth;

/// Advance a monotonic scheduler checkpoint independently of the notifier timer.
/// The stale-node loop advances the separate supervisor checkpoint.
pub(crate) async fn run_runtime_progress_loop(health: RuntimeHealth) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        health.advance_runtime();
        let snapshot = health.snapshot();
        if let Err(error) = iicp_directory_rs::runtime_health::write_snapshot_atomic(
            &runtime_health_path(None),
            &snapshot,
        ) {
            eprintln!("[runtime_health] snapshot write failed: {error}");
        }
    }
}

pub(crate) fn runtime_health_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| std::env::var_os("IICP_RUNTIME_HEALTH_FILE").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .map(|root| root.join("iicp-directory-rs/health.json"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|root| root.join(".local/state/iicp-directory-rs/health.json"))
        })
        .unwrap_or_else(|| PathBuf::from("/tmp/iicp-directory-rs-health.json"))
}

pub(crate) fn run_healthcheck(
    explicit: Option<PathBuf>,
    require_ready: bool,
    json: bool,
) -> Result<i32, String> {
    use iicp_directory_rs::runtime_health::{HealthSnapshot, Liveness, Readiness};
    let path = runtime_health_path(explicit);
    let raw =
        std::fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let snapshot: HealthSnapshot =
        serde_json::from_slice(&raw).map_err(|error| format!("invalid snapshot: {error}"))?;
    let age = std::fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .map_err(|error| format!("cannot establish snapshot freshness: {error}"))?;
    let stale = age.as_millis() > u128::from(snapshot.progress.runtime.stale_after_ms);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&snapshot).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "IICP Rust directory health\n  liveness  {:?}\n  readiness {:?}\n  reasons   {:?}",
            snapshot.liveness, snapshot.readiness, snapshot.reason_codes
        );
    }
    if stale {
        return Ok(1);
    }
    Ok(if require_ready {
        i32::from(snapshot.readiness != Readiness::Ready)
    } else {
        match snapshot.liveness {
            Liveness::Live => 0,
            Liveness::NotLive => 1,
            _ => 2,
        }
    })
}

pub(crate) struct RepositoryRuntime {
    pub(crate) repo: Arc<dyn NodeRepository>,
    pub(crate) mysql_pool: Option<Pool<MySql>>,
}

pub(crate) async fn initialize_repository(env: Env, version: &str) -> RepositoryRuntime {
    // A configured database is an explicit persistence contract: connection or
    // schema failures are fatal, never a silent downgrade to ephemeral memory.
    if let Ok(url) = std::env::var("DATABASE_URL") {
        match db::init_pool(&url).await {
            Ok(pool) => {
                match schema::ensure_schema(&pool).await {
                    Ok(status) => {
                        println!("iicp-directory-rs {version}: MySQL schema status={status}")
                    }
                    Err(error) => {
                        eprintln!("FATAL: MySQL schema verification failed: {error}");
                        std::process::exit(1);
                    }
                }
                println!("iicp-directory-rs {version}: MySQL pool connected");
                RepositoryRuntime {
                    repo: Arc::new(db::MySqlRepo::new(pool.clone())),
                    mysql_pool: Some(pool),
                }
            }
            Err(error) => {
                eprintln!("FATAL: configured MySQL connection failed: {error}");
                std::process::exit(1);
            }
        }
    } else if in_memory_allowed(env, std::env::var("IICP_ALLOW_IN_MEMORY").ok().as_deref()) {
        println!("iicp-directory-rs {version}: no DATABASE_URL; using InMemoryRepo");
        RepositoryRuntime {
            repo: Arc::new(InMemoryRepo::default()),
            mysql_pool: None,
        }
    } else {
        eprintln!(
            "FATAL: DATABASE_URL is required; ephemeral memory requires non-production APP_ENV and IICP_ALLOW_IN_MEMORY=true"
        );
        std::process::exit(1);
    }
}

fn in_memory_allowed(env: Env, value: Option<&str>) -> bool {
    env != Env::Production
        && value.is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

async fn verified_operational_pool() -> Result<Pool<MySql>, String> {
    let url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required for operational commands".to_string())?;
    let pool = db::init_pool(&url)
        .await
        .map_err(|error| format!("configured MySQL connection failed: {error}"))?;
    schema::verify_existing_schema(&pool)
        .await
        .map_err(|error| format!("MySQL schema verification failed: {error}"))?;
    Ok(pool)
}

pub(crate) async fn run_operational_command(command: Command) -> Result<(), String> {
    let pool = verified_operational_pool().await?;
    let (value, json_requested) = match command {
        Command::Service { .. } => {
            return Err("service commands must be dispatched before database initialization".into())
        }
        Command::Healthcheck { .. } => {
            return Err("healthcheck must be dispatched before database initialization".into())
        }
        Command::Update { .. } => {
            return Err("update commands must be dispatched before database initialization".into())
        }
        Command::DbMaintenanceStatus { retention, json } => (
            serde_json::to_value(
                maintenance::maintenance_status(&pool, retention.policy())
                    .await
                    .map_err(|error| format!("maintenance status failed: {error}"))?,
            )
            .map_err(|error| error.to_string())?,
            json,
        ),
        Command::TelemetryPrune {
            retention,
            batch,
            max_batches,
            dry_run: _,
            apply,
            json,
        } => (
            serde_json::to_value(
                maintenance::prune_telemetry(&pool, retention.policy(), batch, max_batches, apply)
                    .await
                    .map_err(|error| format!("telemetry prune failed: {error}"))?,
            )
            .map_err(|error| error.to_string())?,
            json,
        ),
        Command::E050Readiness { json } => (
            serde_json::to_value(
                maintenance::e050_readiness(
                    &pool,
                    std::env::var("IICP_E050_STRICT_SECURED").is_ok_and(|value| {
                        matches!(
                            value.to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        )
                    }),
                )
                .await
                .map_err(|error| format!("E050 readiness failed: {error}"))?,
            )
            .map_err(|error| error.to_string())?,
            json,
        ),
    };
    if !json_requested {
        eprintln!("content-free operational report (use --json for machine-readable mode)");
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_requires_non_production_and_explicit_truthy_value() {
        assert!(!in_memory_allowed(Env::Production, Some("true")));
        assert!(!in_memory_allowed(Env::Testing, None));
        assert!(!in_memory_allowed(Env::Local, Some("false")));
        for value in ["1", "true", "TRUE", "yes", "on"] {
            assert!(in_memory_allowed(Env::Testing, Some(value)));
        }
    }
}

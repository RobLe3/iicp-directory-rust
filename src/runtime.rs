//! Process startup and database-backed operational command composition.

use std::sync::Arc;

use sqlx::{MySql, Pool};

use crate::cli::Command;
use crate::repo::{InMemoryRepo, NodeRepository};
use crate::validate::Env;
use crate::{db, maintenance, schema};

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

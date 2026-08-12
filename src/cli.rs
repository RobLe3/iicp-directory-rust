// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Parser, Subcommand};

use crate::maintenance;

#[derive(Debug, Parser)]
#[command(name = "iicp-directory-rs", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Read the private local runtime-health snapshot written by the running process.
    Healthcheck {
        /// Require readiness rather than local liveness.
        #[arg(long)]
        ready: bool,
        /// Emit the versioned machine-readable snapshot.
        #[arg(long)]
        json: bool,
        /// Override the local snapshot path.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
    /// Install, inspect, restart or remove the user-level systemd service.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Check the authoritative crates.io package line without mutating this installation.
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
    /// Report metadata-only database maintenance status.
    DbMaintenanceStatus {
        #[command(flatten)]
        retention: RetentionArgs,
        #[arg(long)]
        json: bool,
    },
    /// Count expired telemetry by default; delete only with explicit --apply.
    TelemetryPrune {
        #[command(flatten)]
        retention: RetentionArgs,
        #[arg(long, default_value_t = maintenance::DEFAULT_BATCH_SIZE)]
        batch: u32,
        #[arg(long, default_value_t = maintenance::DEFAULT_MAX_BATCHES)]
        max_batches: u32,
        #[arg(long, conflicts_with = "apply")]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
        #[arg(long)]
        json: bool,
    },
    /// Report aggregate strict-E050 readiness without mutating registrations.
    E050Readiness {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum UpdateAction {
    /// Report whether a newer immutable crate release is available.
    Check {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServiceAction {
    /// Write, enable and optionally start the user service.
    Install {
        /// Absolute environment file containing the directory configuration.
        #[arg(long)]
        env_file: std::path::PathBuf,
        /// Install and enable without starting the service now.
        #[arg(long)]
        no_start: bool,
        /// Enable Type=notify; watchdog remains off unless --watchdog-sec is supplied.
        #[arg(long)]
        notify: bool,
        /// Measured watchdog interval. Implies --notify and is never guessed.
        #[arg(long, value_parser = clap::value_parser!(u64).range(30..=3600))]
        watchdog_sec: Option<u64>,
        /// Print the unit and manager actions without changing the host.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print effective service-manager properties.
    Status,
    /// Restart the installed service.
    Restart,
    /// Disable and remove the generated service unit.
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Default, Args)]
pub(crate) struct RetentionArgs {
    #[arg(long)]
    pub(crate) probe_days: Option<u32>,
    #[arg(long)]
    pub(crate) aggregate_days: Option<u32>,
    #[arg(long)]
    pub(crate) proxy_days: Option<u32>,
    #[arg(long)]
    pub(crate) dispatch_days: Option<u32>,
}

impl RetentionArgs {
    pub(crate) fn policy(&self) -> maintenance::RetentionPolicy {
        let mut policy = maintenance::RetentionPolicy::from_env();
        policy.probe_days = positive_override(self.probe_days, policy.probe_days);
        policy.aggregate_days = positive_override(self.aggregate_days, policy.aggregate_days);
        policy.proxy_days = positive_override(self.proxy_days, policy.proxy_days);
        policy.dispatch_days = positive_override(self.dispatch_days, policy.dispatch_days);
        policy
    }
}

fn positive_override(value: Option<u32>, default: u32) -> u32 {
    value.filter(|value| *value > 0).unwrap_or(default)
}

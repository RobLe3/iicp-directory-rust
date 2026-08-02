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

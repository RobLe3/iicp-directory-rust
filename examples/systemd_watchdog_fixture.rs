// SPDX-License-Identifier: Apache-2.0
//! Development-only process used by the isolated systemd evidence lane.

#[cfg(target_os = "linux")]
use iicp_directory_rs::runtime_health::{RuntimeHealth, RuntimeHealthFault};
#[cfg(target_os = "linux")]
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::{path::PathBuf, time::Duration};

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct CadenceEvidence {
    content_free: bool,
    configured_interval_ms: u128,
    max_observed_interval_ms: u128,
    samples: usize,
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "stall-once".to_string());
    let argument = std::env::args().nth(2).map(PathBuf::from);
    if mode == "crash-once" {
        let marker = argument.clone().expect("crash-once requires a marker path");
        if !marker.exists() {
            std::fs::write(marker, b"crashed\n").expect("write crash marker");
            std::process::exit(1);
        }
    }
    let should_stall = match mode.as_str() {
        "always-stall" => true,
        "stall-once" => {
            let marker = argument.clone().expect("stall-once requires a marker path");
            if marker.exists() {
                false
            } else {
                std::fs::write(marker, b"stalled\n").expect("write stall marker");
                true
            }
        }
        "healthy" | "measure" | "crash-once" | "external-degraded" => false,
        _ => panic!("unsupported systemd evidence mode"),
    };

    let health = RuntimeHealth::new(true);
    health.mark_running();
    health.advance_runtime();
    health.advance_supervisor();
    if mode == "external-degraded" {
        health.inject_fault(RuntimeHealthFault::DirectoryUnavailable);
    }
    let _notifier = iicp_directory_rs::systemd_notify::spawn_if_enabled(health.clone())
        .expect("systemd notification must be enabled by the evidence unit");

    let cadence = if mode == "measure" {
        Duration::from_secs(5)
    } else {
        Duration::from_millis(100)
    };
    let measurement_path =
        (mode == "measure").then(|| argument.expect("measure requires an output path"));
    let mut intervals = Vec::new();
    let mut previous = std::time::Instant::now();
    let mut cycles = 0_u64;
    loop {
        tokio::time::sleep(cadence).await;
        let now = std::time::Instant::now();
        intervals.push(now.duration_since(previous).as_millis());
        previous = now;
        cycles += 1;
        if should_stall && cycles == 5 {
            health.inject_fault(RuntimeHealthFault::RuntimeProgressStale);
            continue;
        }
        if !should_stall {
            health.advance_runtime();
            health.advance_supervisor();
        }
        if let Some(path) = &measurement_path {
            if cycles == 6 {
                let evidence = CadenceEvidence {
                    content_free: true,
                    configured_interval_ms: cadence.as_millis(),
                    max_observed_interval_ms: *intervals.iter().max().unwrap_or(&0),
                    samples: intervals.len(),
                };
                std::fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap())
                    .expect("write cadence evidence");
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("systemd_watchdog_fixture requires Linux");
    std::process::exit(2);
}

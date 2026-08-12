#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Isolated, content-free systemd manager recovery evidence.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]] || ! command -v systemd-run >/dev/null; then
  echo "ERROR: Linux with systemd-run is required" >&2
  exit 2
fi

scope="${IICP_SYSTEMD_EVIDENCE_SCOPE:-user}"
case "$scope" in
  user) manager=(systemctl --user); runner=(systemd-run --user) ;;
  system) manager=(systemctl); runner=(systemd-run) ;;
  *) echo "ERROR: IICP_SYSTEMD_EVIDENCE_SCOPE must be user or system" >&2; exit 2 ;;
esac
"${manager[@]}" show-environment >/dev/null 2>&1 || {
  echo "ERROR: the selected systemd manager is not available" >&2
  exit 2
}

output="${1:-systemd-watchdog-evidence.json}"
started="$(date -u +%FT%TZ)"
work="$(mktemp -d)"
unit="iicp-directory-health-evidence-$RANDOM"
storm="${unit}-storm"
load="${unit}-load"
crash="${unit}-crash"
degraded="${unit}-degraded"
marker="$work/stalled-once"
crash_marker="$work/crashed-once"
cadence="$work/cadence.json"
load_pids=()

cleanup() {
  if [[ "${#load_pids[@]}" -gt 0 ]]; then
    kill "${load_pids[@]}" >/dev/null 2>&1 || true
  fi
  "${manager[@]}" stop "$unit.service" "$storm.service" "$load.service" "$crash.service" "$degraded.service" >/dev/null 2>&1 || true
  "${manager[@]}" reset-failed "$unit.service" "$storm.service" "$load.service" "$crash.service" "$degraded.service" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --locked --example systemd_watchdog_fixture \
  --features systemd-notify,runtime-health-fault-injection
fixture="${CARGO_TARGET_DIR:-$(pwd)/target}/debug/examples/systemd_watchdog_fixture"

common=(
  --property=Type=notify
  --property=NotifyAccess=main
  --property=WatchdogSec=2s
  --property=Restart=on-failure
  --property=RestartSec=250ms
  --setenv=IICP_SYSTEMD_NOTIFY=1
)

"${runner[@]}" --unit="$unit" "${common[@]}" \
  --property=StartLimitIntervalSec=20s --property=StartLimitBurst=4 \
  "$fixture" stall-once "$marker" >/dev/null

recovered=0
for _ in $(seq 1 80); do
  restarts="$("${manager[@]}" show "$unit.service" -p NRestarts --value)"
  active="$("${manager[@]}" show "$unit.service" -p ActiveState --value)"
  if [[ "$restarts" -ge 1 && "$active" == "active" ]]; then
    recovered=1
    break
  fi
  sleep 0.25
done
[[ "$recovered" -eq 1 ]] || {
  echo "ERROR: systemd did not recover the one-time PID-alive stall" >&2
  exit 1
}

"${runner[@]}" --unit="$crash" "${common[@]}" \
  --property=StartLimitIntervalSec=20s --property=StartLimitBurst=4 \
  "$fixture" crash-once "$crash_marker" >/dev/null || true

crash_recovered=0
for _ in $(seq 1 80); do
  restarts="$("${manager[@]}" show "$crash.service" -p NRestarts --value)"
  active="$("${manager[@]}" show "$crash.service" -p ActiveState --value)"
  if [[ "$restarts" -ge 1 && "$active" == "active" ]]; then
    crash_recovered=1
    break
  fi
  sleep 0.25
done
[[ "$crash_recovered" -eq 1 ]] || {
  echo "ERROR: systemd did not recover the one-time process crash" >&2
  exit 1
}

"${runner[@]}" --unit="$degraded" "${common[@]}" \
  --property=StartLimitIntervalSec=20s --property=StartLimitBurst=4 \
  "$fixture" external-degraded >/dev/null
sleep 3
degraded_restarts="$("${manager[@]}" show "$degraded.service" -p NRestarts --value)"
degraded_active="$("${manager[@]}" show "$degraded.service" -p ActiveState --value)"
[[ "$degraded_restarts" -eq 0 && "$degraded_active" == "active" ]] || {
  echo "ERROR: external connectivity degradation caused a watchdog restart" >&2
  exit 1
}

"${runner[@]}" --unit="$storm" "${common[@]}" \
  --property=StartLimitIntervalSec=20s --property=StartLimitBurst=2 \
  "$fixture" always-stall >/dev/null

limited=0
for _ in $(seq 1 100); do
  active="$("${manager[@]}" show "$storm.service" -p ActiveState --value)"
  result="$("${manager[@]}" show "$storm.service" -p Result --value)"
  restarts="$("${manager[@]}" show "$storm.service" -p NRestarts --value)"
  if [[ "$active" == "failed" && "$result" == "watchdog" && "$restarts" -ge 2 ]]; then
    limited=1
    break
  fi
  sleep 0.25
done
[[ "$limited" -eq 1 ]] || {
  echo "ERROR: restart-storm limit was not observed" >&2
  exit 1
}

"${runner[@]}" --unit="$load" \
  --property=Type=notify --property=NotifyAccess=main \
  --property=WatchdogSec=20s --property=Restart=on-failure \
  --property=RestartSec=1s --setenv=IICP_SYSTEMD_NOTIFY=1 \
  "$fixture" measure "$cadence" >/dev/null

for _ in 1 2; do
  yes >/dev/null &
  load_pids+=("$!")
done
(
  while :; do
    dd if=/dev/zero of="$work/storage-load" bs=1M count=32 conv=fsync status=none
    rm -f "$work/storage-load"
  done
) &
load_pids+=("$!")

for _ in $(seq 1 90); do
  [[ -s "$cadence" ]] && break
  sleep 0.5
done
for pid in "${load_pids[@]}"; do
  kill -0 "$pid" >/dev/null 2>&1 || {
    echo "ERROR: a bounded load generator exited before cadence measurement completed" >&2
    exit 1
  }
done
kill "${load_pids[@]}" >/dev/null 2>&1 || true
load_pids=()
[[ -s "$cadence" ]] || {
  echo "ERROR: loaded cadence evidence was not produced" >&2
  exit 1
}
load_restarts="$("${manager[@]}" show "$load.service" -p NRestarts --value)"
load_active="$("${manager[@]}" show "$load.service" -p ActiveState --value)"
[[ "$load_restarts" -eq 0 && "$load_active" == "active" ]] || {
  echo "ERROR: legitimate load caused a watchdog restart" >&2
  exit 1
}
max_interval="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["max_observed_interval_ms"])' "$cadence")"
[[ "$max_interval" -lt 30000 ]] || {
  echo "ERROR: runtime progress exceeded the existing 30-second stale threshold" >&2
  exit 1
}

completed="$(date -u +%FT%TZ)"
arch="$(uname -m)"
systemd_version="$(systemctl --version | awk 'NR==1 {print $2}')"
python3 - "$output" "$started" "$completed" "$scope" "$arch" "$systemd_version" "$max_interval" <<'PY'
import json
import pathlib
import sys

path, started, completed, scope, arch, systemd, max_interval = sys.argv[1:]
record = {
    "schema": "iicp.directory_runtime_health_systemd_evidence.v1",
    "content_free": True,
    "started_at": started,
    "completed_at": completed,
    "platform": {"os": "linux", "arch": arch, "systemd": systemd, "scope": scope},
    "checks": {
        "pid_alive_stall_watchdog_recovery": "pass",
        "process_crash_recovery": "pass",
        "external_degradation_no_restart": "pass",
        "post_restart_healthy_instance": "pass",
        "restart_storm_limit": "pass",
        "loaded_runtime_cadence": "pass",
    },
    "recovery_watchdog_seconds": 2,
    "loaded_watchdog_seconds": 20,
    "loaded_cadence": {
        "configured_interval_ms": 5000,
        "max_observed_interval_ms": int(max_interval),
        "stale_threshold_ms": 30000,
    },
    "limitations": [
        "temporary_fixture_process_not_a_production_directory",
        "does_not_classify_the_original_raspberry_pi_incident",
        "does_not_authorize_default_watchdog_enablement",
    ],
}
pathlib.Path(path).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
PY

echo "systemd watchdog evidence written to $output"

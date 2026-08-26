#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Content-free Rust runtime-health evidence lane for Linux/ARM operators.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${IICP_DISPOSABLE_CARGO_ACTIVE:-0}" != 1 ]]; then
  exec "$ROOT/scripts/with_disposable_cargo_target.sh" --label runtime-health-arm -- "$0" "$@"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: this evidence lane requires Linux" >&2
  exit 2
fi

output="${1:-runtime-health-evidence.json}"
started="$(date -u +%FT%TZ)"
start_seconds="$(date +%s)"

cargo test --locked --all-features \
  runtime_health::tests::fault_injection_distinguishes_local_stalls_from_external_degradation
cargo test --locked --all-features systemd_notify::tests
cargo clippy --locked --all-features --all-targets -- -D warnings

completed="$(date -u +%FT%TZ)"
elapsed="$(( $(date +%s) - start_seconds ))"
arch="$(uname -m)"
kernel="$(uname -r | cut -d- -f1)"
rustc_version="$(rustc --version | awk '{print $2}')"
systemd_version="$(systemctl --version 2>/dev/null | awk 'NR==1 {print $2}' || true)"

python3 - "$output" "$started" "$completed" "$elapsed" "$arch" "$kernel" "$rustc_version" "$systemd_version" <<'PY'
import json
import pathlib
import sys

path, started, completed, elapsed, arch, kernel, rustc, systemd = sys.argv[1:]
record = {
    "schema": "iicp.directory_runtime_health_platform_evidence.v1",
    "content_free": True,
    "started_at": started,
    "completed_at": completed,
    "elapsed_seconds": int(elapsed),
    "platform": {"os": "linux", "arch": arch, "kernel_release": kernel},
    "toolchain": {"rustc": rustc, "systemd": systemd or None},
    "checks": {
        "fault_classification": "pass",
        "native_notify_socket": "pass",
        "strict_clippy": "pass",
    },
    "limitations": [
        "does_not_enable_or_modify_a_systemd_service",
        "does_not_prove_restart_storm_or_boot_persistence",
        "does_not_classify_the_original_raspberry_pi_incident",
    ],
}
pathlib.Path(path).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
PY

echo "runtime-health evidence written to $output"

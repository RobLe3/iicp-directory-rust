#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run one CI/release-style Cargo gate in an isolated target directory.
set -euo pipefail

usage() {
  echo "usage: $0 --label LABEL -- COMMAND [ARG ...]" >&2
  exit 2
}

[[ "${1:-}" == "--label" && -n "${2:-}" && "${3:-}" == "--" ]] || usage
label="$2"
shift 3
[[ "$#" -gt 0 ]] || usage
[[ "$label" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || {
  echo "ERROR: unsafe disposable target label" >&2
  exit 2
}

base="${IICP_DISPOSABLE_TARGET_ROOT:-${TMPDIR:-/tmp}/iicp-cargo-targets}"
python3 - "$base" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1]).expanduser()
path.mkdir(mode=0o700, parents=True, exist_ok=True)
info = path.lstat()
if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit("ERROR: disposable target root must be a real directory")
if hasattr(os, "getuid") and info.st_uid != os.getuid():
    raise SystemExit("ERROR: disposable target root is not owned by the current user")
path.chmod(0o700)
PY

target="$(mktemp -d "$base/$label.XXXXXX")"
case "$target" in
  "$base"/*) ;;
  *) echo "ERROR: mktemp escaped disposable target root" >&2; exit 2 ;;
esac
export CARGO_TARGET_DIR="$target"
export CARGO_INCREMENTAL=0
export IICP_DISPOSABLE_CARGO_ACTIVE=1
started="$(date -u +%FT%TZ)"

set +e
"$@"
status=$?
set -e

size_bytes="$(du -sk "$target" | awk '{print $1 * 1024}')"
preserved=false
if [[ "$status" -ne 0 && "${IICP_KEEP_FAILED_CARGO_TARGET:-0}" == "1" ]]; then
  preserved=true
  printf 'disposable Cargo target preserved after failure: %s (%s bytes)\n' "$target" "$size_bytes" >&2
else
  python3 - "$base" "$target" <<'PY'
import pathlib
import shutil
import stat
import sys

base = pathlib.Path(sys.argv[1]).expanduser().resolve(strict=True)
target = pathlib.Path(sys.argv[2])
info = target.lstat()
if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit("ERROR: refusing unsafe disposable target cleanup")
resolved = target.resolve(strict=True)
if resolved.parent != base:
    raise SystemExit("ERROR: refusing target outside disposable root")
shutil.rmtree(resolved)
PY
fi

if [[ -n "${IICP_DISPOSABLE_TARGET_RECEIPT:-}" ]]; then
  IICP_RECEIPT_PATH="$IICP_DISPOSABLE_TARGET_RECEIPT"   IICP_RECEIPT_LABEL="$label"   IICP_RECEIPT_STARTED="$started"   IICP_RECEIPT_STATUS="$status"   IICP_RECEIPT_PRESERVED="$preserved"   IICP_RECEIPT_SIZE="$size_bytes"   python3 - <<'PY'
import json
import os
import pathlib
from datetime import datetime, timezone

path = pathlib.Path(os.environ["IICP_RECEIPT_PATH"])
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
record = {
    "schema": "iicp.disposable-cargo-target-receipt.v1",
    "label": os.environ["IICP_RECEIPT_LABEL"],
    "started_at": os.environ["IICP_RECEIPT_STARTED"],
    "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "exit_code": int(os.environ["IICP_RECEIPT_STATUS"]),
    "preserved": os.environ["IICP_RECEIPT_PRESERVED"] == "true",
    "peak_retained_bytes": int(float(os.environ["IICP_RECEIPT_SIZE"])),
    "incremental_compilation": False,
    "content_free": True,
}
temporary = path.with_name(f".{path.name}.{os.getpid()}")
temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
temporary.chmod(0o600)
temporary.replace(path)
PY
fi

exit "$status"


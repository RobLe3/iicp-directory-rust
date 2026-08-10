#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Audit against a clean advisory checkout so unrelated local DB state cannot
# create duplicate IDs or hide repository findings.
set -euo pipefail

TMP="$(mktemp -d "${TMPDIR:-/tmp}/iicp-rustsec.XXXXXX")"
cleanup() {
  python3 - "$TMP" <<'PY'
import shutil
import sys
shutil.rmtree(sys.argv[1], ignore_errors=True)
PY
}
trap cleanup EXIT

for command in cargo git python3; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done
git clone --quiet --depth 1 https://github.com/RustSec/advisory-db.git "$TMP/db"
cargo audit --db "$TMP/db" --ignore RUSTSEC-2023-0071

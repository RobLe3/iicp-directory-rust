#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo 'workflow validation requires Go to run pinned actionlint v1.7.12' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 "$@"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Measure production coverage with ordinary and disposable-MySQL tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MYSQL_IMAGE="${IICP_MYSQL_IMAGE:-mysql@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b}"
CONTAINER=""

cleanup() {
  if [[ -n "$CONTAINER" ]]; then
    docker stop "$CONTAINER" >/dev/null 2>&1 || true
    docker container rm "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v cargo-llvm-cov >/dev/null 2>&1 || {
  echo 'cargo-llvm-cov is required (cargo install cargo-llvm-cov --locked)' >&2
  exit 1
}
if command -v rustup >/dev/null 2>&1; then
  CARGO=(rustup run stable cargo)
else
  CARGO=(cargo)
fi

if [[ -z "${IICP_TEST_DATABASE_URL:-}" ]]; then
  for command in docker python3; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
  done
  CONTAINER="iicp-coverage-$RANDOM-$$"
  password="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
  docker run --detach --name "$CONTAINER" \
    --env "MYSQL_ROOT_PASSWORD=$password" --env MYSQL_DATABASE=iicp \
    --publish 127.0.0.1::3306 "$MYSQL_IMAGE" >/dev/null
  ready=false
  for _ in $(seq 1 120); do
    if docker exec "$CONTAINER" mysqladmin ping "-p$password" --silent >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 0.5
  done
  [[ "$ready" == true ]] || { echo "disposable MySQL did not become ready" >&2; exit 1; }
  sleep 2
  port="$(docker port "$CONTAINER" 3306/tcp | awk -F: 'NR == 1 {print $NF}')"
  export IICP_TEST_DATABASE_URL="mysql://root:$password@127.0.0.1:$port/iicp?ssl-mode=DISABLED"
fi

cd "$ROOT"
"${CARGO[@]}" llvm-cov clean --workspace
"${CARGO[@]}" llvm-cov --locked --no-report
"${CARGO[@]}" llvm-cov --locked --no-report -- --ignored --test-threads=1
"${CARGO[@]}" llvm-cov report --summary-only --fail-under-lines 70

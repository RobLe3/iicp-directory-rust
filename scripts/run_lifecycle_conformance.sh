#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run the released lifecycle profile against a disposable MySQL-backed directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${IICP_DISPOSABLE_CARGO_ACTIVE:-0}" != 1 ]]; then
  exec "$ROOT/scripts/with_disposable_cargo_target.sh" --label directory-lifecycle -- "$0" "$@"
fi
SPEC_REPO="${IICP_SPEC_REPO:-$ROOT/../IICP}"
CONFORMANCE_REF="${IICP_CONFORMANCE_REF:-v1.10.8}"
MYSQL_IMAGE="${IICP_MYSQL_IMAGE:-mysql@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b}"
PROFILE="directory-lifecycle-v1"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/iicp-rust-lifecycle.XXXXXX")"
CONTAINER="iicp-lifecycle-$RANDOM-$$"
SERVER_PID=""
umask 077

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  docker stop "$CONTAINER" >/dev/null 2>&1 || true
  python3 - "$CONTAINER" "$TMP" <<'PY'
import shutil
import subprocess
import sys
subprocess.run(
    ["docker", "container", "rm", "--volumes", sys.argv[1]],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
shutil.rmtree(sys.argv[2], ignore_errors=True)
PY
}
trap cleanup EXIT

for command in cargo curl docker git python3 tar; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done
[[ -d "$SPEC_REPO/.git" ]] || { echo "missing IICP specification checkout" >&2; exit 2; }
git -C "$SPEC_REPO" rev-parse --verify "refs/tags/$CONFORMANCE_REF" >/dev/null

python3 - <<'PY'
import socket
sock = socket.socket()
try:
    sock.bind(("127.0.0.1", 8090))
except OSError as error:
    raise SystemExit("port 8090 is already in use") from error
finally:
    sock.close()
PY

cd "$ROOT"
cargo test --locked register_non_routable_endpoint_is_422_in_prod >"$TMP/ssrf-test.log" 2>&1
cargo build --locked --quiet

MYSQL_PASSWORD="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)"
cat >"$TMP/mysql.env" <<EOF
MYSQL_ROOT_PASSWORD=$MYSQL_PASSWORD
MYSQL_DATABASE=iicp
EOF
docker run --detach --name "$CONTAINER" --env-file "$TMP/mysql.env" \
  --label local.docker.lifecycle=ephemeral --label local.docker.owner=iicp-directory-rust/run_lifecycle_conformance \
  --publish 127.0.0.1::3306 "$MYSQL_IMAGE" >/dev/null

mysql_ready=false
for _ in $(seq 1 120); do
  if docker exec "$CONTAINER" mysqladmin ping "-p$MYSQL_PASSWORD" --silent >/dev/null 2>&1; then
    mysql_ready=true
    break
  fi
  sleep 0.5
done
[[ "$mysql_ready" == true ]] || { echo "disposable MySQL did not become ready" >&2; exit 1; }
# mysqladmin runs inside the container; allow the published host socket to finish
# accepting authenticated connections before the one-shot directory startup.
sleep 2
MYSQL_PORT="$(docker port "$CONTAINER" 3306/tcp | awk -F: 'NR == 1 {print $NF}')"

export APP_ENV=testing IICP_SKIP_LIVENESS_CHECK=true
export DATABASE_URL="mysql://root:$MYSQL_PASSWORD@127.0.0.1:$MYSQL_PORT/iicp?ssl-mode=DISABLED"
"${CARGO_TARGET_DIR:?missing disposable Cargo target}/debug/iicp-directory-rs" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!

server_ready=false
for _ in $(seq 1 100); do
  if curl --fail --silent --show-error http://127.0.0.1:8090/api/v1/stats >/dev/null 2>&1; then
    server_ready=true
    break
  fi
  sleep 0.2
done
[[ "$server_ready" == true ]] || { echo "disposable Rust directory did not become ready" >&2; exit 1; }

git -C "$SPEC_REPO" archive "$CONFORMANCE_REF" conformance-runner | tar -x -C "$TMP"
python3 -m venv "$TMP/venv"
"$TMP/venv/bin/pip" install --quiet --disable-pip-version-check "$TMP/conformance-runner"
"$TMP/venv/bin/iicp-conformance" run \
  --profile "$PROFILE" \
  --target http://127.0.0.1:8090 \
  --output "$TMP/result.json"
"$TMP/venv/bin/iicp-conformance" verify "$TMP/result.json" >/dev/null

python3 - "$TMP/result.json" "$CONFORMANCE_REF" <<'PY'
import json
import sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {"total": 6, "passed": 6, "failed": 0}
if result.get("profile") != "directory-lifecycle-v1" or result.get("summary") != expected:
    raise SystemExit("lifecycle conformance failed")
print(json.dumps({
    "implementation": "rust",
    "profile": result["profile"],
    "suite_version": result["suite_version"],
    "fixture_digest": result["fixture_digest"],
    "summary": result["summary"],
    "specification_ref": sys.argv[2],
    "content_free": True,
}, sort_keys=True))
PY

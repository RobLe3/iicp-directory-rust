#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Disposable, content-free Rust operator distribution evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_REF="${IICP_RUST_BASELINE_REF:-main}"
STAMP="$(date -u +%Y%m%dt%H%M%Sz)"
RUN="iicp-rust-distribution-${STAMP}-$$"
REPORT="${IICP_RUST_DISTRIBUTION_REPORT:-${TMPDIR:-/tmp}/${RUN}.json}"
NET="$RUN-net"
DB="$RUN-db"
BASELINE_IMAGE="$RUN-baseline"
CANDIDATE_IMAGE="$RUN-candidate"
SERVICE=""
BASELINE_TREE=""
BASELINE_METRICS=""
CANDIDATE_METRICS=""

cleanup() {
  [[ -z "$SERVICE" ]] || docker rm -f "$SERVICE" >/dev/null 2>&1 || true
  docker rm -fv "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  [[ -z "$BASELINE_TREE" ]] || find "$BASELINE_TREE" -depth -delete 2>/dev/null || true
  [[ -z "$BASELINE_METRICS" ]] || find "$BASELINE_METRICS" -delete 2>/dev/null || true
  [[ -z "$CANDIDATE_METRICS" ]] || find "$CANDIDATE_METRICS" -delete 2>/dev/null || true
}
trap cleanup EXIT

for command in curl docker git python3; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done
git -C "$ROOT" rev-parse --verify "$BASELINE_REF^{commit}" >/dev/null
BASELINE_TREE="$(mktemp -d "${TMPDIR:-/tmp}/iicp-rust-baseline.XXXXXX")"
git -C "$ROOT" archive "$BASELINE_REF" | tar -x -C "$BASELINE_TREE"

docker build -q -t "$BASELINE_IMAGE" "$BASELINE_TREE" >/dev/null
docker build -q -t "$CANDIDATE_IMAGE" "$ROOT" >/dev/null
candidate_user="$(docker image inspect "$CANDIDATE_IMAGE" --format '{{.Config.User}}')"
[[ "$candidate_user" = "10001:10001" ]]
baseline_digest="$(docker image inspect "$BASELINE_IMAGE" --format '{{.Id}}')"
candidate_digest="$(docker image inspect "$CANDIDATE_IMAGE" --format '{{.Id}}')"

docker network create "$NET" >/dev/null
docker run -d --name "$DB" --network "$NET" \
  --label local.docker.lifecycle=ephemeral --label local.docker.owner=iicp-directory-rust/run_distribution_evidence \
  -e MYSQL_DATABASE=iicp -e MYSQL_USER=iicp -e MYSQL_PASSWORD=iicp \
  -e MYSQL_ROOT_PASSWORD=root mysql:8.0 >/dev/null
deadline=$((SECONDS + 90))
until docker exec "$DB" mysqladmin ping -h127.0.0.1 -uroot -proot --silent >/dev/null 2>&1; do
  [[ "$SECONDS" -lt "$deadline" ]] || exit 1
  sleep 2
done

start_service() {
  local image="$1" hardened="$2"
  SERVICE="$RUN-service"
  port="$(python3 - <<'PY'
import socket
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
  local args=(run -d --name "$SERVICE" --network "$NET" -p "127.0.0.1:${port}:8090"
    -e APP_ENV=local -e "DATABASE_URL=mysql://iicp:iicp@${DB}/iicp")
  if [[ "$hardened" = 1 ]]; then
    args+=(--read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,size=16m)
  fi
  docker "${args[@]}" "$image" >/dev/null
  deadline=$((SECONDS + 120))
  until curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; do
    if [[ "$SECONDS" -ge "$deadline" ]]; then
      docker logs "$SERVICE" >&2
      exit 1
    fi
    sleep 2
  done
}

stop_service() {
  docker rm -f "$SERVICE" >/dev/null
  SERVICE=""
}

# Baseline → candidate → baseline → candidate proves schema adoption, rollback,
# and forward recovery without touching production.
start_service "$BASELINE_IMAGE" 0
docker exec "$DB" mysql -uiicp -piicp iicp -e \
  "INSERT INTO dispatch_usage_daily (usage_date, mode, request_count, created_at, updated_at)
   VALUES (UTC_DATE(), 'distribution_gate', 1, NOW(), NOW())
   ON DUPLICATE KEY UPDATE request_count=1" 2>/dev/null
stop_service
start_service "$CANDIDATE_IMAGE" 1
stop_service
start_service "$BASELINE_IMAGE" 0
sentinel="$(docker exec "$DB" mysql -N -uiicp -piicp iicp -e \
  "SELECT request_count FROM dispatch_usage_daily WHERE usage_date=UTC_DATE() AND mode='distribution_gate'" 2>/dev/null)"
[[ "$sentinel" = 1 ]]
stop_service

measure() {
  local image="$1" hardened="$2" output="$3"
  start_service "$image" "$hardened"
  python3 - "http://127.0.0.1:$port" "$output" <<'PY'
import json, statistics, sys, time, urllib.request
base, output = sys.argv[1:]
paths = ("/health", "/api/v1/stats",
         "/api/v1/discover?intent=urn%3Aiicp%3Aintent%3Allm%3Achat%3Av1")
samples, failures = [], 0
for index in range(210):
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(base + paths[index % len(paths)], timeout=10) as response:
            if response.status >= 500:
                failures += 1
            response.read()
    except Exception:
        failures += 1
    if index >= 10:
        samples.append((time.perf_counter() - started) * 1000)
ordered = sorted(samples)
p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
json.dump({"requests": len(samples), "failures": failures, "p50_ms": statistics.median(samples),
           "p95_ms": p95}, open(output, "w"))
PY
  stop_service
}

BASELINE_METRICS="$(mktemp "${TMPDIR:-/tmp}/iicp-baseline-metrics.XXXXXX")"
CANDIDATE_METRICS="$(mktemp "${TMPDIR:-/tmp}/iicp-candidate-metrics.XXXXXX")"
measure "$BASELINE_IMAGE" 0 "$BASELINE_METRICS"
measure "$CANDIDATE_IMAGE" 1 "$CANDIDATE_METRICS"

python3 - "$BASELINE_METRICS" "$CANDIDATE_METRICS" "$REPORT" \
  "$baseline_digest" "$candidate_digest" <<'PY'
import json, pathlib, sys
baseline = json.load(open(sys.argv[1]))
candidate = json.load(open(sys.argv[2]))
assert baseline["failures"] == 0 and candidate["failures"] == 0
limit = baseline["p95_ms"] * 1.10
assert candidate["p95_ms"] <= limit, (baseline, candidate, limit)
report = {
    "schema": "iicp.rust_directory.distribution_evidence.v1",
    "content_free": True,
    "production_accessed": False,
    "baseline_image_digest": sys.argv[4],
    "candidate_image_digest": sys.argv[5],
    "candidate_user": "10001:10001",
    "read_only_root": True,
    "capabilities_dropped": True,
    "no_new_privileges": True,
    "upgrade_verified": True,
    "rollback_verified": True,
    "forward_recovery_verified": True,
    "baseline": baseline,
    "candidate": candidate,
    "p95_regression_limit_percent": 10,
}
path = pathlib.Path(sys.argv[3])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, sort_keys=True))
PY

echo "Rust distribution evidence passed: $REPORT"

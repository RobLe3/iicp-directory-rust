#!/usr/bin/env bash
set -euo pipefail

# Disposable privileged systemd manager used only for recovery evidence. It
# does not install or change a host service.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${IICP_SYSTEMD_EVIDENCE_PLATFORM:-linux/arm64}"
ARCH_TAG="${PLATFORM#linux/}"
ARCH_TAG="${ARCH_TAG//\//-}"
IMAGE="iicp-directory-systemd-evidence:rust-1.88-${ARCH_TAG}"
NAME="iicp-directory-systemd-evidence-$$"
OUTPUT="${1:-$ROOT/target/systemd-watchdog-evidence.json}"

docker build --platform "$PLATFORM" -t "$IMAGE" "$ROOT/ops/systemd-evidence"
docker run --detach --rm --privileged --platform "$PLATFORM" \
  --name "$NAME" \
  --tmpfs /run --tmpfs /run/lock \
  -v "iicp-rust-${ARCH_TAG}-cargo:/usr/local/cargo/registry" \
  -v "iicp-rust-${ARCH_TAG}-target:/target" \
  -v "$ROOT:/work" -w /work "$IMAGE" >/dev/null
cleanup() { docker stop "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
for _ in $(seq 1 60); do
  docker exec "$NAME" systemctl is-system-running --wait >/dev/null 2>&1 && break
  sleep 1
done
docker exec -e IICP_SYSTEMD_EVIDENCE_SCOPE=system -e CARGO_TARGET_DIR=/target \
  -e RUST_MIN_STACK=16777216 "$NAME" \
  /work/scripts/validate_systemd_watchdog.sh /tmp/evidence.json
mkdir -p "$(dirname "$OUTPUT")"
docker cp "$NAME:/tmp/evidence.json" "$OUTPUT"
echo "isolated systemd evidence: $OUTPUT"

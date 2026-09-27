#!/usr/bin/env bash
# Prove PHP -> Rust -> PHP restricted-membership database compatibility.
# The database must be disposable. Credential output is consumed, never logged.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${IICP_CROSS_FLAVOR_RUST_BINARY:-}" && "${IICP_DISPOSABLE_CARGO_ACTIVE:-0}" != 1 ]]; then
  exec "$ROOT/scripts/with_disposable_cargo_target.sh" --label cross-flavor-membership -- "$0" "$@"
fi
cd "$ROOT"

# An installed-artifact diagnostic must not silently fall back to cargo run.
# The caller supplies immutable bytes and expected self-report; these are
# diagnostic inputs, not qualification or release authorization.
rust_command=(cargo run --locked --quiet --)
if [[ -n "${IICP_CROSS_FLAVOR_RUST_BINARY:-}" ]]; then
  : "${IICP_CROSS_FLAVOR_RUST_SHA256:?set the installed Rust binary SHA256}"
  : "${IICP_CROSS_FLAVOR_RUST_VERSION:?set the installed Rust version}"
  python3 - "$IICP_CROSS_FLAVOR_RUST_BINARY" "$IICP_CROSS_FLAVOR_RUST_SHA256" "$IICP_CROSS_FLAVOR_RUST_VERSION" <<'PYCODE'
import hashlib, pathlib, re, subprocess, sys
binary, expected, version = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
if (not binary.is_absolute() or binary.is_symlink() or not binary.is_file()
        or any(p.is_symlink() for p in binary.parents)
        or binary.stat().st_size > 256 * 1024 * 1024
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected)
        or not re.fullmatch(r"0\.1\.[0-9]+", version)):
    raise SystemExit("invalid installed cross-flavor binary boundary")
observed = "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest()
if observed != expected:
    raise SystemExit("installed cross-flavor binary digest differs")
result = subprocess.run([str(binary), "--version"], capture_output=True, timeout=10, check=False,
    env={"PATH": "/usr/bin:/bin"})
if result.returncode or result.stdout.strip() != ("iicp-directory-rs " + version).encode():
    raise SystemExit("installed cross-flavor binary version differs")
PYCODE
  rust_command=("$IICP_CROSS_FLAVOR_RUST_BINARY")
fi

: "${PHP_DIRECTORY_ROOT:?set PHP_DIRECTORY_ROOT to the reviewed PHP directory checkout}"
: "${IICP_CROSS_FLAVOR_DATABASE_URL:?set the Rust URL for the disposable MySQL database}"
: "${IICP_CROSS_FLAVOR_DB_NAME:?set the disposable database name}"
: "${MYSQL_HOST:=127.0.0.1}"
: "${MYSQL_PORT:=3306}"
: "${MYSQL_USER:=root}"
: "${MYSQL_PASSWORD:=}"

[[ "$IICP_CROSS_FLAVOR_DB_NAME" =~ ^iicp_cross_[a-z0-9_]{1,48}$ ]] || {
  echo "refusing unsafe or non-disposable database name" >&2
  exit 2
}
[ -f "$PHP_DIRECTORY_ROOT/artisan" ] || { echo "PHP directory checkout is invalid" >&2; exit 2; }

mysql_cmd=(mysql --protocol=TCP --host="$MYSQL_HOST" --port="$MYSQL_PORT" --user="$MYSQL_USER" --batch --skip-column-names)
export MYSQL_PWD="$MYSQL_PASSWORD"
cleanup() {
  "${mysql_cmd[@]}" -e "DROP DATABASE IF EXISTS $IICP_CROSS_FLAVOR_DB_NAME" >/dev/null 2>&1
}
finish() {
  status=$?
  trap - EXIT
  if cleanup; then
    echo "cross-flavor database cleanup verified"
  else
    echo "cross-flavor database cleanup failed; run remains incomplete" >&2
    if [[ "$status" == 0 ]]; then status=1; fi
  fi
  exit "$status"
}
trap finish EXIT

cleanup
"${mysql_cmd[@]}" -e "CREATE DATABASE $IICP_CROSS_FLAVOR_DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"

(
  cd "$PHP_DIRECTORY_ROOT"
  APP_ENV=testing \
  DB_CONNECTION=mysql DB_HOST="$MYSQL_HOST" DB_PORT="$MYSQL_PORT" \
  DB_DATABASE="$IICP_CROSS_FLAVOR_DB_NAME" DB_USERNAME="$MYSQL_USER" \
  DB_PASSWORD="$MYSQL_PASSWORD" \
  php artisan migrate --force --no-interaction >/dev/null
)

# The Rust verifier must accept the PHP-owned schema without mutating it.
DATABASE_URL="$IICP_CROSS_FLAVOR_DATABASE_URL" \
  "${rust_command[@]}" db-maintenance-status --json >/dev/null

common_env=(
  IICP_RESTRICTED_DOMAIN_ENABLED=true
  IICP_TRUST_DOMAIN_ID=example.test
  IICP_TRUST_DOMAIN_AUTHORITY_ID=did:key:cross-flavor-authority
  DATABASE_URL="$IICP_CROSS_FLAVOR_DATABASE_URL"
)

# Consume the one-time bearer value without printing, persisting or exporting it.
env "${common_env[@]}" "${rust_command[@]}" \
  trust-domain-membership-issue --kind node --subject node-cross-flavor \
  --scopes registration,discovery,bootstrap --ttl-seconds 3600 |
  python3 -c 'import sys; value=sys.stdin.read().strip(); raise SystemExit(0 if value and "\n" not in value else 1)'

active=$("${mysql_cmd[@]}" "$IICP_CROSS_FLAVOR_DB_NAME" -e \
  "SELECT COUNT(*) FROM trust_domain_memberships WHERE domain_id='example.test' AND subject_id='node-cross-flavor' AND revoked_at IS NULL")
[ "$active" = "1" ] || { echo "Rust-issued membership is not visible in the PHP schema" >&2; exit 1; }

env "${common_env[@]}" "${rust_command[@]}" \
  trust-domain-membership-revoke --kind node --subject node-cross-flavor >/dev/null

revoked=$("${mysql_cmd[@]}" "$IICP_CROSS_FLAVOR_DB_NAME" -e \
  "SELECT COUNT(*) FROM trust_domain_memberships WHERE domain_id='example.test' AND subject_id='node-cross-flavor' AND revoked_at IS NOT NULL")
[ "$revoked" = "1" ] || { echo "Rust revocation is not preserved in the PHP schema" >&2; exit 1; }

# A runtime rollback to PHP must recognize its migration history and retained row.
(
  cd "$PHP_DIRECTORY_ROOT"
  APP_ENV=testing \
  DB_CONNECTION=mysql DB_HOST="$MYSQL_HOST" DB_PORT="$MYSQL_PORT" \
  DB_DATABASE="$IICP_CROSS_FLAVOR_DB_NAME" DB_USERNAME="$MYSQL_USER" \
  DB_PASSWORD="$MYSQL_PASSWORD" \
  php artisan migrate:status --no-interaction >/dev/null
)

# Mixed restricted/federated configuration must fail before serving traffic.
set +e
mixed_output=$(env "${common_env[@]}" APP_ENV=testing IICP_REPLICA_MODE=true \
  IICP_SEED_URL=https://invalid.example \
  IICP_SEED_DID=did:web:seed.invalid.example \
  IICP_REPLICA_DID=did:web:replica.invalid.example \
  IICP_REPLICA_ENDPOINT=https://replica.invalid.example \
  timeout 15 "${rust_command[@]}" 2>&1)
mixed_status=$?
set -e
[ "$mixed_status" -ne 0 ] || { echo "mixed restricted/replica startup unexpectedly succeeded" >&2; exit 1; }
printf '%s' "$mixed_output" | grep -Fq \
  'restricted trust-domain federation is not implemented; replica mode cannot be combined with restricted-domain mode' || {
  echo "mixed-version refusal did not expose the expected fail-closed reason" >&2
  exit 1
}

echo "cross-flavor membership checks passed (cleanup pending): PHP migrate, Rust verify/issue/revoke, PHP resume, mixed-mode refusal"

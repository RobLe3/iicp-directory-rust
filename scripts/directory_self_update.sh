#!/usr/bin/env bash
set -euo pipefail

# Guarded operator-preview updater. It verifies crates.io's immutable checksum
# against the release manifest before installing, verifies the existing schema
# with the candidate, and rolls the stable symlink back when service health fails.

PACKAGE="iicp-directory-rs"
API="${IICP_DIRECTORY_CRATES_API:-https://crates.io/api/v1/crates/$PACKAGE}"
ROOT="${IICP_DIRECTORY_RELEASE_ROOT:-$HOME/.local/share/iicp-directory-rs}"
STABLE_BIN="${IICP_DIRECTORY_STABLE_BIN:-$HOME/.local/bin/iicp-directory-rs}"
SERVICE="iicp-directory-rs.service"
HEALTH_URL="${IICP_DIRECTORY_HEALTH_URL:-http://127.0.0.1:8090/health}"
MODE=""
ENV_FILE=""
DRY_RUN=0

usage() {
  cat <<'EOF'
usage: directory_self_update.sh --check | --staged --env-file ABSOLUTE_PATH [options]
       directory_self_update.sh --install-timer --env-file ABSOLUTE_PATH [--dry-run]
       directory_self_update.sh --remove-timer [--dry-run]

  --check             read-only crates.io version check
  --staged            verified install, schema check, service restart and rollback
  --env-file PATH     environment used for the candidate schema verification
  --service NAME      systemd user unit (default iicp-directory-rs.service)
  --health-url URL    local post-restart health URL
  --dry-run           report planned mutation without changing the host
  --install-timer     install a disabled-by-default daily user timer
  --remove-timer      disable and remove the updater timer
EOF
}

while (($#)); do
  case "$1" in
    --check|--staged|--install-timer|--remove-timer) MODE="$1" ;;
    --env-file) shift; ENV_FILE="${1:-}" ;;
    --service) shift; SERVICE="${1:-}" ;;
    --health-url) shift; HEALTH_URL="${1:-}" ;;
    --dry-run) DRY_RUN=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[[ -n "$MODE" ]] || { usage >&2; exit 2; }

timer_service="$HOME/.config/systemd/user/iicp-directory-update.service"
timer_unit="$HOME/.config/systemd/user/iicp-directory-update.timer"
if [[ "$MODE" == "--install-timer" || "$MODE" == "--remove-timer" ]]; then
  if [[ "$MODE" == "--install-timer" ]]; then
    [[ "$ENV_FILE" = /* && -f "$ENV_FILE" ]] || { echo "--install-timer requires an existing absolute --env-file" >&2; exit 2; }
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    service_content="[Unit]
Description=Check and stage an IICP Rust directory update
After=network-online.target

[Service]
Type=oneshot
ExecStart=\"$script_path\" --staged --env-file \"$ENV_FILE\"
"
    timer_content="[Unit]
Description=Daily guarded IICP Rust directory update

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1800

[Install]
WantedBy=timers.target
"
    if ((DRY_RUN)); then
      printf '# %s\n%s# %s\n%s' "$timer_service" "$service_content" "$timer_unit" "$timer_content"
    else
      mkdir -p "$(dirname "$timer_unit")"
      printf '%s' "$service_content" > "$timer_service"
      printf '%s' "$timer_content" > "$timer_unit"
      systemctl --user daemon-reload
      systemctl --user enable --now "$(basename "$timer_unit")"
    fi
  else
    if ((DRY_RUN)); then
      echo "would disable and remove $timer_unit and $timer_service"
    else
      systemctl --user disable --now "$(basename "$timer_unit")" || true
      rm -f "$timer_unit" "$timer_service"
      systemctl --user daemon-reload
    fi
  fi
  exit 0
fi

current="$($STABLE_BIN --version 2>/dev/null | awk '{print $2}' || true)"
api_file="$(mktemp)"
api_status="$(curl --silent --show-error -A 'iicp-directory-rs guarded updater' \
  -o "$api_file" -w '%{http_code}' "$API")"
if [[ "$api_status" == "404" ]]; then
  rm -f "$api_file"
  if [[ "$MODE" == "--check" ]]; then
    printf 'package=%s current=%s published=not-published\n' "$PACKAGE" "${current:-not-installed}"
    exit 0
  fi
  echo "$PACKAGE is not published on crates.io" >&2
  exit 1
fi
[[ "$api_status" == "200" ]] || { echo "crates.io lookup returned HTTP $api_status" >&2; rm -f "$api_file"; exit 1; }
api_json="$(cat "$api_file")"
rm -f "$api_file"
read -r latest checksum < <(python3 -c '
import json,re,sys
p=json.load(sys.stdin)
stable=re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)").fullmatch
versions=[v for v in p.get("versions",[]) if not v.get("yanked") and stable(v.get("num", ""))]
if not versions: raise SystemExit("no non-yanked stable release")
def key(v): return tuple(int(x) for x in v["num"].split("."))
v=max(versions,key=key)
print(v["num"], v["checksum"])
' <<<"$api_json")

if [[ "$MODE" == "--check" ]]; then
  printf 'package=%s current=%s published=%s\n' "$PACKAGE" "${current:-not-installed}" "$latest"
  exit 0
fi

[[ "$ENV_FILE" = /* && -f "$ENV_FILE" ]] || {
  echo "--staged requires an existing absolute --env-file" >&2
  exit 2
}
if [[ "$current" == "$latest" ]]; then
  echo "$PACKAGE $latest already installed"
  exit 0
fi

release="v$latest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
crate="$work/$PACKAGE-$latest.crate"
manifest="$work/release-manifest.json"
crate_url="${IICP_DIRECTORY_CRATE_URL:-https://crates.io/api/v1/crates/$PACKAGE/$latest/download}"
manifest_url="${IICP_DIRECTORY_RELEASE_MANIFEST_URL:-https://github.com/RobLe3/iicp-directory-rust/releases/download/$release/release-manifest.json}"
curl --fail --location --silent --show-error -A 'iicp-directory-rs guarded updater' -o "$crate" "$crate_url"
curl --fail --location --silent --show-error -A 'iicp-directory-rs guarded updater' -o "$manifest" "$manifest_url"
actual="$(shasum -a 256 "$crate" | awk '{print $1}')"
manifest_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["crate_sha256"])' "$manifest")"
manifest_version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$manifest")"
[[ "$actual" == "$checksum" && "$actual" == "$manifest_sha" && "$manifest_version" == "$latest" ]] || {
  echo "release checksum/version binding failed" >&2
  exit 1
}
crate_commit="$(tar -xOf "$crate" "$PACKAGE-$latest/.cargo_vcs_info.json" | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["git"]["sha1"])')"
manifest_commit="$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); assert p["status"]=="operator_preview"; assert p["production_authority"] is False; assert p["genesis_cutover_authorized"] is False; print(p["commit"])' "$manifest")"
[[ "$crate_commit" =~ ^[0-9a-f]{40}$ && "$crate_commit" == "$manifest_commit" ]] || {
  echo "release source-commit/authority binding failed" >&2
  exit 1
}

if ((DRY_RUN)); then
  echo "verified $PACKAGE $latest ($actual); would install, verify schema, switch, restart and health-check"
  exit 0
fi

mkdir -p "$ROOT/releases/$latest" "$(dirname "$STABLE_BIN")"
tar -xzf "$crate" -C "$work"
cargo install --locked --path "$work/$PACKAGE-$latest" --root "$ROOT/releases/$latest"
candidate="$ROOT/releases/$latest/bin/$PACKAGE"

# Source only the operator-selected local file. Values are never printed.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
"$candidate" db-maintenance-status --json >/dev/null

previous=""
if [[ -L "$STABLE_BIN" ]]; then
  previous="$(readlink "$STABLE_BIN")"
elif [[ -e "$STABLE_BIN" ]]; then
  echo "$STABLE_BIN exists but is not a managed symlink; refusing mutation" >&2
  exit 1
fi
ln -sfn "$candidate" "$STABLE_BIN"
if ! systemctl --user restart "$SERVICE" || \
   ! curl --fail --silent --show-error "$HEALTH_URL" | \
      python3 -c 'import json,sys; p=json.load(sys.stdin); assert p.get("ok") is True; assert sys.argv[1] in p.get("version","")' "$latest"; then
  echo "candidate verification failed; rolling back" >&2
  if [[ -n "$previous" ]]; then
    ln -sfn "$previous" "$STABLE_BIN"
    systemctl --user restart "$SERVICE" || true
  else
    rm -f "$STABLE_BIN"
  fi
  exit 1
fi
echo "updated $PACKAGE to $latest; previous=${current:-none}"

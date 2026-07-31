#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Supervise an operator-preview Rust replica behind a disposable Quick Tunnel.
# Secrets are read from one external mode-0600 env file and never passed as argv.
set -eu

ENV_FILE=${IICP_SHADOW_ENV_FILE:?set IICP_SHADOW_ENV_FILE to an external mode-0600 file}
[ -f "$ENV_FILE" ] || { echo "shadow env file not found" >&2; exit 1; }
mode=$(stat -f '%Lp' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE")
[ "$mode" = 600 ] || { echo "shadow env file must have mode 0600" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

: "${IICP_REPLICA_DID:?missing IICP_REPLICA_DID}"
: "${IICP_SHADOW_STABLE_HOST:?missing IICP_SHADOW_STABLE_HOST}"
: "${CLOUDFLARE_API_TOKEN:?missing CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ZONE_ID:?missing CLOUDFLARE_ZONE_ID}"
: "${DATABASE_URL:?missing DATABASE_URL}"
: "${APP_KEY:?missing APP_KEY}"
: "${IICP_GENESIS_ED25519_SECRET_KEY:?missing signing key}"
[ "$IICP_REPLICA_DID" = "did:web:$IICP_SHADOW_STABLE_HOST" ] || {
  echo "replica DID must match the stable shadow host" >&2; exit 1;
}

CLOUDFLARED=${CLOUDFLARED_BIN:-$(command -v cloudflared)}
DIRECTORY=${IICP_DIRECTORY_BIN:-$(command -v iicp-directory-rs)}
PORT=${IICP_SHADOW_LOCAL_PORT:-8090}
TMP=${TMPDIR:-/tmp}/iicp-rust-shadow.$$
mkdir -m 700 "$TMP"
cleanup() {
  [ -n "${directory_pid:-}" ] && kill "$directory_pid" 2>/dev/null || true
  [ -n "${tunnel_pid:-}" ] && kill "$tunnel_pid" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM HUP

"$CLOUDFLARED" tunnel --no-autoupdate --url "http://127.0.0.1:$PORT" >"$TMP/tunnel.log" 2>&1 &
tunnel_pid=$!
endpoint=
i=0
while [ "$i" -lt 120 ]; do
  endpoint=$(sed -nE 's#.*(https://[a-z0-9-]+\.trycloudflare\.com).*#\1#p' "$TMP/tunnel.log" | head -1)
  [ -n "$endpoint" ] && break
  kill -0 "$tunnel_pid" 2>/dev/null || { echo "cloudflared exited before publishing an endpoint" >&2; exit 1; }
  i=$((i + 1)); sleep 1
done
[ -n "$endpoint" ] || { echo "Quick Tunnel endpoint was not observed" >&2; exit 1; }
tunnel_host=${endpoint#https://}
export IICP_REPLICA_ENDPOINT=$endpoint
export IICP_DIRECTORY_DID=$IICP_REPLICA_DID
export IICP_DIRECTORY_ENDPOINT="https://$IICP_SHADOW_STABLE_HOST/v1"
export IICP_SHADOW_TUNNEL_HOST=$tunnel_host

python3 - <<'PY'
import json, os, urllib.parse, urllib.request
zone=os.environ['CLOUDFLARE_ZONE_ID']; token=os.environ['CLOUDFLARE_API_TOKEN']
name=os.environ['IICP_SHADOW_STABLE_HOST']; target=os.environ['IICP_SHADOW_TUNNEL_HOST']
base=f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"
headers={'Authorization':f'Bearer {token}','Content-Type':'application/json'}
query=base+'?'+urllib.parse.urlencode({'type':'CNAME','name':name})
with urllib.request.urlopen(urllib.request.Request(query, headers=headers), timeout=15) as response:
    result=json.load(response)
records=result.get('result') or []
payload=json.dumps({'type':'CNAME','name':name,'content':target,'proxied':True,'ttl':1}).encode()
url=f"{base}/{records[0]['id']}" if records else base
method='PUT' if records else 'POST'
with urllib.request.urlopen(urllib.request.Request(url, data=payload, headers=headers, method=method), timeout=15) as response:
    changed=json.load(response)
if not changed.get('success'):
    raise SystemExit('Cloudflare DNS update failed')
PY

"$DIRECTORY" &
directory_pid=$!
wait "$directory_pid"

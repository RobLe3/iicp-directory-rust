# Persistent Rust shadow evidence

This procedure prepares operational evidence for the Rust directory without
making it Genesis authority. It does not authorize a deployment, production
database change, PHP deprecation or cutover.

## Isolation contract

The shadow must use its own MySQL database, database account, APP key, Ed25519
signing identity, DID, replica registration and external port. Do not clone the
Genesis database or reuse any Genesis secret. Start from the immutable `v0.1.5`
release assets and verify their published checksums before installation.

Copy `ops/shadow.env.example` to a location outside every repository, set mode
`0600`, and replace every `REQUIRED_...` value. Production must not define
`IICP_DEV_ALLOW_INSECURE_TLS` or `IICP_DEV_ALLOW_UNSIGNED_EVENTS`.

The binary listens on container port 8090. Bind that port to a distinct
loopback or shadow-only host port; a reverse proxy may expose the separately
approved replica endpoint. Do not reuse the Genesis virtual host.

## Preflight and rollback

1. Create a new empty shadow database and an encrypted off-host backup target.
2. Verify the release archive, release manifest and `SHA256SUMS`.
3. Run `./scripts/check_quality.sh` and `./ops/run_distribution_evidence.sh`.
4. Start the release with the external environment file and hardened container
   settings from `OPERATIONS.md`.
5. Require `/health`, `/iicp/health`, `/api/v1/stats`, public discovery and the signed
   deployment record to succeed. Confirm writes redirect to Genesis.
   Confirm the DID document, deployment record and signed event responses all
   identify `did:web:rust-shadow.iicp.network`; a rotating Quick Tunnel is an
   endpoint only and must never become the directory identity.
6. Stop and restart the shadow. A new replica handshake must rotate the
   snapshot credential while event replay remains signature-verified.
7. Restore only into a fresh disposable database. Never test restoration over
   the running shadow.

Rollback first calls authenticated `POST /api/v1/replicas/deregister`, then
means stopping the Rust shadow, removing it from routing and replica
presentation, retaining the database for the reviewed evidence period, and
returning clients to PHP Genesis. It never means rolling the Genesis schema
back to a Rust schema.

Quick Tunnel availability is operator-preview evidence only. It cannot satisfy
an independent-host, stable-endpoint, federation, or Genesis-cutover gate.

### Local macOS Quick Tunnel supervisor

`ops/run_quick_tunnel_shadow.sh` starts a disposable tunnel, updates only the
configured stable shadow CNAME, then launches the directory with the rotating
tunnel URL as `IICP_REPLICA_ENDPOINT`. If either child exits, launchd restarts
the pair and the directory re-registers the same stable DID with a rotated
bearer. The script refuses env files that are not mode `0600`; credentials are
read from that external file and are never passed as command arguments.

Copy `ops/network.iicp.directory-rust-shadow.plist.example` outside the
repository, replace its three `REQUIRED_...` paths, install it under
`~/Library/LaunchAgents`, and validate it with `plutil -lint` before loading.
Use `launchctl kickstart -k gui/$(id -u)/network.iicp.directory-rust-shadow`
for an intentional restart. Do not run a second ad-hoc tunnel alongside it.

## Content-free comparison

Before any persistent shadow is authorized, run the public, read-only preflight:

```bash
python3 -c 'import cryptography' # required for Ed25519 verification
python3 ops/assess_prod_seed.py \
  --output /tmp/iicp-rust-public-seed-assessment.json
```

The preflight verifies the retained signed event stream and attempts to reconstruct
the public node set without registering a replica or fetching an authenticated
snapshot. Historical unsigned events are counted but never applied. If the public
stream cannot reconstruct current state, retain the content-free negative result and
stop: replica registration and snapshot access require a separate production-write
authorization.

Use `AUTHENTICATED_SNAPSHOT_PREFLIGHT.md` for that authorization boundary. A
configured replica must obtain and validate the authenticated snapshot before
applying newer signed events; it must not silently substitute an incomplete
public-tail reconstruction.

Run the observer from a trusted operator host:

```bash
python3 ops/compare_shadow.py \
  --shadow-base https://shadow-directory.example \
  --samples 12 \
  --interval 300 \
  --output /tmp/iicp-rust-shadow-comparison.json
```

The report retains only response field names, aggregate counts, timings and
parity outcomes. It never stores endpoints, node IDs, route metadata, keys,
tokens, payloads or result rows. Public discovery fails the comparison if any
route-bearing field appears.

## Seven-day observation gate

Starting this window requires explicit maintainer authorization. During the
window:

- run the complete REACH suite against the shadow after startup, restart and
  credential rotation;
- run the comparison observer at a fixed interval;
- record process availability, event lag and restart recovery only as
  aggregates;
- treat any signature failure, unauthorized snapshot, unexplained node-count
  divergence, route disclosure or schema mismatch as a failed window.

The milestone passes only after seven continuous days with no unresolved
semantic divergence, successful restart and token-rotation recovery, a tested
production-specific rollback procedure, and a separate cutover decision.

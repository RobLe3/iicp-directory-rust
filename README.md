# IICP Directory — Rust operator preview

Rust implementation of the IICP directory control plane.

The protocol is defined by the public [IICP specification](https://github.com/RobLe3/IICP).
This repository owns the Rust implementation, not the protocol, website,
production deployment, or Genesis Seed credentials and data.

This makes the directory an intent-resolution and provider-eligibility control
plane, not a task-execution protocol or universal agent runtime. MCP, A2A, HTTP
or another negotiated binding may execute after selection. See the public
[protocol positioning](https://github.com/RobLe3/IICP/blob/main/standards/IICP_PROTOCOL_POSITIONING.md)
and [adjacent-protocol comparison](https://github.com/RobLe3/IICP/blob/main/standards/PROTOCOL_COMPARISON_2026-08-15.md).

Release compatibility and the PHP transition boundary are defined in
[`RELEASE_POLICY.md`](RELEASE_POLICY.md).

**Status:** Rust is the second official implementation flavor of the IICP
directory contract and is published as a pre-1.0 operator preview. PHP remains
the deployed Genesis flavor. Rust is not a cutover-ready production
replacement: persistent REACH, production rollback and explicit cutover
approval remain separate gates. See [`PARITY.md`](PARITY.md) and the versioned
parity fixtures before making an operational-equivalence claim.

The protocol and versioned behavior contracts are implementation-neutral.
PHP/Laravel remains the production seed today; Rust is the intended long-term
maintained flavor and must pass the same REACH/live conformance probes before
it can own production traffic.

## What is covered now

- `/api/v1/stats`, `/api/v1/discover`, `/api/v1/bootstrap`, `/api/v1/node/{id}` and `/api/v1/me`
- `/api/v1/register`, `/api/v1/heartbeat`, `/api/v1/peers`, `/api/v1/operator/rename`
- `/api/v1/registry/nodes`, `/api/v1/registry/nodes/{id}`, `/api/v1/registry/intents`, `/api/v1/registry/stats`
- `/api/v1/credits/balance`, `/api/v1/credits/summary`, `/api/v1/credits/transactions`, `/api/v1/credits/quote`, `/api/v1/credits/award`
- `/api/v1/conformance/badges`, `/api/v1/conformance/submit`, `/api/v1/conformance/verify`, `/api/v1/badge/{tier}`
- `/api/v1/events`, `/api/v1/snapshot`, `/api/v1/replicas/register`
- `/api/v1/directory-key`, `/api/v1/consumer-token`, `/api/v1/relay/ticket`
- `/api/v1/compliance-attestation`, `/api/v1/audit-report`, `/api/v1/telemetry`, `/api/v1/telemetry/probe`, `/api/v1/probe`
- `/.well-known/did.json` and `/.well-known/iicp-replicas.json`

`/api/v1/discover` also emits the live PHP compatibility fields that current clients and the website expect: `cx_public_key`/`public_key`, `key_ready`, `privacy_routing_status`, `sdk_status`, `sdk_baseline_version`, `auto_update`, `backend_stability`, `trust_progress`, `route_evidence`, `routing_hint`, `browser_usable`, `directory_observed_reachable`, `capability_summary`, `input_modalities`, `pricing` and `performance`.

## Important caveats

- The compliance-attestation route is present and signs a compact Rust attestation when a directory signing key is configured. The PHP production seed still owns the full REACH-backed attestation evidence.
- Rust keeps `/v1/*` for existing Rust consumers and adds `/api/v1/*` for PHP/live compatibility.
- API route parity does not automatically mean operational parity. Production replacement still requires the same live REACH probes, deployment runbooks, cache behavior, background jobs and operator procedures to pass.
- The PHP directory is still the source of truth for production until the maintainer explicitly cuts over.

## Why a Rust implementation

The PHP directory is the current production implementation. The Rust flavor
provides a single typed binary for operators who prefer that deployment model.
Its routing, persistence and security behavior remains accountable to the same
public contracts and conformance evidence as PHP.

Migration path:

```text
PHP Genesis → dual supported flavors → Rust Genesis → PHP maintenance retirement
```

## Requirements

- Rust 1.88 or newer
- MySQL 8 / MariaDB 11 for durable operation

## Run

### Local, in memory

```bash
APP_ENV=local IICP_ALLOW_IN_MEMORY=true cargo run
cargo test --locked
```

The server listens on `0.0.0.0:8090`. In-memory storage is available only when
`APP_ENV` is not `production` and `IICP_ALLOW_IN_MEMORY=true` is explicit.
Production startup fails when `DATABASE_URL` is absent.

### With MySQL

```bash
export DATABASE_URL="mysql://user:pass@localhost/iicp_directory"
cargo run
```

An empty database is bootstrapped from the embedded baseline schema. An
existing database is verified and startup fails on incompatible state; the
binary does not silently apply the incremental files under `migrations/`.
Review and back up before any operator-managed migration.

### User-level systemd service

Install the service from the exact binary you intend to run. Keep the
environment file outside the repository and readable only by its owner.

```bash
iicp-directory-rs service install --env-file /absolute/path/directory.env
iicp-directory-rs service status
```

The default service uses `Restart=always`, but leaves the native systemd
watchdog disabled. `--notify` enables readiness notification. A measured
watchdog interval can be supplied separately with `--watchdog-sec`; the
installer never guesses one. User lingering remains an explicit operator
decision.

The running process also writes a mode-0600 local health snapshot. Inspect
local liveness without changing the existing `/iicp/health` wire behavior:

```bash
iicp-directory-rs healthcheck --json
```

See [`OPERATIONS.md`](OPERATIONS.md) for staged updates and rollback.

For a durable installation, backup and recovery guidance, read
[`OPERATIONS.md`](OPERATIONS.md). In-memory mode is for local evaluation only.

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `DATABASE_URL` | — | MySQL DSN. Required in production. |
| `IICP_DB_POOL_MAX_CONNECTIONS` | `10` | Maximum MySQL pool size. Must be between 1 and 1024. Tune from measured deployment load rather than increasing it to hide saturation. |
| `IICP_DB_POOL_MIN_CONNECTIONS` | `0` | Minimum idle MySQL connections. Must not exceed the configured maximum. |
| `IICP_DB_POOL_ACQUIRE_TIMEOUT_MS` | `30000` | Maximum wait for a pool connection before an explicit failure. Must be greater than zero. |
| `IICP_DB_POOL_IDLE_TIMEOUT_MS` | `600000` | Idle connection lifetime in milliseconds. Must be greater than zero. |
| `APP_ENV` | `production` | `local`, `testing`, `staging` or `production`; controls fail-closed safety policy. |
| `APP_KEY` | — | Optional HS256 JWT compatibility key. |
| `IICP_GENESIS_ED25519_SECRET_KEY` | — | 128-hex libsodium Ed25519 secret key used for event, DID, token and attestation signing. Required in production. |
| `IICP_REPLICA_MODE` | `false` | When true, unsafe writes redirect to the seed and discovery remains unavailable until verified synchronization completes. |
| `IICP_SEED_URL` | — | Configured seed location. This is not identity or trust evidence. |
| `IICP_SEED_DID` | — | Expected `did:web` seed identity. Required separately from `IICP_SEED_URL` in replica mode. |
| `IICP_REPLICA_DID`, `IICP_REPLICA_ENDPOINT` | — | Stable replica identity and HTTPS endpoint. Both are required in replica mode. |
| `IICP_LOCAL_DIRECTORY_ADVERTISE` | `false` | Opt in to `_iicp-dir._tcp.local.` candidate advertisement. Discovery does not establish trust. |
| `IICP_LOCAL_DIRECTORY_HOSTNAME` | — | Required `.local.` DNS name when local advertisement is enabled. |
| `IICP_LOCAL_DIRECTORY_PORT` | `443` | HTTPS descriptor port advertised through DNS-SD. |
| `IICP_LOCAL_DIRECTORY_INSTANCE` | `IICP Directory` | Display-only DNS-SD instance label; never treated as identity. |
| `IICP_LOCAL_DIRECTORY_ROLE` | `standalone` or `replica` | Optional `seed`, `replica` or `standalone` hint. The signed descriptor remains authoritative. |
| `IICP_REPLICA_STATUS_FILE` | platform state directory | Owner-private, non-secret synchronization status and cursor evidence. |
| `IICP_ALLOW_IN_MEMORY` | `false` | Explicitly allow disposable in-memory state outside production. |
| `IICP_DEV_ALLOW_INSECURE_TLS` | `false` | Allow invalid probe certificates only in local/testing environments. Never affects production. |
| `IICP_DEV_ALLOW_HTTP_DID` | `false` | Allow a plain-HTTP replica endpoint only when `APP_ENV` is `local` or `testing`. Staging/production always require HTTPS. |
| `IICP_DEV_ALLOW_UNSIGNED_EVENTS` | `false` | Allow unsigned replica events only in local/testing environments. Never affects production. |
| `IICP_DEPLOYMENT_KIND` | — | `shared_hosting`, `container`, `native` or `other`; required to publish signed deployment provenance. |
| `IICP_RELEASE_TAG`, `IICP_SOURCE_COMMIT`, `IICP_BUILD_ID`, `IICP_DEPLOYED_AT` | — | Immutable release inputs for `/.well-known/iicp-deployment.json`. |
| `IICP_ROOT_KEY_ID` | — | DID verification-method ID for the configured signing key. |
| `IICP_OPENAPI_VERSION`, `IICP_PROTOCOL_MIN`, `IICP_PROTOCOL_MAX` | `1.7.0`, `1.9.0`, `1.9.0` | Compatibility metadata in the signed deployment record. |
| `IICP_RUNTIME_HEALTH_FILE` | platform runtime/state directory | Private local runtime-health snapshot used by the healthcheck and supervision adapters. |
| `IICP_RESTRICTED_DOMAIN_ENABLED` | `false` | Enables fail-closed restricted trust-domain admission on registration, discovery, bootstrap, heartbeat, peer, dispatch and relay surfaces. |
| `IICP_TRUST_DOMAIN_ID` | — | Stable restricted-domain identifier. Required when restricted mode is enabled. |
| `IICP_TRUST_DOMAIN_AUTHORITY_ID` | — | Membership issuer identifier. Required when restricted mode is enabled. |
| `IICP_TRUST_DOMAIN_AUTHORITY_KEY_ID` | `<authority-id>#key-1` | Verification-method identifier placed in peer-verifiable membership assertions. |
| `IICP_TRUST_DOMAIN_MEMBERSHIP_EPOCH` | `1` | Minimum accepted credential generation; increasing it invalidates older credentials. |
| `IICP_TRUST_DOMAIN_MAX_CREDENTIAL_TTL` | `86400` | Maximum membership lifetime in seconds, with a minimum of 60. |

`GET /v1/metrics` exposes content-free SQL pool capacity, open/idle/in-use
connections, utilization, and a 250 ms bounded acquisition probe when MySQL is
active. These measurements contain no query text, node identifiers, endpoints,
credentials, payloads, or private topology and are suitable for isolated
qualification receipts. They are observations, not a production capacity
claim.

In production mode, `POST /v1/register` and `POST /api/v1/register` reject private/loopback endpoints. Use `APP_ENV=local` for local endpoint tests.
The deployment-provenance endpoint returns 503 until every required release
input and the signing key are present.

Restricted mode is additive and disabled by default. It requires durable MySQL
storage and cannot currently be combined with replica mode; startup fails
instead of silently weakening either boundary. Requests to protected routes
carry `X-IICP-Membership` and `X-IICP-Subject-Id`. Membership administration is
local and prints a newly issued credential only once:

```bash
iicp-directory-rs trust-domain-membership-issue \
  --kind node --subject node-1 --scopes registration,heartbeat,peers \
  --subject-key-id 'did:key:node-1#key-1' \
  --subject-public-key BASE64URL_ED25519_PUBLIC_KEY
iicp-directory-rs trust-domain-membership-revoke --kind node --subject node-1
```

Supplying both subject-key options also prints a short-lived, directory-signed
membership assertion. It binds public identity, domain, generation, expiry and
peer scopes without exposing the bearer credential. These controls do not make
the Rust preview the Genesis authority and do not enable cross-domain
federation. Restricted discovery rechecks provider membership before ranking,
so expired, revoked or pre-epoch nodes cannot remain eligible merely because a
registration record is still live.

## Test baseline

Current local verification:

```bash
./scripts/run_lifecycle_conformance.sh
```

This lane runs the IICP v1.10.8 lifecycle profile against a disposable,
MySQL-backed loopback directory. It rechecks production endpoint rejection,
uses only the explicit testing liveness bypass, removes the container and state
afterward, and emits a content-free summary. It never contacts Genesis.

```bash
cd iicp-directory-rust
./scripts/check_quality.sh
```

The route-alias and live-shape compatibility tests are isolated in
`src/main_tests.rs`. The local publication-quality lane blocks on Clippy,
RustSec and a 70% production line-coverage floor, combining ordinary and
disposable-MySQL execution. This is an explicit ratchet, not a claim of PHP's
higher coverage level.

## Relationship to PHP

See [`PARITY.md`](PARITY.md) for the detailed PHP/Rust parity checklist. The versioned parity fixtures define the seed requirements; the dedicated PHP repository remains the easiest way to compare exact Laravel behavior.

Applications do not need to know which directory implementation serves a
compatible endpoint. To connect a consumer or provider agent, follow
[Connect an AI agent to IICP](https://github.com/RobLe3/IICP/blob/main/docs/agent-bootstrap.md).

## Contributing and security

Run `cargo fmt --check`, `cargo test --locked`, and the parity checks described
in `PARITY.md` before proposing a change. See `CONTRIBUTING.md`, `SECURITY.md`,
`OPERATIONS.md`, and `PUBLICATION_READINESS.md` for repository boundaries and
self-host guidance.

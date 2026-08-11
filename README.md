# IICP Directory — Rust operator preview

Rust implementation of the IICP directory control plane.

The protocol is defined by the public [IICP specification](https://github.com/RobLe3/IICP).
This repository owns the Rust implementation, not the protocol, website,
production deployment, or Genesis Seed credentials and data.

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

- Rust 1.86 or newer
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

Migrations are loaded from `migrations/` on startup.

For a durable installation, backup and recovery guidance, read
[`OPERATIONS.md`](OPERATIONS.md). In-memory mode is for local evaluation only.

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `DATABASE_URL` | — | MySQL DSN. Required in production. |
| `APP_ENV` | `production` | `local`, `testing`, `staging` or `production`; controls fail-closed safety policy. |
| `APP_KEY` | — | Optional HS256 JWT compatibility key. |
| `IICP_GENESIS_ED25519_SECRET_KEY` | — | 128-hex libsodium Ed25519 secret key used for event, DID, token and attestation signing. Required in production. |
| `IICP_REPLICA_MODE` | `false` | When true, unsafe writes redirect to the seed. |
| `IICP_SEED_URL` | — | Seed URL used by replica write redirection. |
| `IICP_ALLOW_IN_MEMORY` | `false` | Explicitly allow disposable in-memory state outside production. |
| `IICP_DEV_ALLOW_INSECURE_TLS` | `false` | Allow invalid probe certificates only in local/testing environments. Never affects production. |
| `IICP_DEV_ALLOW_UNSIGNED_EVENTS` | `false` | Allow unsigned replica events only in local/testing environments. Never affects production. |
| `IICP_DEPLOYMENT_KIND` | — | `shared_hosting`, `container`, `native` or `other`; required to publish signed deployment provenance. |
| `IICP_RELEASE_TAG`, `IICP_SOURCE_COMMIT`, `IICP_BUILD_ID`, `IICP_DEPLOYED_AT` | — | Immutable release inputs for `/.well-known/iicp-deployment.json`. |
| `IICP_ROOT_KEY_ID` | — | DID verification-method ID for the configured signing key. |
| `IICP_OPENAPI_VERSION`, `IICP_PROTOCOL_MIN`, `IICP_PROTOCOL_MAX` | `1.7.0`, `1.9.0`, `1.9.0` | Compatibility metadata in the signed deployment record. |

In production mode, `POST /v1/register` and `POST /api/v1/register` reject private/loopback endpoints. Use `APP_ENV=local` for local endpoint tests.
The deployment-provenance endpoint returns 503 until every required release
input and the signing key are present.

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

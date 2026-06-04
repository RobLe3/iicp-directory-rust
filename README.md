# iicp-directory-rs

Rust reference implementation of the IICP directory control plane (Phase 6 / L6.1).

**Status**: **full non-federation parity** with the PHP directory — 28 routes implemented
(incl. `/v1/probe` SSRF guard), MySQL-backed data layer wired, **6 background tasks**
(incl. active per-node probing DIR-PROBE-NODE-01, #373 Phase B),
88 tests, quality gate 6872, REACH probe compliant (DIR-CIP-01/02/03, DIR-DISC-08/09/10,
DIR-NODE-01/02, DIR-PROBE-01/02, DIR-STATS-01/02 all passing).

NODELIST response has full field parity with PHP (28 fields): address_family, cip_policy,
cip_conformance_level, models, quantization, inference_engine, relay_capable, nat_type,
transport_method/endpoint/metadata, sdk_language/sdk_version, public_key, reputation_tier, pricing.
See [`PARITY.md`](PARITY.md) for the authoritative checklist.

## Why Rust

The PHP directory (`directory/`) is the current production reference implementation.
This Rust crate is the permanent replacement:

1. **Auditable scoring** — the reputation/scoring formula compiled into one binary,
   not spread across configurable server-side weights (concept-review F7/F10).
2. **Type-safe wire contract** — iicp-dir v0.9.0 schema as Rust types, eliminating
   field-accretion drift that the PHP NODELIST suffered (#384).
3. **Security properties** — bcrypt token storage, constant-time HMAC verification
   (W-009), RT-01..05 + RT-01b..05b bypass-prevention mitigations compiled in.

Migration path:

```
PHP reference → Rust directory takes hot path → federated mesh (≥2 replicas) → PHP decommission
```

Federation (replica sync, signed event log) is **gated on ADR-013** advancing past Vision.

## Run

### Local (in-memory, no DB required)

```bash
cargo run               # all routes on :8090; data is ephemeral (InMemoryRepo)
cargo test              # 74 unit + integration tests
```

### With MySQL

```bash
# 1. Set the DSN (MariaDB/MySQL 5.7.8+ required for JSON_EXTRACT in audit-report)
export DATABASE_URL="mysql://user:pass@localhost/iicp_directory"

# 2. On first start, migrations run automatically from migrations/001_initial.sql
cargo run
# iicp-directory-rs v0.1.0-rs: MySQL pool connected
# iicp-directory-rs v0.1.0-rs listening on 0.0.0.0:8090
```

### Docker (example)

```dockerfile
FROM rust:1.78 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get install -y libssl-dev ca-certificates
COPY --from=builder /app/target/release/iicp-directory-rs /usr/local/bin/
EXPOSE 8090
CMD ["iicp-directory-rs"]
```

```bash
docker run -e DATABASE_URL="mysql://..." -p 8090:8090 iicp-directory-rs
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | MySQL DSN. Omit for InMemoryRepo (local/test). |
| `APP_ENV` | `production` | `local` / `testing` / `staging` / `production`. Controls endpoint routability validation. |

In `production` mode, `POST /v1/register` rejects private/loopback endpoints (IICP-E035).
Use `APP_ENV=local` for development against `localhost` endpoints.

## Routes (27 non-federation)

### Read + registry
- `GET /` — root info (version, spec link)
- `GET /health` — liveness probe
- `GET /v1/stats` — active_node count + mesh health
- `GET /v1/metrics` — Prometheus text exposition
- `GET /v1/discover` — NODELIST (§3.3/§3.4, scored + filtered)
- `GET /v1/bootstrap` — recently-active peer list (§3.7)
- `GET /v1/node/{id}` — node detail
- `GET /v1/registry/nodes` · `/nodes/{id}` · `/intents` · `/stats` — ADR-017 public registry
- `GET /.well-known/did.json` — DID document for `did:web:iicp.network`

### Lifecycle
- `POST /v1/register` — register node (UUID v4 id, bcrypt token, HMAC key, RT-04 check)
- `DELETE /v1/register` — deregister
- `POST /v1/heartbeat` — update load + reputation (RT-01 delta cap)
- `GET /v1/me` — authenticated self-view
- `POST /v1/peers` — peer exchange (§3.5, max 20 known)

### Credits + reputation
- `GET /v1/credits/balance` · `/transactions` · `/quote`
- `POST /v1/credits/award` — HMAC-SHA256 receipt verification (W-009, RT-02 nonce replay)
- `POST /v1/audit-report` — reputation delta (RT-05 griefing cap, max 2 reporters/24h)
- `POST /v1/telemetry/probe` — REACH conformance probe upload (ProbeTokenAuth)
- `POST /v1/telemetry` — proxy latency report (RT-03 self-report guard, Sybil quorum signal)

### Conformance
- `GET /v1/badges` · `GET /v1/badge/{tier}` — certificate list + SVG shield
- `POST /v1/submit` · `GET /v1/verify` — conformance evaluation pipeline

## Background tasks (5)

| Task | Interval | PHP equivalent |
|------|----------|----------------|
| `ExpireStaleNodes` | 60s | `ExpireStaleNodes` Artisan command |
| `ReputationDecay` | 1h | `ReputationDecayCommand` (−0.005/hr, floor 0.30) |
| `NodeLifecycle` | 24h | `NodeLifecycleCommand` (archive dormant > 90 days) |
| `PruneHeartbeatEvents` | 7d | `PruneHeartbeatEventsCommand` (retention db-D4prime) |
| `RotateReputationWindow` | 24h | `RotateReputationWindowCommand` (90-day rolling window reset) |

## Security model

- `node_token` stored as **bcrypt hash** (cost 12, matching PHP `PASSWORD_BCRYPT`)
- `proxy_token` issued on registration, bcrypt-hashed; required for `POST /v1/telemetry`
- `node_hmac_key` is a 32-byte hex secret returned at registration; used for CIP
  credit receipt signing (HMAC-SHA256 canonical message, W-009)
- `probe_token` verified via SHA-256 hash lookup (no bcrypt — probe tokens are
  long-lived and don't need computational hardening)
- `node_id` format validated on register: `[a-zA-Z0-9][a-zA-Z0-9._:-]*`, max 36 chars

**RT-01b** (velocity ceiling): heartbeat reputation gain capped at +0.20/hour/node via
rolling `rep_hourly_gain` + `rep_hourly_window_start` columns. Prevents fleet-scale
inflation with N nodes × fast heartbeats.

**RT-02b** (free-credit IP gate): `credit_ip_gates` table adds an IP-level gate
alongside the per-node_id gate. Prevents harvest by re-registering a new node_id
from the same IP within the 6h window.

**RT-03b** (quorum independence): Sybil quorum gate (≥3 distinct proxy reporters) now
requires each reporting proxy to be ≥3 days old AND have reputation ≥0.55. Prevents
3-second fresh-node triplets from satisfying the gate.

**RT-05b** (audit reporter eligibility): `audit-report` reporters must be ≥3 days old
AND have reputation ≥0.55 for their report to carry a reputation delta. Prevents
rotation-attack griefing via fresh node registrations.

## Placement

Lives in-repo (like `iicp-node/`) for now. Will be extracted to `RobLe3/iicp-directory-rs`
once it serves real traffic, mirroring the `iicp-directory-php` seed plan (#291).

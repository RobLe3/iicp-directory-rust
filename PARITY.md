# iicp-directory-rs — PHP Feature Parity Checklist

Last refreshed: **2026-07-27**. Rust now consumes the PHP authority's normalized
`parity/http-contract-v1.json` for runtime `v1.10.80.1` at `08fa5f9`. The older
`contract-v1.10.76.json` remains immutable capability evidence; neither fixture
is a production cutover claim.

> **Status:** this Rust implementation is a reconciled parity baseline, not a
> cutover-ready replacement. Operator acceptance/DSR routes, signed policy-manifest
> validation with fail-closed key lifecycle, public-vs-dispatch discovery and bounded
> anonymous dispatch counters are implemented. Public-mesh intent-policy refusal uses
> the shared canonical taxonomy. `directory/parity/contract-v1.10.76.json` is the
> authoritative checklist; do not infer operational parity from route count alone.

The post-`v1.10.76` refresh is tracked by issue #1 and its bounded follow-ups.
Signed-event appends now use the PHP-compatible durable, row-locked chain head;
credit concurrency, shared policy/registration characterization and operator
distribution evidence remain open and must not be inferred from this increment.

The HTTP fixture is copied byte-for-byte from the PHP repository. Rust CI pins
its digest and checks all 43 canonical method/path pairs plus the finite auth
and documented success-status vocabularies. Behavioral policy parity remains a
separate gate; route acknowledgement alone does not prove equivalent outcomes.

Rust also executes the byte-identical `behavior-contract-v1.json` vectors for
ranking, eligibility, pricing ceilings and endpoint-IP refusal, and pins both
fixtures through `contract-v1.10.80.json`. Registration recovery and rollback
remain database-backed behavior: their shared case declarations complement,
rather than replace, the disposable dual-MySQL parity gate.

The goal is not merely to compile a Rust server. The Rust directory must be wire-compatible with the PHP/Laravel directory for clients, nodes, relays, the website and future replicas. The PHP seed remains production authority until live conformance and operational evidence justify a cutover.

Status legend: ✅ done · 🔶 present but not full production equivalent · ⬜ not ported / intentionally PHP-only

## API route parity

### Public/read path

| Surface | Rust status |
|---|---|
| `GET /health` | ✅ |
| `GET /api/v1/stats` + legacy `/v1/stats` | ✅ |
| `GET /api/v1/metrics` + legacy `/v1/metrics` | ✅ |
| `GET /api/v1/discover` + legacy `/v1/discover` | ✅ live-shape fields added 2026-06-30 |
| `GET /api/v1/bootstrap` + legacy `/v1/bootstrap` | ✅ |
| `GET /api/v1/node/{id}` + legacy `/v1/node/{id}` | ✅ |
| `GET /api/v1/me` + legacy `/v1/me` | ✅ node-token auth |
| `GET /api/v1/probe` + legacy `/v1/probe` | ✅ SSRF guarded |
| `GET /` | ✅ root metadata |
| `GET /.well-known/did.json` | ✅ |
| `GET /.well-known/iicp-replicas.json` | ✅ |

### Lifecycle and routing

| Surface | Rust status |
|---|---|
| `POST /api/v1/register` + legacy `/v1/register` | ✅ |
| `DELETE /api/v1/register` + legacy `/v1/register` | ✅ |
| `POST /api/v1/heartbeat` + legacy `/v1/heartbeat` | ✅ |
| `POST /api/v1/peers` + legacy `/v1/peers` | ✅ |
| `POST /api/v1/operator/rename` + legacy `/v1/operator/rename` | ✅ |
| `POST /api/v1/operator/challenge`, `/key/rotate`, `/key/revoke` + legacy `/v1` | ✅ signed dual-key lifecycle; no-store/redacted receipts |
| `POST /api/v1/operator/acceptance`, `/dsr/{export,restrict,anonymize}` + legacy `/v1` | ✅ signed/no-store routes; shared related-record and disposable MySQL parity gate |
| `GET /api/v1/leaderboards/{board_id}` + legacy `/v1/leaderboards/{board_id}` | ✅ |

### Registry, credits, conformance and telemetry

| Surface | Rust status |
|---|---|
| `/api/v1/registry/nodes`, `/nodes/{id}`, `/intents`, `/stats` | ✅ |
| `/api/v1/credits/balance`, `/summary`, `/transactions`, `/quote`, `/award` | ✅ |
| `/api/v1/conformance/badges`, `/submit`, `/verify` | ✅ |
| `/api/v1/badge/{tier}` | ✅ |
| `POST /api/v1/audit-report` | ✅ |
| `POST /api/v1/telemetry` | ✅ |
| `POST /api/v1/telemetry/probe` | ✅ |

### Federation, tokens and relay preparation

| Surface | Rust status |
|---|---|
| `GET /api/v1/events` + legacy `/v1/events` | ✅ signed event log supported when signing key configured |
| `GET /api/v1/snapshot` + legacy `/v1/snapshot` | ✅ |
| `POST /api/v1/replicas/register` + legacy `/v1/replicas/register` | ✅ |
| `GET /api/v1/directory-key` + legacy `/v1/directory-key` | ✅ |
| `POST /api/v1/consumer-token` + legacy `/v1/consumer-token` | ✅ Ed25519 signed |
| `POST /api/v1/relay/ticket` + legacy `/v1/relay/ticket` | ✅ Ed25519 signed |
| `GET /api/v1/compliance-attestation` + legacy `/v1/compliance-attestation` | 🔶 route and signing are present; PHP still owns full REACH-backed evidence |

## Discover/NODELIST compatibility

Rust now enriches each discovered node with the current PHP/live fields used by clients and the website:

```text
cx_public_key, public_key, key_ready, privacy_routing_status,
sdk_status, sdk_baseline_version, upgrade_required, auto_update,
backend, backend_stability, trust_progress, route_evidence,
routing_hint, browser_usable, directory_observed_reachable,
reachability_tier, capability_summary, input_modalities,
pricing, performance, health_confidence
```

This closes the biggest practical Rust-vs-live drift: older Rust discovery exposed a narrower `/v1` shape and omitted several fields that current clients use for privacy, routing, quality display and upgrade decisions.

The public discover/detail wire shape is intentionally not a raw Rust `Node` serialization. Internal fields such as task counters, pricing scalar columns, operator verification internals and `health_models` stay available to Rust scoring/storage, but are hidden from the public response when live PHP exposes the same information only through public summary blocks.

## v1.10.76 control-plane parity

- ✅ `POST /api/v1/dispatch/ticket`: prompt-free, signed, intent/node/expiry-scoped route disclosure ticket. V1 is disclosure-only; stateful redemption/node admission is deferred.
- ✅ Intent-policy refusal for prohibited and high-risk capability/discovery intent families; transparency and general/custom intents remain routable.
- ✅ Operator acceptance plus signed, no-store DSR export, restriction and anonymisation routes.
- ✅ Signed policy-manifest validation; operator rotation/revocation invalidates stale manifests and records policy-key lifecycle state.
- ✅ Public-vs-dispatch discovery and bounded anonymous daily dispatch-usage counters.
- ✅ Shared `dsr-related-records-v1.json` coverage and a disposable dual-MySQL gate prove PHP/Rust export shape, redaction, signed lifecycle, replay/conflict handling, transactional rollback, retained ledger/event evidence and telemetry deletion parity.
- ✅ Metadata-only DB maintenance status, aggregate strict-E050 readiness and
  bounded telemetry pruning now have Rust CLI equivalents. Rust pruning is
  safer by default: it is read-only unless `--apply` is explicit.
- ✅ The versioned `directory-runtime-parity-v1` REACH profile compares 37
  environment-neutral probes against isolated PHP and Rust databases. The
  production `run_all` probe sequence remains unchanged. An empty event log
  produces the same expected `DIR-FED-07` failure in both candidates; this is
  fixture state, not evidence of a production pass.

These are control-plane safety features, not cosmetic route aliases. Rust must not claim full directory parity until each has equivalent storage, authorization, redaction and contract tests.

## Shared profile-fixture and policy-taxonomy baseline

Rust carries the exact pre-normative `parity/profile-compatibility-v0.json`
fixture and the canonical `parity/intent-risk-taxonomy.json` used by the seed.
The policy guard enforces the taxonomy at registration and discovery: prohibited
and high-risk families fail closed with `IICP-POLICY-001`; transparency-risk and
general/custom families remain routable. This is identifier-only control-plane
policy, not prompt moderation: task payloads do not pass through the directory.

Profile fixture coverage remains an integrity-consumption gate until ticket,
receipt, DSR and lifecycle profile behaviours have their own executable parity
suites.

## Remaining parity cautions

- **Database startup:** Rust now bootstraps only a truly empty database from
  `schema/baseline-v1.sql` and verifies every existing database against
  `schema/contract-v1.json`. It never replays the historical SQLx migration
  chain, repairs partial schemas, mutates `_sqlx_migrations`, or silently falls
  back to memory when `DATABASE_URL` is configured. The disposable Docker gate
  proves fresh bootstrap, Laravel adoption, restart/history preservation,
  incomplete-schema rejection and atomic registration rollback.
- **Compliance attestation:** Rust emits a compact signed attestation when configured. Production PHP includes latest REACH conformance probe evidence and cache behavior; Rust needs a real probe-data path before this is production-equivalent.
- **Operational commands:** Rust now provides maintenance status, bounded
  telemetry pruning and E050 readiness, and its scheduler uses the PHP
  retention horizons. PHP Artisan remains the richer operator toolbox for
  genesis key provisioning, probe-token issuance, warm caches, founder lock-in
  scans and deployment-specific operations.
- **Middleware/deployment behavior:** Replica write redirect exists in Rust. Exact PHP shared-hosting middleware, CDN cache tuning and deploy-script behavior still need live verification before cutover.
- **Live proof:** API shape and unit tests are necessary but not sufficient. Replacement requires REACH probes, live discover/stats comparison and deployment rollback practice.

## Current verification

```bash
cd iicp-directory-rs
cargo fmt --check && cargo test --locked
cd ..
bash scripts/docker_rust_schema_reliability_gate.sh
bash scripts/docker_directory_dsr_parity_gate.sh
bash scripts/docker_directory_runtime_parity_gate.sh
```

New parity tests added in this refresh:

- `/api/v1/*` aliases do not 404 for the live PHP route surface.
- `/api/v1/discover` contains the current live PHP compatibility fields.
- `/api/v1/directory-key` exposes the Ed25519 public key from a libsodium secret key.
- Registration refuses prohibited capability families before persistence; discovery refuses high-risk public-mesh intents before repository lookup.
- `/api/v1/consumer-token` and `/api/v1/relay/ticket` issue signed short-lived tokens.
- Auth-first JSON handling keeps malformed unauthenticated credit, telemetry
  and peer requests at the same 401 boundary as PHP; extractor errors are
  normalized to content-free JSON.
- The runtime-parity fixture and gate prevent production REACH behavior from
  being inferred from a hand-picked local transcript.

## Cutover rule

Rust can replace PHP for a surface only when:

1. the Rust response is compatible with the documented PHP/live contract,
2. the same REACH/live conformance probes pass,
3. production deployment, cache and rollback behavior is verified, and
4. the maintainer explicitly authorizes cutover.

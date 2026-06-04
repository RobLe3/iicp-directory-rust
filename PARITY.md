# iicp-directory-rs — PHP Feature Parity Checklist

**The Rust directory MUST reach full feature parity with the PHP reference implementation
(`directory/`) before it can replace it.** This is the authoritative scope — not the M1–M5
happy-path plan alone. Every endpoint, service, middleware, and cron job below has a PHP
implementation that the Rust directory must match (wire-identical by contract, verified by
the same REACH probes) before the PHP directory is decommissioned.

Status legend: ✅ done · 🔶 partial · ⬜ not started · 🔒 gated (ADR-013 / Phase 6)

## Routes (27)

### Read path
- ✅ `GET /health`
- ✅ `GET /v1/stats` (§3.9b — live active_count from MySQL)
- ✅ `GET /v1/discover` → NODELIST (§3.3/§3.4) — **full field parity** with PHP (28 fields; iter-1699/1703)
- ✅ `GET /` (root info)
- ✅ `GET /v1/node/{id}` (node detail)
- ✅ `GET /v1/bootstrap` (§3.7)
- ✅ `GET /v1/me` (authenticated node self-view — X-Node-Id interim; JWT in Phase 4)
- ✅ `GET /v1/metrics` (Prometheus text/plain exposition)
- ✅ `GET /v1/registry/nodes`, `/nodes/{id}`, `/intents`, `/stats` (ADR-017 public registry)
- ✅ `GET /.well-known/did.json` (DID document placeholder)

### Register / lifecycle
- ✅ `POST /v1/register` (UUID v4 node_id + bcrypt token + hmac_key; ADR-026 anti-laundering; RT-04 declared-reachable check)
- ✅ `DELETE /v1/register` (deregister with token auth)
- ✅ `POST /v1/heartbeat` (§3.2 — bcrypt token verify; reputation delta with RT-01 cap)
- ✅ `POST /v1/peers` (PEER_EXCHANGE §3.5 — known_peers cap 20)

### Reputation / telemetry
- ✅ `POST /v1/telemetry` (proxyReport — EMA wiring, outlier weight, Sybil quorum ≥3, cip_capable filter)
- ✅ `POST /v1/telemetry/probe` (ProbeTokenAuth + batch insert to iicp_telemetry_probes)
- ✅ `POST /v1/audit-report` (§7 — RT-05 griefing cap MAX_REPORTERS=2/24h via node_events)

### Credits
- ✅ `GET /v1/credits/balance`
- ✅ `GET /v1/credits/transactions` (paginated)
- ✅ `GET /v1/credits/quote`
- ✅ `POST /v1/credits/award` (W-009 HMAC-SHA256 receipt + RT-02 nonce replay + ceiling cap)

### Conformance / recognition
- ✅ `GET /v1/badges` · `GET /v1/badge/{tier}` (SVG shield — Shields.io format)
- ✅ `POST /v1/submit` · `GET /v1/verify` (conformance submission/verification)

### Federation (Phase 6 — 🔒 ADR-013 must reach Proposed)
- 🔒 `GET /v1/events` (signed event log §3.7)
- 🔒 `POST /v1/replicas/register` · `GET /v1/snapshot` (S.13)

### Liveness probe
- ✅ `GET /v1/probe` (SSRF-guarded node reachability check — blocks private/loopback IPs)

### Ops (operator concern — may stay PHP-only / out of protocol scope)
- ⬜ `POST /_deploy/migrate` (HMAC-gated migration — NOT ported; out-of-scope)

## Services (13)
- ✅ NodeScorer (reputation = pure function, RT-01 cap — the Rust differentiator, M4)
- ✅ ReputationService (delta rules §11.2 + RT-01 cap + RT-05 audit path)
- 🔶 NodeHealthService (ADR-044 per-node health + mesh aggregate). **Phase-A done (iter-1957)**: the pure scoring algorithm is ported byte-for-byte into `src/health.rs` (weights W_REACHABILITY=0.30/W_LATENCY=0.25/W_SUCCESS=0.25/W_REPUTATION=0.20, latency curve, success curve, label thresholds, nearest-rank percentile, median-based mesh aggregate, MIN_MESH_SAMPLE=3) with 11 unit tests, and wired into both **`/v1/stats` `mesh_health`** (over the active provider set via `repo.active_nodes()` — full unlimited liveness set; real median/mean/p10/distribution replacing the all-zero stub) and the **`/v1/registry/nodes/:id` `health` field** (per-node vector: score, label, observed, components{liveness/reachability/latency/success_rate/reputation}, evaluated_at — PHP `RegistryController` `forNode` parity, iter-1958). **Phase-B remaining (#385 signal layer)**: stats() currently passes PHP's documented neutral fallbacks (reachability=0.5, success neutral) for those two components; reputation + latency are ground-truth. **Phase-B progress (iter-1969 AL4 + iter-1973)**: the columns exist (no migration), but iter-1973 found they were **not populated**: the heartbeat dropped `tasks_failed` (folded into `tasks_total`) and nothing writes `public_reachable`.
- **SUCCESS signal — DONE (iter-1973)**: heartbeat now persists `tasks_failed` (AL3 counter-flow fix — `tasks_failed = tasks_failed + ?`), `NodeRow`/`Node` carry it, and stats() + node-detail compute the **real success ratio** (`(tasks_total − tasks_failed)/tasks_total`) instead of the neutral fallback. Test: `heartbeat_persists_tasks_failed_for_success_signal`.
- **REACHABILITY signal — self-attested flags (`reachability_signal`), not probe-verified**: `health` is fed `reachability: n.reachability_signal` (main.rs), i.e. `reachability_from_flags(public_reachable, relay_capable)` — 1.0 direct / 0.5 relay / 0.0 unreachable from the node's REGISTER-time flags (PHP self-attested-branch parity), not a flat neutral. Probe-*verified* reachability (the directory dialing each node and writing `public_reachable`) is **structurally unavailable**: it needs origin IPv6 egress to reach CGNAT/IPv6 nodes, and the **VPS that would have provided that is cancelled** (see `project_vps_upgrade.md`). Per **#411 (closed) + ADR-047**, the reachability model is now **heartbeat-based** (cryptographic liveness challenge + 3-tier `reachability_tier`), not directory dial-back — so the old "#373 active probe will populate this once VPS lands" plan is superseded; dial-back becomes optional `relay→direct` enrichment if egress ever exists. LATENCY + REPUTATION are already ground-truth. **Still open shape gap** vs live PHP: `directory_health` top-level key; `probes.active_count`/`regions`/`aggregate_24h`/`conformance_24h`. Structural fields closed: `server.internal_nodes`/`uptime_seconds` (iter-1653), `p10`/`distribution`/`basis` (iter-1673). Score/mean/p10 wire format is float[0,1] — PHP v1.10.6 normalisation (spec iicp-dir §3.9b v0.9.2). **Security parity (iter-1717..1722)**: RT-02b (credit_ip_gates) ✅, RT-01b (rep_hourly_gain velocity ceiling) ✅, RT-03b (quorum min-age+reputation JOIN) ✅, RT-05b (audit reporter eligibility) ✅ — all in db.rs + migrations/001_initial.sql. PHP v1.10.10.
- ✅ CreditService (balance, award W-009 HMAC+RT-02, transactions, quote, free-tier 6h gate)
- ✅ NodeRegistry (register/liveness/heartbeat/deregister + bcrypt + hmac_key + JWT)
- ✅ NodeAddressObserver (observe_address → node_address_history on register)
- 🔶 NodeEventLogger (AUDIT_REPORT ✅, DEREGISTER ✅, REPUTATION_UPDATE ✅; signed event log 🔒 Phase 6)
- ✅ LivenessMonitor (ExpireStaleNodes 60s background task)
- ✅ JwtService (HS256 issue/verify, APP_KEY base64 decode, PHP-compatible)
- ⬜ ConformanceBadgeValidator · OtelTracer · SeedDidResolver · ReplicaEventApplier (🔒)

## Middleware (7)
- ✅ NodeTokenAuth (JWT sub→node_id ✅; bcrypt bearer fallback ✅; X-Node-Id interim)
- ✅ ProbeTokenAuth (SHA-256 hash → probe_tokens lookup)
- ✅ ProxyTokenAuth (bearer present + bcrypt verify against proxy_token_hash; grace period removed)
- 🔒 ReplicaTokenAuth
- 🔒 LoadRedirect (Phase 6 / ADR-013 — redirects read load to replicas) · 🔒 ReplicaModeRedirect · 🔒 SignReplicaResponse

## Console / cron (10)
- ✅ ExpireStaleNodes (60s interval)
- ✅ NodeLifecycleCommand (86400s — archive_dormant(90))
- ✅ ReputationDecayCommand (3600s — GREATEST(0.30, score−0.005))
- ✅ PruneHeartbeatEventsCommand (604800s weekly — db-D4prime retention)
- ✅ RotateReputationWindowCommand (90-day rolling window reset)
- ✅ ProbeNodesCommand (300s — #373 Phase B active reachability probing; SSRF-guarded TCP; DIR-PROBE-NODE-01)
- ⬜ GenesisKeyCommand · IssueProbeToken (operator tooling — out-of-scope for core)
- 🔒 ReplicaPreflightCommand · ReplicaStartCommand · RotateReplicaLifecycleCommand (Phase 6)

## Parity gate
The Rust directory replaces the PHP directory for a given surface only when:
1. that surface passes the **same REACH conformance probes** as PHP, AND
2. its responses are **byte-compatible** with the PHP directory for the documented contract, AND
3. the full directory test suite (currently 552 PHP tests) has equivalent Rust coverage for that surface.

Non-federation parity (everything not 🔒) is the near-term target; federation parity lands
when ADR-013 advances past Vision.

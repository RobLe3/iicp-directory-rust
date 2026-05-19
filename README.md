# iicp-directory-rust

**IICP Directory Service — Rust Implementation (Planned)**  
Apache 2.0 · [Protocol: iicp.network](https://iicp.network) · Private beta

> A high-performance Rust reimplementation of the IICP Control Plane.  
> Same API surface as `iicp-directory-php`, designed for operators running high-throughput or resource-constrained directory nodes.

---

## Overview

IICP's three-plane architecture:

```
Control Plane   →  iicp-directory-rust  ← you are here
Execution Plane →  iicp-adapter (Python FastAPI + vLLM/llama.cpp/Ollama)
Client Plane    →  iicp-proxy (Python → Rust)
```

The directory is **discovery-only** — no task traffic routes through it. Nodes register, heartbeat, and are discovered here; actual inference runs adapter-to-adapter.

The **PHP reference implementation** (`iicp-directory-php`) is the production-tested baseline. This Rust implementation is the planned high-performance variant, sharing the same API contract.

---

## Status

| Feature | Status |
|---------|--------|
| Repository | ✅ Created |
| API contract (matches PHP reference) | ✅ Spec-defined |
| Implementation | ⚠ Planned — not yet started |
| Production deployment | ⚠ Planned — awaiting Phase 5 CIP ratification |

**This is a placeholder repository.** Implementation will begin once the PHP reference implementation is fully stable and the protocol spec is ratified (Phase 5 complete).

---

## Planned API Surface

Identical to `iicp-directory-php`:

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/register` | — | Register a new node, receive JWT |
| POST | `/api/v1/heartbeat` | Bearer JWT | Update node liveness (every 30s) |
| GET | `/api/v1/discover` | — | Scored, available nodes by intent |
| GET | `/api/v1/registry/nodes` | — | Browse the public node directory |
| GET | `/api/v1/stats` | — | Network-wide status and probe health |
| GET | `/api/v1/bootstrap` | — | Seed peer list for mesh bootstrap |
| POST | `/api/v1/peers` | Bearer JWT | Gossip peer exchange (HMAC-SHA256) |
| GET | `/api/v1/credits/balance` | Bearer JWT | Node credit balance |

Full error codes: `IICP-E001` through `IICP-E032`. See [error reference](https://iicp.network/docs/error-reference).

---

## Planned Tech Stack

- **Rust** (stable) + **Axum** — HTTP routing
- **SQLx** + **MySQL 8.0** — async database access
- **JWT HS256** — node authentication
- **Ed25519** — node event signing (ring or dalek)
- Target: single statically-linked binary, minimal dependencies

The goal is full API parity with `iicp-directory-php` with lower memory footprint and higher concurrency headroom — relevant for operators running the directory on embedded or edge infrastructure.

---

## Why Two Implementations?

| | PHP reference | Rust (this repo) |
|--|---------------|------------------|
| Status | Production | Planned |
| Best for | Standard hosting, rapid iteration | High-throughput, embedded, edge |
| Operator requirement | PHP-FPM + MySQL | Any Linux binary + MySQL |
| Spec compliance | Full | Planned full |

Both implementations MUST pass the same conformance test suite (REACH probes + `spec/conformance-test-suite.md`).

---

## Protocol Context

This implementation will target **IICP spec S.12** (Cooperative Inference Profile) and all Phase 1–5 normative requirements.

- Spec: `spec/iicp-core.md` in the main monorepo
- Reference implementation: [`iicp-directory-php`](https://github.com/RobLe3/iicp-directory-php)
- Live network: [https://iicp.network](https://iicp.network)

---

## Contributing

Implementation has not started. If you want to contribute or track progress:

1. Watch this repository for updates
2. Follow [iicp.network](https://iicp.network) for protocol news
3. Check the [Phase 5 milestone](https://github.com/RobLe3/iicp.network/milestone/5) for implementation gate requirements
4. Open an issue in `RobLe3/iicp.network` to discuss implementation approach

---

## See Also

- [`iicp-directory-php`](https://github.com/RobLe3/iicp-directory-php) — PHP reference implementation (production today)
- [`iicp.network`](https://github.com/RobLe3/iicp.network) — Monorepo: directory + adapter + proxy + website
- [iicp.network](https://iicp.network) — Live network and documentation

---

## License

Apache 2.0 — see `LICENSE`. Protocol is vendor-neutral; this implementation is the reference, not the standard.

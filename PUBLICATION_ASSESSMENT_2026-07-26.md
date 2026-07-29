# Rust directory publication assessment — 2026-07-29

## Decision

**READY FOR PUBLIC OPERATOR PREVIEW.** The exact `v0.1.2` source candidate
passed the publication checks below. This decision publishes source and release
assets only. It does not deploy Rust, cut over Genesis or deprecate PHP.

## Content-free evidence

- Gitleaks 8.30.1 full-history scan: zero findings.
- TruffleHog verified-only full-history scan: zero verified findings.
- `cargo fmt --check` and blocking Clippy with `-D warnings`: passed.
- `cargo test --locked`: 247 unit tests passed, with six disposable-MySQL tests
  excluded from the default lane; 13 external contract/parity tests passed.
- All six ignored concurrency tests passed separately against fresh disposable
  MySQL databases.
- RustSec passed after upgrading fixed dependencies. The only vulnerability
  exception is `RUSTSEC-2023-0071`, inherited through `sqlx-mysql`/`rsa`, for
  which RustSec lists no fixed release; IICP does not use RSA for protocol
  signing. The inherited `spin 0.9.8` yanked warning remains visible.
- Measured line coverage was 74.05%; the local publication lane blocks below
  the initial 70% ratchet.
- The locked release archive and manifest rebuilt successfully from the
  immutable tag. The container runs as fixed unprivileged identity
  `10001:10001`.
- Strict PHP/Rust checks passed against the same byte-identical HTTP and
  behavior fixtures under directory contract `v1.10.81`.

## Security and operational alignment

The preview now verifies TLS identity for registration and lifecycle probes,
requires persistent storage and signing material in production, refuses
unsigned production federation state, preserves the replica cursor on rejected
events, and grounds compliance attestations in stored probe evidence.
Development bypasses are explicit and cannot affect production.

The earlier SDK/REACH adoption observation window concerns live client
adoption. It is not evidence for, and does not block, publication of directory
source. Genesis remains the PHP implementation until a separate, explicit
cutover decision and live rehearsal.

## Provenance note

The `v0.1.0` tag is retained as a failed publication attempt: its compatibility
manifest gate did not complete and it has no release assets. `v0.1.2` is the current corrective operator-preview release; `v0.1.1` remains a valid earlier preview pinned to the failed PHP tag name and should not be used as the current compatibility reference.

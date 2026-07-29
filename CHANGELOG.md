# Changelog

## 0.1.0

- Makes production persistence fail closed when `DATABASE_URL` is absent.
- Verifies TLS identity for registration and lifecycle probes; insecure TLS is
  limited to an explicit local/testing fixture flag.
- Requires verified federation events in staging/production and prevents an
  unsigned snapshot from mutating a strict replica before seed-key resolution.
- Grounds compliance attestations in stored conformance probe evidence.
- Adds blocking formatting, Clippy, tests, a measured 70% line-coverage ratchet
  and RustSec checks to the local publication-quality lane.
- First public operator preview of the Rust directory implementation.
- Declares compatibility with the versioned PHP HTTP, behavior and schema
  fixtures listed in `compatibility/v0.1.0.json`.
- Includes disposable MySQL upgrade, rollback, recovery and non-root container
  evidence.
- Does not authorize a Genesis Seed cutover or PHP deprecation.

## v0.1.0 — operator-preview candidate

- Establishes Rust as the second official implementation flavor of the
  implementation-neutral IICP directory contract.
- Pins PHP `v1.10.80.1` normalized HTTP and behavior contracts.
- Implements durable MySQL schema adoption, signed-event and credit
  concurrency, transactional registration, discovery policy and DSR parity.
- Provides fixed non-root container execution and disposable
  upgrade/rollback/forward-recovery evidence.
- Remains pre-1.0 and does not authorize Genesis cutover or PHP deprecation.

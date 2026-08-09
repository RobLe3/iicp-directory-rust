# Changelog

## Unreleased

## 0.1.10 — 2026-08-09

- Repairs the nested replica-lifecycle fixture digest and adds recursive release
  compatibility validation for every fixture named by a parity contract.
- Accepts persisted no-op MySQL heartbeats after a locked node lookup instead
  of returning a false not-found result.
- Updates `event-listener` to the patched 5.4.2 line without adding a RustSec
  exception.
- Preserves operator-preview status and the immutable `v0.1.9` tag and assets.


## 0.1.9 — 2026-08-08

- Serialized reputation score, task-counter and hourly positive-gain updates
  in one database transaction, with bounded retries for transient MySQL
  deadlocks and lock timeouts.
- Added real-MySQL evidence that concurrent heartbeats share the persisted
  `+0.20` hourly gain budget across process and repository reloads.
- Corrected MySQL timestamp decoding for the locked hourly-window state.
- Preserved the operator-preview boundary and existing HTTP, OpenAPI and
  database-schema contracts.

## 0.1.8 — 2026-08-02

- Added separate provider implementation name/version and SDK compatibility
  version axes, with legacy alias support and conflicting dual values rejected.
- Advanced deployment compatibility metadata to OpenAPI 1.7.0 while preserving
  the operator-preview and Genesis cutover boundaries.

## 0.1.7 — 2026-08-01

- Advanced shared discovery release-currency evidence to SDK `0.7.101`.
- Pinned the PHP `v1.10.85` parity manifest without changing schema, wire
  behavior, or the operator-preview deployment boundary.

## 0.1.6

- Added PHP-compatible discovery evidence for health dimensions, Gold threshold
  state, latency basis, SDK currency and aggregate operator diversity.
- Preserved ranking, routing and the operator-preview boundary.

## 0.1.5

- Added `/iicp/health` for registration dial-back compatibility.
- Bound replica DID documents, deployment records and locally signed event
  metadata to the configured replica identity instead of the Genesis DID.
- Added authenticated, atomic replica decommissioning and same-DID low-trust
  reactivation with shared PHP/Rust contract fixtures.
- Added a launchd-compatible Quick Tunnel supervisor that keeps the stable DID
  separate from its rotating endpoint and reads secrets from a mode-0600 file.

## 0.1.4

- Corrects production replica bootstrap so verification-required replicas fetch
  and validate the authenticated S.13 snapshot before applying newer signed
  events.
- Rejects incomplete snapshot envelopes without mutating the replica database
  and never substitutes an incomplete public-tail reconstruction.
- Updates the persistent-shadow and authenticated-preflight procedures to
  require this immutable release.
- Does not change the shared HTTP or database contract and does not authorize
  replica registration, a persistent shadow, Genesis cutover or PHP
  deprecation.

## 0.1.3

- Aligns replica authentication with PHP `v1.10.82`: registration rotates a
  snapshot-scoped JWT, only its SHA-256 hash is stored, snapshots require the
  current token, and the signed event tail remains public. The former events
  scope is accepted for one compatibility window.
- Adds a byte-identical PHP/Rust replica-token contract fixture.
- Adds the signed `/.well-known/iicp-deployment.json` profile with the same
  canonical fixture, purpose separation and fail-closed verification behavior
  as the PHP directory.
- Refreshes the parity summary without rewriting the immutable HTTP and
  behavior fixture authority.
- Does not authorize Genesis cutover or production federation activation.

## 0.1.2

- Corrects the PHP compatibility baseline to `v1.10.81.2`. The accidentally
  published PHP `v1.10.81.1` tag identifies its previous main commit and is not
  a deployable release.
- Preserves the same Rust security behavior and byte-identical HTTP/behavior
  fixtures as v0.1.1.

## 0.1.1

- Corrective first public operator preview after the `v0.1.0` tag was pushed
  before its compatibility-manifest gate completed. The failed tag remains
  immutable and has no release assets.
- Includes the production persistence, TLS, federation, attestation and local
  quality-gate hardening described below.

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
  fixtures listed in `compatibility/v0.1.1.json`.
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

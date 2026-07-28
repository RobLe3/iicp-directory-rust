# Rust directory publication assessment — 2026-07-26

## Decision

**READY FOR FINAL v0.1.0 CANDIDATE GATES.** The technical
publication-preparation checks below pass, but this assessment does not claim
production equivalence with the PHP Genesis Seed.

## Content-free evidence

- The working tree and branch were clean before the assessment.
- Gitleaks 8.30.1 full-history scan: zero findings.
- TruffleHog verified-only full-history scan: zero verified findings.
- `cargo fmt --check`: passed.
- `cargo test --locked`: passed with 245 unit tests, 6 disposable-MySQL tests
  ignored in the default lane, and 12 external contract or parity tests.
- A clean locked release Docker build completed.
- The tracked tree contains source, migrations, schema/parity fixtures and
  public operator documentation; it contains no environment file, credential,
  backup, production database or operator dataset.

## Publication corrections

- CI actions and Docker base images are pinned to reviewed immutable digests.
- CI now builds the locked Docker image in addition to formatting and tests.
- Cargo repository metadata names the dedicated Rust directory repository.
- Docker context exclusions prevent local Git, target, environment and backup
  state from entering image builds.

## Remaining gate

Before any visibility change, rerun both history scanners against the exact
candidate commit, verify the clean release gates, and complete the
preregistered observation window. Publication exposes the second official directory
implementation flavor as a pre-1.0 operator preview. It would not deploy it,
cut over the Genesis Seed, deprecate PHP, publish the IICP website or establish
independent multi-root federation.

## 2026-07-27 operator-evidence addendum

The candidate image now runs as fixed unprivileged identity `10001:10001`.
A disposable local rehearsal passed with a read-only root filesystem, all
capabilities dropped and `no-new-privileges`: baseline → candidate upgrade,
baseline rollback and candidate forward recovery all preserved the synthetic
database sentinel. Both images completed 200 content-free read-path samples
with zero failures; candidate p95 was 3.308 ms versus 3.198 ms for the baseline,
within the fixed 10% guard. These host-local measurements are regression
evidence only, not a production capacity claim or visibility authorization.

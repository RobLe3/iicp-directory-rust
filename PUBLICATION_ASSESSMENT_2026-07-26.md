# Rust directory publication assessment — 2026-07-26

## Decision

**DEFER pending explicit maintainer authorization.** The technical
publication-preparation checks below pass, but this assessment does not change
repository visibility or claim production equivalence with the PHP Genesis
Seed.

## Content-free evidence

- The working tree and branch were clean before the assessment.
- Gitleaks 8.30.1 full-history scan: zero findings.
- TruffleHog verified-only full-history scan: zero verified findings.
- `cargo fmt --check`: passed.
- `cargo test --locked`: passed with 237 unit tests and 8 external contract or
  parity tests.
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
candidate commit, verify the clean CI run, and obtain an explicit maintainer
decision. Publication would expose a pre-1.0 reference implementation only; it
would not deploy it, cut over the Genesis Seed, publish the IICP website or
establish independent multi-root federation.

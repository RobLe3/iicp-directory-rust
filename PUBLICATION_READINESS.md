# Publication readiness

The repository may be published as a pre-1.0 implementation when:

- current and full-history secret scans are resolved;
- `cargo fmt --check` and `cargo test --locked` pass from a clean checkout;
- PHP/Rust parity fixtures and runtime gates pass;
- production topology, credentials, backups and operator data are absent;
- the README accurately distinguishes route parity from production equivalence;
- the maintainer explicitly authorizes the visibility change.

Publication is not a production cutover.

The dated assessment in `PUBLICATION_ASSESSMENT_2026-07-26.md` records the
current evidence and remaining authorization gate. Passing technical checks
does not change repository visibility.

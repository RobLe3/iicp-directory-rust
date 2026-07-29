# Publication readiness

The repository may be published as a pre-1.0 implementation when:

- current and full-history secret scans are resolved;
- formatting, blocking Clippy, locked tests, the coverage ratchet and RustSec pass from a clean checkout;
- PHP/Rust parity fixtures and runtime gates pass;
- the non-root, read-only operator distribution rehearsal passes locally;
- production topology, credentials, backups and operator data are absent;
- the README accurately distinguishes route parity from production equivalence;
- the maintainer explicitly authorizes the visibility change.

Publication is not a production cutover or evidence of independent
multi-operator federation.

The dated assessment in `PUBLICATION_ASSESSMENT_2026-07-26.md` records the
candidate evidence. Client-adoption or REACH observation windows are separate
live-system evidence and do not gate source visibility.

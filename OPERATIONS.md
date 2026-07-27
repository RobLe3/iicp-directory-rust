# Self-host operations

The Rust directory uses an in-memory repository when `DATABASE_URL` is absent
and MySQL when it is configured. In-memory operation is for development and
does not provide durable recovery.

For MySQL operation, create an encrypted off-host backup before and after every
migration or maintenance operation. Restore tests must use a new disposable
database rather than overwriting a running instance.

```bash
umask 077
mkdir -p backups
mysqldump --single-transaction --routines --triggers \
  --host="$DB_HOST" --user="$DB_USER" --password \
  "$DB_DATABASE" | gzip > "backups/iicp-directory-pre-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
```

Keep backups, signing keys and database credentials outside the repository and
web-accessible paths. Credits, reputation, identity and signed lifecycle
evidence require explicit retention decisions and must not be treated as raw
telemetry.

## Hardened container profile

The release image runs as fixed unprivileged identity `10001:10001`. A
production orchestrator should additionally use a read-only root filesystem,
drop all Linux capabilities, set `no-new-privileges`, and provide only a small
non-executable `/tmp` tmpfs if the platform requires one. Database and signing
credentials remain runtime secrets; never bake them into the image.

Before considering an operator release, run the disposable evidence lane:

```bash
IICP_RUST_BASELINE_REF=main \
  IICP_RUST_DISTRIBUTION_REPORT=/tmp/iicp-rust-distribution.json \
  ./ops/run_distribution_evidence.sh
```

The lane builds the baseline and candidate from locked source, verifies the
non-root/read-only profile, rehearses baseline → candidate → baseline →
candidate recovery against disposable MySQL, and compares 200 content-free
read-path samples per image. It fails on any 5xx response or candidate p95
regression above 10%. The retained report contains only image digests,
aggregate timings and pass/fail flags; it is not production capacity evidence
or deployment authorization.

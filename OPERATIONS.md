# Self-host operations

The Rust directory requires `DATABASE_URL` in production. Disposable in-memory
operation requires both a non-production `APP_ENV` and
`IICP_ALLOW_IN_MEMORY=true`; it does not provide durable recovery. Production
startup fails rather than silently losing directory state.

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
credentials remain runtime secrets; never bake them into the image. Production
startup requires both `DATABASE_URL` and a valid 128-hex
`IICP_GENESIS_ED25519_SECRET_KEY`.

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

## Production trust boundaries

TLS certificates are verified during registration dial-back and lifecycle
probes. `IICP_DEV_ALLOW_INSECURE_TLS=true` is accepted only in `local` or
`testing`; production always verifies peer identity.

Replica mode requires signed events in staging and production. Until the seed
signing key is available, the replica waits without applying a snapshot or
advancing its cursor. `IICP_DEV_ALLOW_UNSIGNED_EVENTS=true` is limited to local
and testing fixtures.

Compliance attestations are issued only when stored conformance probe evidence
exists and a directory signing key is configured. Missing evidence or signing
material fails closed; an empty signed success record is never emitted.

## Signed deployment record

Set deployment provenance from an immutable release artifact, not from a
mutable checkout:

```bash
export IICP_DEPLOYMENT_KIND=container
export IICP_RELEASE_TAG="${VERIFIED_RELEASE_TAG:?set a verified immutable release tag}"
export IICP_SOURCE_COMMIT=<40-hex-release-commit>
export IICP_BUILD_ID=sha256:<artifact-digest>
export IICP_DEPLOYED_AT=<RFC3339-UTC-time>
export IICP_ROOT_KEY_ID=did:web:directory.example#key-1
```

Set `IICP_IMAGE_DIGEST` and `IICP_SBOM_DIGEST` when those artifacts exist.
Otherwise the signed record reports them as `null`. Verify
`/.well-known/iicp-deployment.json` against the public release assets and DID
key before advertising the directory. The record contains no database,
hostname, path or credential information.

## Persistent replica shadow

The Genesis-cutover evidence lane is documented in
[`ops/PERSISTENT_SHADOW.md`](ops/PERSISTENT_SHADOW.md). It provides an
environment template and a content-free PHP/Rust observer. Preparing or testing
that lane does not authorize starting a persistent service; the seven-day
observation window requires explicit maintainer approval.

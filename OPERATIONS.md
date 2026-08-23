# Self-host operations

The Rust directory requires `DATABASE_URL` in production. Disposable in-memory
operation requires both a non-production `APP_ENV` and
`IICP_ALLOW_IN_MEMORY=true`; it does not provide durable recovery. Production
startup fails rather than silently losing directory state.

## Process supervision and runtime health

The directory separates three concerns. The background supervisor repairs or
retries directory-specific work. The runtime-health core records local Tokio
and supervisor progress. The operating system owns final process restart.
Directory, DNS or network loss must not by itself classify the local process
as dead.

For a user-level systemd installation:

```bash
umask 077
cat > "$HOME/.config/iicp-directory.env" <<'EOF'
DATABASE_URL=mysql://user:password@127.0.0.1/iicp_directory
IICP_GENESIS_ED25519_SECRET_KEY=<operator-managed-secret>
APP_ENV=production
# Optional restricted-domain deployment. All values are required together.
# IICP_RESTRICTED_DOMAIN_ENABLED=true
# IICP_TRUST_DOMAIN_ID=example.internal
# IICP_TRUST_DOMAIN_AUTHORITY_ID=did:web:directory.example
# IICP_TRUST_DOMAIN_MEMBERSHIP_EPOCH=1
# IICP_TRUST_DOMAIN_MAX_CREDENTIAL_TTL=86400
EOF
chmod 600 "$HOME/.config/iicp-directory.env"

iicp-directory-rs service install \
  --env-file "$HOME/.config/iicp-directory.env"
```

This installs a foreground user service with bounded restart-storm settings.
It does not change lingering, create a system-wide service, or enable the
native watchdog. Inspect effective properties with `service status` and check
lingering separately with `loginctl show-user "$USER" -p Linger`.

Native notification is opt-in. Use `--notify` only with a Linux binary built
with the default `systemd-notify` feature. Add `--watchdog-sec` only after
measuring runtime cadence on representative hardware. A notification pulse is
withheld when local runtime or supervisor progress is stale; remote outages do
not cause a watchdog restart loop.

`/iicp/health` retains its established registration dial-back behavior. The
local `healthcheck` command reads a private, versioned snapshot instead:

```bash
iicp-directory-rs healthcheck
iicp-directory-rs healthcheck --ready --json
```

## Guarded operator-preview updates

Read-only update discovery is available in the binary:

```bash
iicp-directory-rs update check --json
```

The repository also ships `scripts/directory_self_update.sh`. Its staged mode
downloads the crate, compares the crates.io checksum with the GitHub release
manifest, installs into a versioned release directory, verifies the existing
database schema with the candidate, switches the stable symlink, restarts the
user service and checks the local health response. A failed restart or health
check restores the previous symlink.

```bash
scripts/directory_self_update.sh --check
scripts/directory_self_update.sh --staged \
  --env-file "$HOME/.config/iicp-directory.env" --dry-run
```

Run staged mutation only from a reviewed release. Publication does not enable
automatic updates, deploy a replica, change Genesis authority or authorize
federation.

An optional daily systemd user timer invokes the same guarded updater. It is
not installed by the crate or service command:

```bash
scripts/directory_self_update.sh --install-timer \
  --env-file "$HOME/.config/iicp-directory.env" --dry-run
# Remove an installed timer with --remove-timer.
```

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

## Restricted trust-domain lifecycle

Restricted mode is disabled by default. Before enabling it, record the opaque
domain identifier, directory authority identifier, authority verification
method and membership epoch in the operator change record. Keep the Ed25519
signing secret in the same protected secret store used by the directory; do not
place it in a portable configuration bundle. Startup rejects incomplete
restricted-domain configuration, in-memory persistence and replica/federation
mode rather than falling back to public behavior.

Issue the minimum scopes needed by each participant. Supplying a subject key
creates the peer-verifiable assertion needed for bootstrap or gossip; bearer
membership remains limited to protected directory requests.

```bash
iicp-directory-rs trust-domain-membership-issue \
  --kind node --subject node-1 \
  --scopes registration,heartbeat,bootstrap,peers \
  --subject-key-id 'did:key:node-1#key-1' \
  --subject-public-key BASE64URL_ED25519_PUBLIC_KEY

iicp-directory-rs trust-domain-membership-issue \
  --kind client --subject client-1 --scopes discovery,dispatch
```

The bearer credential is printed once. Deliver it through an authenticated
out-of-band channel and store only a secret reference in automation. Rotation
issues a new generation for the same domain, kind and subject. Confirm that the
new credential works before removing the old secret reference; the persisted
record makes the prior credential invalid.

```bash
iicp-directory-rs trust-domain-membership-revoke \
  --kind node --subject node-1
```

Revocation affects new protected operations immediately. Peer caches must also
enforce assertion expiry and the configured minimum generation; absence from a
partial bootstrap response is not, by itself, revocation. Raising
`IICP_TRUST_DOMAIN_MEMBERSHIP_EPOCH` invalidates every older generation and is
therefore an emergency domain-wide operation, not routine rotation.

Backups of a restricted directory contain membership records and signed peer
assertions. Protect them as authorization data. A restore rehearsal must use a
new disposable database, the same domain/authority identity and an authorized
copy of the signing key. Before service traffic is enabled, verify schema
version, current epoch, revoked records, assertion expiry and one authorized
and one unauthorized request. Do not restore into a different domain by
editing membership rows.

Loss or suspected compromise of the directory signing key requires stopping
new enrollment and assertion issuance. Restore a verified key backup or create
a reviewed authority-rotation plan that reissues assertions and updates every
trust anchor; changing only the configured key while retaining old assertions
is not a recovery procedure. If current revocation or authority state cannot be
established, keep restricted mode unavailable rather than starting public mode.

The Rust directory remains an operator preview. Restricted mode does not
authorize Genesis activation, cross-domain federation, or a PHP-to-Rust
cutover. A shared PHP/Rust migration must use the authoritative PHP migration
sequence and disposable rollback evidence; do not run both flavors as writers
against an unreviewed membership schema.

## Optional local directory advertisement

Local DNS-SD advertisement is disabled by default. To expose this directory as
a candidate on the local link, configure its stable DID, HTTPS API endpoint and
signing key, then set:

```text
IICP_LOCAL_DIRECTORY_ADVERTISE=true
IICP_LOCAL_DIRECTORY_HOSTNAME=iicp-directory.local.
IICP_LOCAL_DIRECTORY_PORT=443
IICP_LOCAL_DIRECTORY_INSTANCE=IICP Directory
IICP_LOCAL_DIRECTORY_ROLE=standalone
```

The process publishes `_iicp-dir._tcp.local.` with bounded bootstrap hints and
serves a signed, five-minute descriptor at
`/.well-known/iicp-directory.json`. The instance label, SRV address and TXT DID
are observations, not identity or authorization. A client must still validate
TLS, the descriptor signature, the DID and its configured trust policy before
sending credentials. `IICP_OPERATING_MODE=local_only` rejects advertisement,
and incomplete HTTPS or signing configuration fails startup when advertisement
is requested. Changing advertisement settings requires a supervised restart;
graceful shutdown withdraws the service.

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
## Effective-capability schema upgrade

The runtime bootstraps a genuinely empty database but never mutates an existing
one. Before running a build that includes the effective-capability Profile over
an existing standalone preview database, back up the database and apply the
reviewed `migrations/022_add_effective_capability_fields.sql` change. Startup
then verifies the complete embedded schema contract and fails closed if the
upgrade is missing or partial. A shared PHP/Rust deployment must use the
authoritative PHP migration sequence rather than replaying this standalone SQL.

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

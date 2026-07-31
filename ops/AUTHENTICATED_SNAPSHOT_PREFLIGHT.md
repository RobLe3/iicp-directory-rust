# Authenticated Genesis snapshot preflight

This packet defines the next disposable Rust federation check. It does not
authorize the production write, start a persistent service or approve a
Genesis cutover.

## Requested production action

After explicit maintainer approval, one disposable Rust `v0.1.3` candidate may
send `POST /api/v1/replicas/register` to the PHP Genesis Seed using a distinct
replica DID and HTTPS endpoint. Registration creates or rotates the replica
record and returns a 90-day bearer scoped to `GET /v1/snapshot`. The token must
exist only in the external mode-`0600` environment and process memory.

The candidate then fetches one authenticated snapshot, validates its complete
S.13 §5.5 envelope, applies it only to an empty disposable database, and tails
newer public events with Genesis Ed25519 verification. Genesis snapshots rely
on the protocol's TLS+DNS trust boundary; public tail events still fail closed
on missing or invalid signatures.

## Required inputs

- verified Rust directory `v0.1.3` release artifact and checksums;
- a new empty MySQL database and account;
- a new APP key and Ed25519 signing identity;
- a distinct `did:web` document and HTTPS endpoint;
- an encrypted evidence and backup target outside every repository;
- the exact Genesis deployment record and DID key observed immediately before
  registration.

No Genesis database, APP key, signing key, replica token, node token, backup or
virtual host may be reused.

## Stop conditions

Stop and destroy the disposable runtime if registration, DID resolution, TLS,
snapshot authorization, envelope validation, event signature verification or
hash-chain verification fails. Also stop on unexplained node-count/schema
divergence, route disclosure, snapshot/event sequence regression or any write
outside the single replica-registration request.

Do not fall back from a failed authenticated snapshot to a partial event-tail
reconstruction. A configured replica must retain an empty local database and
retry the snapshot without serving discovery.

## Retained evidence

Retain only timestamps, release and deployment digests, schema names,
aggregate row counts, snapshot/event sequence ranges, lag, signature and chain
outcomes, restart outcome, and parity booleans. Do not retain the bearer,
replica identifier, node identifiers, endpoints, routes, keys, payloads or
result rows.

Passing this preflight permits a separate request to start the seven-day
persistent-shadow window described in `PERSISTENT_SHADOW.md`. It does not make
Rust Genesis authority.

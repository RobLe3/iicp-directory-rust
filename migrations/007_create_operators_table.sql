-- #463/#310/#464 — operator-identity record, keyed by operator_id (== the ed25519
-- operator_pubkey verified via the ADR-045 delegation). One row per operator; the single
-- source of truth for the public display_name (node detail + recognition leaderboard).
-- PHP-directory parity (#385): directory/database/migrations/2026_06_05_150000_create_operators_table.php.
--
-- operator_pubkey: PRIVATE — never exposed in a public API response.
-- display_name: PUBLIC, mutable (operator-signed via a delegated re-register).
-- operator_integrity_hash = SHA256(operator_id ':' created_at): self-attested, pinned on
--   first register for tamper detection. A self-claimed created_at is backdatable, so it is
--   NEVER authoritative for ordinals.
-- first_seen_ms: DIRECTORY-observed; authoritative for founder ordinal/tier timing.
-- ordinal/tier/badge/provenance: #310 founder recognition (nullable until lock-in).

CREATE TABLE IF NOT EXISTS operators (
    id                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    operator_pubkey          VARCHAR(64)  NOT NULL,
    display_name             VARCHAR(64)  NULL,
    attested_created_at      VARCHAR(40)  NULL,
    operator_integrity_hash  CHAR(64)     NULL,
    first_seen_ms            BIGINT UNSIGNED NULL,
    ordinal                  BIGINT UNSIGNED NULL,
    tier                     VARCHAR(32)  NULL,
    badge                    VARCHAR(32)  NULL,
    provenance               JSON         NULL,
    created_at               TIMESTAMP    NULL,
    updated_at               TIMESTAMP    NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_operators_pubkey (operator_pubkey)
);

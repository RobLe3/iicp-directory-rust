-- #441 — trusted-replicas registry. Mirrors the PHP Laravel `replicas` table
-- (2026_05_25_200000_create_replicas_table.php) so the Rust replica records
-- REPLICA_REGISTERED events at full state fidelity (FEDERATION_TEST_PROTOCOL Stage 3).
--
-- A replica is keyed by its DID (natural key); replica_id is the surrogate UUID the
-- seed issued. trust_tier starts 'unverified'/'low' and is promoted by governance.

CREATE TABLE IF NOT EXISTS replicas (
    id                  BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT PRIMARY KEY,
    replica_id          CHAR(36)            NOT NULL UNIQUE,
    did                 VARCHAR(253)        NOT NULL UNIQUE,
    endpoint            VARCHAR(255)        NOT NULL,
    trust_tier          VARCHAR(16)         NOT NULL DEFAULT 'low',
    -- SHA-256 hash of the issued replica_token; never the plaintext. Empty on a
    -- replica-applied REPLICA_REGISTERED event (the replica didn't issue the token).
    replica_token_hash  VARCHAR(64)         NOT NULL DEFAULT '',
    expires_at          TIMESTAMP           NULL,
    last_seen_at        TIMESTAMP           NULL,
    created_at          TIMESTAMP           NULL,
    updated_at          TIMESTAMP           NULL,
    KEY idx_trust_tier (trust_tier)
);

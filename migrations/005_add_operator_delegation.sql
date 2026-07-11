-- ADR-045 Phase A (#407) — operator→node delegation binding, PHP-directory parity (#385).
-- Mirrors directory/database/migrations/2026_06_03_110000_add_operator_identity_to_nodes.php:
--   operator_pubkey VARCHAR(64) NULL, operator_verified BOOLEAN DEFAULT 0,
--   operator_trust_tier VARCHAR(16) NULL, plus an index on operator_pubkey.
-- Set at register when a valid ed25519 delegation is verified (src/delegation.rs); the
-- directory records the bound operator identity so it survives a restart.

ALTER TABLE nodes
    ADD COLUMN operator_pubkey     VARCHAR(64) NULL          AFTER operator_contact,
    ADD COLUMN operator_verified   TINYINT(1)  NOT NULL DEFAULT 0 AFTER operator_pubkey,
    ADD COLUMN operator_trust_tier VARCHAR(16) NULL          AFTER operator_verified;

CREATE INDEX nodes_operator_pubkey_idx ON nodes (operator_pubkey);

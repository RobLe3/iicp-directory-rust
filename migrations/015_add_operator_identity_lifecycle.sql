-- #618 — accountless operator-key lifecycle parity with the Laravel seed.
-- Operator public keys remain directory-private.  Historical rows are retained
-- as evidence while inactive identities fail closed for future self-service.

ALTER TABLE operators
    ADD COLUMN identity_status VARCHAR(16) NOT NULL DEFAULT 'active' AFTER operator_pubkey,
    ADD COLUMN successor_operator_pubkey_sha256 CHAR(64) NULL AFTER identity_status,
    ADD COLUMN rotation_epoch INT UNSIGNED NULL AFTER successor_operator_pubkey_sha256,
    ADD COLUMN identity_revoked_at TIMESTAMP NULL AFTER rotation_epoch,
    ADD COLUMN identity_reason_class VARCHAR(64) NULL AFTER identity_revoked_at;

CREATE INDEX operators_identity_status_idx ON operators (identity_status);

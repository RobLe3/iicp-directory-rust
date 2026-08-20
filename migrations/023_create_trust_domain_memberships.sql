CREATE TABLE IF NOT EXISTS trust_domain_memberships (
    id CHAR(36) NOT NULL PRIMARY KEY,
    domain_id VARCHAR(191) NOT NULL,
    subject_kind VARCHAR(16) NOT NULL,
    subject_id VARCHAR(191) NOT NULL,
    issuer_id VARCHAR(191) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    scopes JSON NOT NULL,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL,
    UNIQUE KEY trust_domain_membership_subject_unique (domain_id, subject_kind, subject_id),
    UNIQUE KEY trust_domain_memberships_token_hash_unique (token_hash),
    INDEX trust_domain_membership_validity_index (domain_id, revoked_at, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

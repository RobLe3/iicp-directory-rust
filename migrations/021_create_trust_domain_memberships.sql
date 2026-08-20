CREATE TABLE IF NOT EXISTS trust_domain_memberships (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain_id VARCHAR(255) NOT NULL,
    issuer_id VARCHAR(255) NOT NULL,
    subject_kind VARCHAR(16) NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    scopes JSON NOT NULL,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY trust_domain_subject_unique (domain_id, subject_kind, subject_id),
    UNIQUE KEY trust_domain_token_unique (token_hash),
    INDEX trust_domain_current (domain_id, expires_at, revoked_at, generation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

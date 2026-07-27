-- SPDX-License-Identifier: Apache-2.0
-- Historical evidence only: runtime schema management is bootstrap-or-verify.
CREATE TABLE node_event_chain_heads (
    chain_id VARCHAR(32) PRIMARY KEY,
    last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_signature VARCHAR(128) NULL,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO node_event_chain_heads
    (chain_id, last_seq, last_signature, created_at, updated_at)
SELECT 'genesis', COALESCE(t.seq, 0), t.signature, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM (SELECT 1) AS seed
LEFT JOIN (
    SELECT seq, signature FROM node_events ORDER BY seq DESC LIMIT 1
) AS t ON TRUE;

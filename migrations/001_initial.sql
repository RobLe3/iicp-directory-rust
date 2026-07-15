-- IICP Directory — consolidated initial schema.
-- Mirrors the PHP Laravel migrations (2026_05_14 baseline + all subsequent
-- denormalization passes) so this crate can share a database with the PHP
-- reference implementation during the transition period (L6.1 / issue #291).
--
-- Run automatically on startup via sqlx::migrate!() when DATABASE_URL is set.

CREATE TABLE IF NOT EXISTS nodes (
    id              CHAR(36)            NOT NULL PRIMARY KEY,
    endpoint        VARCHAR(255)        NOT NULL,
    region          VARCHAR(64)         NOT NULL DEFAULT '',
    `load`          FLOAT               NOT NULL DEFAULT 0.0,
    active_jobs     INT UNSIGNED        NOT NULL DEFAULT 0,
    available       TINYINT(1)          NOT NULL DEFAULT 1,
    last_seen       TIMESTAMP           NULL,
    -- Phase 4 (auth): store bcrypt hash. Phase 1 stores plain token as placeholder.
    node_token_hash VARCHAR(512)        NOT NULL DEFAULT '',
    -- HMAC secret for credit receipt verification (W-009, iicp-dir §6.2). Hex-encoded.
    node_hmac_key   VARCHAR(64)         NOT NULL DEFAULT '',
    max_concurrent  INT UNSIGNED        NOT NULL DEFAULT 0,
    tokens_per_min  INT UNSIGNED        NOT NULL DEFAULT 0,
    -- Denormalized from reputations (W-042 / D2prime)
    reputation_score          FLOAT             NOT NULL DEFAULT 0.5,
    tasks_total               INT UNSIGNED      NOT NULL DEFAULT 0,
    tasks_failed              INT UNSIGNED      NOT NULL DEFAULT 0,
    avg_latency_ms            FLOAT             NOT NULL DEFAULT 0.0,
    -- RT-01b (#381): per-node hourly reputation velocity ceiling
    rep_hourly_gain           DECIMAL(8,4)      NOT NULL DEFAULT 0,
    rep_hourly_window_start   TIMESTAMP         NULL,
    -- Denormalized from credits (W-042 / D1prime)
    credit_balance              DECIMAL(15,4) NOT NULL DEFAULT 0.0000,
    free_credit_last_allocation_at TIMESTAMP NULL,
    -- Rolling window (reputation decay context)
    tasks_total_recent   INT UNSIGNED   NOT NULL DEFAULT 0,
    tasks_failed_recent  INT UNSIGNED   NOT NULL DEFAULT 0,
    avg_latency_ms_recent FLOAT         NOT NULL DEFAULT 0.0,
    recent_window_start  TIMESTAMP      NULL,
    -- NAT / transport (ADR-043 + nat traversal)
    transport_method  VARCHAR(32)       NULL,
    nat_type          VARCHAR(32)       NULL,
    transport_endpoint VARCHAR(255)     NULL,
    public_reachable  TINYINT(1)        NOT NULL DEFAULT 0,
    -- ADR-022: node can forward tasks to peers on behalf of consumers (PHP parity
    -- — directory/.../add_relay_capable_to_nodes.php). Feeds NodeHealthService
    -- reachability fallback (#385 Phase-B): public_reachable→1.0, else relay→0.5.
    relay_capable     TINYINT(1)        NOT NULL DEFAULT 0,
    -- SDK info
    sdk_language   VARCHAR(32)          NULL,
    sdk_version    VARCHAR(32)          NULL,
    -- Informational local backend flavour; no peer/topology/control-plane data.
    backend        VARCHAR(32)          NULL,
    -- ADR-043 exposure classification
    exposure_mode  VARCHAR(36)          NULL,
    -- Credit pricing (iicp-dir §6.4 — multiplier of base 1.0 credits/1000 tokens)
    credit_cost_multiplier FLOAT        NOT NULL DEFAULT 1.0,
    -- ADR-019 pricing model + attestation flag (#400 — surfaced on /v1/discover, PHP parity)
    pricing_model  VARCHAR(32)          NULL DEFAULT 'per_token',
    attested       TINYINT(1)           NOT NULL DEFAULT 0,
    -- Proxy authentication token (ProxyTokenAuth — separate from node_token)
    proxy_token_hash   VARCHAR(512)     NOT NULL DEFAULT '',
    -- ADR-017 public registry opt-in
    public_listing    TINYINT(1)        NOT NULL DEFAULT 0,
    operator_url      VARCHAR(256)      NULL,
    operator_contact  VARCHAR(256)      NULL,
    -- Lifecycle (ExpireStaleNodes cron)
    status         VARCHAR(32)          NOT NULL DEFAULT 'active',
    dormant_since  TIMESTAMP            NULL,
    created_at     TIMESTAMP            NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP            NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_available  (available),
    INDEX idx_last_seen  (last_seen),
    INDEX idx_region     (region),
    INDEX idx_compound   (available, reputation_score, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_telemetry (
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    node_id           CHAR(36)       NOT NULL,
    proxy_node_id     CHAR(36)       NOT NULL,
    time_bucket       BIGINT UNSIGNED NOT NULL DEFAULT 0, -- floor(unix_ts/60)*60
    latency_ms_observed INT UNSIGNED  NULL,
    tokens_observed   INT UNSIGNED   NULL,
    status            VARCHAR(16)    NOT NULL DEFAULT 'ok',
    qos_advertised    FLOAT          NULL,
    qos_met           TINYINT(1)     NULL,
    created_at        TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_node_proxy_bucket (node_id, proxy_node_id, time_bucket),
    INDEX idx_node_7d (node_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS probe_tokens (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    token_hash     CHAR(64)       NOT NULL UNIQUE,  -- SHA-256 hex of the probe token
    label          VARCHAR(64)    NOT NULL DEFAULT '',
    region         VARCHAR(32)    NULL,
    expires_at     TIMESTAMP      NULL,
    last_seen_at   TIMESTAMP      NULL,
    created_at     TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS iicp_telemetry_probes (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    probe_token_id BIGINT UNSIGNED NULL,
    run_id         VARCHAR(64)    NOT NULL DEFAULT '',
    probe_id       VARCHAR(64)    NOT NULL DEFAULT '',
    probe_type     VARCHAR(32)    NOT NULL DEFAULT '',
    test_id        VARCHAR(64)    NULL,
    level          VARCHAR(16)    NOT NULL DEFAULT 'info',
    passed         TINYINT(1)     NOT NULL DEFAULT 0,
    latency_ms     INT UNSIGNED   NULL,
    detail         TEXT           NULL,
    metadata       JSON           NULL,
    probed_at      TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_run_id  (run_id),
    INDEX idx_probe_id (probe_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS node_events (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_id     CHAR(36)       NOT NULL,
    seq          BIGINT UNSIGNED NOT NULL DEFAULT 0,
    event_type   VARCHAR(64)    NOT NULL,
    node_id      CHAR(36)       NOT NULL,
    ts_ms        BIGINT UNSIGNED NOT NULL,
    payload      JSON           NULL,
    signature    VARCHAR(512)   NULL,
    created_at   TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_node_event (node_id, event_type, ts_ms),
    INDEX idx_event_id   (event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS node_address_history (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    node_id        CHAR(36)       NOT NULL,
    ip_address     VARCHAR(45)    NOT NULL,
    request_type   VARCHAR(32)    NOT NULL DEFAULT 'register',
    observed_at    TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_node_addr (node_id, observed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS conformance_badges (
    badge_id         CHAR(36)       NOT NULL PRIMARY KEY,
    tier             VARCHAR(16)    NOT NULL,  -- bronze/silver/gold/platinum
    subject_did      VARCHAR(255)   NULL,
    subject_component VARCHAR(32)   NOT NULL DEFAULT 'directory',
    suite_version    VARCHAR(32)    NOT NULL DEFAULT '',
    passed_at        TIMESTAMP      NULL,
    expires_at       TIMESTAMP      NULL,
    test_results_url VARCHAR(255)   NULL,
    issuer_did       VARCHAR(255)   NULL,
    status           VARCHAR(16)    NOT NULL DEFAULT 'pending',
    created_at       TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tier_status (tier, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS credit_transactions (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    node_id      CHAR(36)       NOT NULL,
    amount       DECIMAL(15,4)  NOT NULL,
    type         VARCHAR(16)    NOT NULL DEFAULT 'credit', -- 'credit' | 'debit' | 'free'
    task_id      VARCHAR(255)   NULL,
    nonce        VARCHAR(64)    NULL,                      -- dedup key (RT-02)
    reason       VARCHAR(255)   NULL,
    created_at   TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_node_id (node_id),
    INDEX idx_nonce (nonce)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS capabilities (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    node_id          CHAR(36)       NOT NULL,
    intent           VARCHAR(255)   NOT NULL,
    models           JSON           NOT NULL,
    max_tokens       INT UNSIGNED   NOT NULL DEFAULT 0,
    -- Advisory per iicp-core.md §2.1 (issue #118); directory MUST NOT reject unknowns
    quantization     VARCHAR(32)    NULL,
    inference_engine VARCHAR(32)    NULL,
    created_at       TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    INDEX idx_node_intent (node_id, intent),
    INDEX idx_intent      (intent)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- RT-02b IP-level free credit gate (#380): one row per source IP.
-- Prevents harvest by registering a new node_id from the same IP within the 6h window.
CREATE TABLE IF NOT EXISTS credit_ip_gates (
    ip_address            VARCHAR(45)    NOT NULL,
    last_allocation_at    TIMESTAMP      NULL,
    allocation_count      INT UNSIGNED   NOT NULL DEFAULT 0,
    created_at            TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP      NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_address),
    INDEX idx_last_allocation (last_allocation_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

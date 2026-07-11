-- Rolling probe metric aggregates — matches PHP 2026_05_16_100000_create_telemetry_tables.php.
-- Populated by the REACH aggregation job (5-minute cadence). Empty until REACH is active.
CREATE TABLE IF NOT EXISTS iicp_telemetry_aggregates (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    window        VARCHAR(8)      NOT NULL,          -- '1h' | '24h' | '7d'
    metric        VARCHAR(64)     NOT NULL,           -- e.g. 'discover_p50_ms'
    value         FLOAT           NULL,
    sample_count  INT             NOT NULL DEFAULT 0,
    computed_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_agg_window_metric_at (window, metric, computed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

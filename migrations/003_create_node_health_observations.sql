-- ADR-048 (#374) — federation-aware mesh_health. Per-node, per-evaluator health
-- snapshots replicated via the signed HEALTH event (S.13 §3.4). Mirrors the PHP
-- Laravel migration `2026_06_04_100000_create_node_health_observations_table.php`
-- so PHP and Rust replicas share an identical schema.
--
-- One row per (node_id, evaluator_did): the latest snapshot that evaluator published
-- for that node. The mesh_health read resolves each node's canonical value by
-- majority-vote across evaluators (fallback most-recent by evaluated_at_ms).

CREATE TABLE IF NOT EXISTS node_health_observations (
    id              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT PRIMARY KEY,
    node_id         CHAR(36)            NOT NULL,
    -- The directory (seed or replica) that produced this health vector.
    evaluator_did   VARCHAR(255)        NOT NULL,
    -- Per-node health score on the wire scale [0,1] (ADR-044 forNode score/100).
    score           FLOAT               NOT NULL,
    label           VARCHAR(32)         NULL,
    components       JSON                NULL,
    -- Producer-stamped evaluation time — the monotonic key for staleness resolution.
    evaluated_at_ms BIGINT UNSIGNED     NOT NULL,
    -- Provenance: the HEALTH event that last wrote this row.
    event_id        CHAR(36)            NULL,
    created_at      TIMESTAMP           NULL,
    updated_at      TIMESTAMP           NULL,
    -- Exactly one current snapshot per (node, evaluator).
    UNIQUE KEY uq_node_evaluator (node_id, evaluator_did),
    KEY idx_node (node_id),
    KEY idx_evaluated_at (evaluated_at_ms)
);

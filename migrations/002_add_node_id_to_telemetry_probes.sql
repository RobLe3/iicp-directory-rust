-- #373 — per-node attribution for telemetry probes (parity with the PHP directory's
-- 2026_06_02_100000_add_node_id_to_telemetry_probes migration).
-- Directory-infra probes keep node_id NULL; per-node reachability/health probes set it
-- to the probed node's id. Nullable + indexed for per-node health queries.
ALTER TABLE iicp_telemetry_probes
    ADD COLUMN node_id VARCHAR(36) NULL AFTER probe_token_id;

ALTER TABLE iicp_telemetry_probes
    ADD INDEX idx_node_probed (node_id, probed_at);

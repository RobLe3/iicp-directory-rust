-- Portability-first event origin metadata (#624).
-- NULL preserves the legacy v1 signing input. Runtime emitters remain dormant
-- until the independent-service activation gate is explicitly closed.
ALTER TABLE node_events
    ADD COLUMN service_id VARCHAR(64) NULL AFTER event_type,
    ADD INDEX idx_node_events_service_id (service_id);


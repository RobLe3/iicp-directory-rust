ALTER TABLE nodes
    ADD COLUMN legacy_reputation_score FLOAT NULL AFTER reputation_score,
    ADD COLUMN reputation_model VARCHAR(32) NOT NULL DEFAULT 'outcome-v2' AFTER legacy_reputation_score,
    ADD COLUMN reputation_epoch CHAR(36) NULL AFTER reputation_model,
    ADD COLUMN last_metrics_batch_id VARCHAR(64) NULL AFTER reputation_epoch;

SET @iicp_reputation_epoch = UUID();
UPDATE nodes
SET legacy_reputation_score = reputation_score,
    reputation_score = 0.5,
    reputation_model = 'outcome-v2',
    reputation_epoch = @iicp_reputation_epoch,
    last_metrics_batch_id = NULL;

-- WQ-056 / iicp-billing-extension §11 / ADR-035 — the 90-day TTL credit sink (Rust parity
-- with the PHP directory's Unit-E work, commit 57e96b0f). Adds the retention/expiry horizon
-- to credit_transactions so an idle node's unspent balance is swept (the PRIMARY
-- anti-inflation sink; the 2% transaction burn is the secondary one).
--
-- On every earn (type='credit'), record_credit_award sets expires_at = NOW() + 90 DAY.
-- A node whose newest earn is past its TTL with a positive balance is "idle" and is swept
-- by the nightly run_expire_credits_loop. Pinned to credit_economy.TTL_days (90).

ALTER TABLE credit_transactions
    ADD COLUMN expires_at TIMESTAMP NULL AFTER reason;

CREATE INDEX idx_credit_tx_expires_at ON credit_transactions (expires_at);

-- Backfill existing earn rows so the sweep has a determinable TTL for pre-migration
-- credits: expires_at = created_at + 90 days. Spend/free rows stay NULL.
UPDATE credit_transactions
   SET expires_at = created_at + INTERVAL 90 DAY
 WHERE type = 'credit'
   AND expires_at IS NULL;

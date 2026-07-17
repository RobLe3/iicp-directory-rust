ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS supported_receipt_profiles JSON NULL AFTER sdk_version;

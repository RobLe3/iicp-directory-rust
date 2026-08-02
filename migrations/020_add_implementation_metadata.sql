ALTER TABLE nodes
    ADD COLUMN implementation_name VARCHAR(64) NULL AFTER sdk_language,
    ADD COLUMN implementation_version VARCHAR(32) NULL AFTER implementation_name,
    ADD COLUMN sdk_compatibility_version VARCHAR(32) NULL AFTER implementation_version;

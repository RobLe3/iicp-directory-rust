-- Additive, pre-normative capability profile metadata (#69).
ALTER TABLE capabilities
    ADD COLUMN supported_profiles JSON NULL AFTER input_modalities;

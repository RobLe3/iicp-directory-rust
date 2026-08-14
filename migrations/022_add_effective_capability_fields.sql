-- SPDX-License-Identifier: Apache-2.0
-- Manual upgrade evidence for existing standalone Rust preview databases.
-- The runtime remains verify-only for populated databases; operators must
-- apply reviewed schema changes before starting the upgraded binary.
ALTER TABLE capabilities
  ADD COLUMN capability_version VARCHAR(32) NULL AFTER intent,
  ADD COLUMN capability_phase INT UNSIGNED NULL AFTER capability_version,
  ADD COLUMN variant_id VARCHAR(64) NULL AFTER capability_phase,
  ADD COLUMN output_modalities JSON NULL AFTER input_modalities,
  ADD COLUMN features JSON NULL AFTER output_modalities,
  ADD COLUMN execution_capabilities JSON NULL AFTER features,
  ADD COLUMN capability_limits JSON NULL AFTER execution_capabilities,
  ADD COLUMN claim_provenance JSON NULL AFTER supported_profiles,
  ADD COLUMN extensions JSON NULL AFTER claim_provenance,
  ADD UNIQUE INDEX capabilities_node_intent_variant_unique (node_id, intent, variant_id);

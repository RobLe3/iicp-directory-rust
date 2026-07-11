-- #458 — hash-chain the signed event log (prev_hash), PHP-directory parity (#385).
-- Mirrors directory/database/migrations/2026_06_05_*_add_prev_hash_to_node_events.php.
--
-- Each signed event binds its predecessor's signature into its own signing input via
-- prev_hash = SHA256_hex(ascii(previous signed event's signature)), seeding from
-- GENESIS_ROOT = SHA256_hex("iicp:dir:event-log:genesis:v1") when there is no signed
-- predecessor (spec/iicp-federated-directory.md §5.1). Altering any event cascades into
-- every later signature, making insert/delete/reorder detectable (tamper-evident ordering
-- for federation + founder ordinal badges, #310). 64 lowercase-hex chars.
--
-- NULL for legacy rows written before this migration; the chain (re)starts from
-- GENESIS_ROOT at the first signed event carrying a non-null prev_hash.

ALTER TABLE node_events
    ADD COLUMN prev_hash CHAR(64) NULL AFTER payload;

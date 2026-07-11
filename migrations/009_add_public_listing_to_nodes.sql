-- WQ-058 / ADR-017 REG-01 — operator public-listing opt-in (PHP parity with
-- 2026_05_18_300000_add_public_listing_to_nodes.php). A node operator may opt into the
-- public registry listing and advertise a link to their own site; `operator_url` is
-- exposed (in GET /v1/registry/nodes) ONLY when `public_listing = true`.
--
-- LOCAL schema migration on the Rust directory's OWN db (applied via sqlx::migrate! at
-- startup). It never touches the PHP prod db.
--
-- (The private `operator_contact` column from the PHP migration is intentionally omitted
-- here — it is never served, and the listing feature needs only public_listing + operator_url.)

ALTER TABLE nodes
    ADD COLUMN public_listing TINYINT(1) NOT NULL DEFAULT 0 AFTER attested,
    ADD COLUMN operator_url    VARCHAR(256) NULL AFTER public_listing;

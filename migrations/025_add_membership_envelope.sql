ALTER TABLE trust_domain_memberships
    ADD COLUMN membership_envelope JSON NULL AFTER revoked_at;

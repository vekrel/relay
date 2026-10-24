-- The refresh family an authorization code was redeemed into, so a replayed code revokes the
-- tokens it issued (RFC 6749 §4.1.2).
ALTER TABLE auth_codes ADD COLUMN family_id uuid;

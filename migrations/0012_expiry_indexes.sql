-- Indexes for the 5-minute prune (src/cron.rs), asked for in the Task 2 review: each prune is a
-- range delete on expires_at / window_start, and refresh tokens are pruned per family.
CREATE INDEX idx_auth_requests_expires_at ON auth_requests (expires_at);
CREATE INDEX idx_auth_codes_expires_at ON auth_codes (expires_at);
CREATE INDEX idx_magic_links_expires_at ON magic_links (expires_at);
CREATE INDEX idx_device_codes_expires_at ON device_codes (expires_at);
CREATE INDEX idx_refresh_tokens_family_expires_at ON refresh_tokens (family_id, expires_at);
CREATE INDEX idx_relay_rate_limits_window_start ON relay_rate_limits (window_start);

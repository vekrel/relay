-- Held-webhook scheduling (plan 6A Task 11). T3 kept one Durable Object alarm per endpoint
-- (infra/relay/src/hooks/HookInboxObject.ts); here a background task claims due targets.
--   next_attempt_at_ms: when the endpoint's held requests are next tried (T3's alarm), NULL = none.
--   locked_until_ms:    a claim's lease, so one replica delivers an endpoint at a time and a
--                       crashed claim is picked up again after it expires.
ALTER TABLE relay_held_hook_targets ADD COLUMN next_attempt_at_ms bigint;
ALTER TABLE relay_held_hook_targets ADD COLUMN locked_until_ms bigint;
CREATE INDEX idx_relay_held_hook_targets_due ON relay_held_hook_targets (next_attempt_at_ms);

-- A webhook URL names its endpoint by the 16-hex suffix of the tunnel name (T3
-- deploymentConfig.ts MANAGED_ENDPOINT_KEY_PATTERN, managedEndpointTunnelNameForKey).
CREATE INDEX idx_relay_managed_endpoint_allocations_endpoint_key
	ON relay_managed_endpoint_allocations (right(tunnel_name, 17));

COMMENT ON COLUMN relay_held_hooks.raw_token IS
	'Plaintext, as T3 stores it: a replay must send the exact token the machine checks. Deleted on delivery, after 24 h, on unlink, hold opt-out and user disable. Never logged.';
COMMENT ON COLUMN relay_held_hooks.headers IS
	'Plaintext JSON of the forwarded headers (may carry sender signatures or secrets), kept for replay as T3 does. Never logged.';
COMMENT ON COLUMN relay_held_hooks.body IS
	'The exact request body, kept for replay as T3 does. Never logged.';

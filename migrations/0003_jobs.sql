-- Background work as rows, so it survives restarts and is shared by replicas (claims use SKIP LOCKED).

-- Held webhooks. Ports T3's per-endpoint Durable Object SQLite store
-- (infra/relay/src/hooks/HookInboxStore.ts `held_hooks`, `held_hooks_target`; MIT, Copyright (c)
-- T3 Tools Inc.) to shared tables keyed by endpoint_key (T3: `hookInboxes.getByName(endpointKey)`,
-- infra/relay/src/worker.ts). seq keeps arrival order for replay.
CREATE TABLE relay_held_hooks (
	seq bigserial PRIMARY KEY,
	id text NOT NULL UNIQUE,
	endpoint_key text NOT NULL,
	received_at varchar(64) NOT NULL,
	method text NOT NULL,
	raw_hook_id text NOT NULL,
	raw_token text NOT NULL,
	hook_key text NOT NULL,
	query text NOT NULL,
	headers text NOT NULL,
	body bytea NOT NULL
);
CREATE INDEX idx_relay_held_hooks_endpoint ON relay_held_hooks (endpoint_key, seq);
CREATE INDEX idx_relay_held_hooks_hook ON relay_held_hooks (endpoint_key, hook_key);
CREATE INDEX idx_relay_held_hooks_received ON relay_held_hooks (received_at);

CREATE TABLE relay_held_hook_targets (
	endpoint_key text PRIMARY KEY,
	base_url text NOT NULL,
	failures integer NOT NULL DEFAULT 0
);

-- Push deliveries (T3 used Cloudflare Queues). locked_until lets a crashed claim be retried.
CREATE TABLE relay_push_jobs (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	kind text NOT NULL CHECK (kind IN ('apns', 'fcm')),
	payload jsonb NOT NULL,
	run_at timestamptz NOT NULL DEFAULT now(),
	attempts integer NOT NULL DEFAULT 0,
	status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'dead')),
	locked_until timestamptz,
	last_error text,
	created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_relay_push_jobs_due ON relay_push_jobs (status, run_at);

-- Fixed-window counters (T3 used Cloudflare RateLimit bindings, infra/relay/src/worker.ts).
CREATE TABLE relay_rate_limits (
	key text NOT NULL,
	window_start timestamptz NOT NULL,
	count integer NOT NULL DEFAULT 0,
	PRIMARY KEY (key, window_start)
);

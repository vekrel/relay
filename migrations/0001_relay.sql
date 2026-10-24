-- Relay baseline. Ports T3 Code's relay schema (MIT, Copyright (c) T3 Tools Inc.):
--   infra/relay/src/persistence/schema.ts
--   infra/relay/migrations/postgres/20260527044716_baseline .. 20261020013101_upstream_api_pauses
-- folded into one migration at T3's final state. Changes from T3:
--   * "environment" is "machine" in table, column and index names.
--   * user_id is uuid referencing users(id) (T3 stored the raw Clerk `sub` as varchar);
--     rows owned by a user are deleted with the user. `users` is created here (not in 0002)
--     because these foreign keys need it.
--   * default machine label 'Vekrel machine' (T3: 'T3 Environment'; Engine ServerMachineLabel.ts).
-- Timestamps stay ISO-8601 strings in varchar(64), as T3 stores and returns them.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	email citext NOT NULL UNIQUE,
	created_at timestamptz NOT NULL DEFAULT now(),
	disabled_at timestamptz
);

CREATE TABLE relay_mobile_devices (
	user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	device_id varchar(255) NOT NULL,
	label text NOT NULL DEFAULT 'iOS device',
	platform varchar(16) NOT NULL,
	ios_major_version integer,
	android_api_level integer,
	app_version varchar(64),
	bundle_id varchar(255),
	aps_environment varchar(16),
	push_token text,
	push_to_start_token text,
	preferences_json jsonb NOT NULL,
	created_at varchar(64) NOT NULL,
	updated_at varchar(64) NOT NULL,
	PRIMARY KEY (user_id, device_id)
);
CREATE UNIQUE INDEX idx_relay_mobile_devices_push_token ON relay_mobile_devices (push_token);
CREATE UNIQUE INDEX idx_relay_mobile_devices_push_to_start_token ON relay_mobile_devices (push_to_start_token);

CREATE TABLE relay_live_activities (
	user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	device_id varchar(255) NOT NULL,
	activity_push_token text,
	remote_start_queued_at varchar(64),
	remote_started_at varchar(64),
	ended_at varchar(64),
	last_aggregate_json jsonb,
	last_live_activity_delivery_at varchar(64),
	created_at varchar(64) NOT NULL,
	updated_at varchar(64) NOT NULL,
	PRIMARY KEY (user_id, device_id)
);
CREATE UNIQUE INDEX idx_relay_live_activities_activity_push_token ON relay_live_activities (activity_push_token);

CREATE TABLE relay_machine_links (
	user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	machine_id varchar(191) NOT NULL,
	machine_label text NOT NULL DEFAULT 'Vekrel machine',
	machine_public_key text NOT NULL,
	endpoint_http_base_url text NOT NULL,
	endpoint_ws_base_url text NOT NULL,
	endpoint_provider_kind varchar(32) NOT NULL,
	notifications_enabled boolean NOT NULL DEFAULT true,
	live_activities_enabled boolean NOT NULL DEFAULT true,
	managed_tunnels_enabled boolean NOT NULL DEFAULT false,
	hold_webhooks_while_offline boolean NOT NULL DEFAULT false,
	created_by_device_id varchar(191),
	revoked_at varchar(64),
	created_at varchar(64) NOT NULL,
	updated_at varchar(64) NOT NULL,
	PRIMARY KEY (user_id, machine_id)
);
CREATE INDEX idx_relay_machine_links_machine ON relay_machine_links (machine_id, revoked_at);

CREATE TABLE relay_managed_endpoint_allocations (
	user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	machine_id varchar(191) NOT NULL,
	hostname text NOT NULL,
	tunnel_id varchar(191),
	tunnel_name text NOT NULL,
	dns_record_id varchar(191),
	ready_at varchar(64),
	recovery_enabled_at varchar(64),
	recovery_machine_public_key text,
	tunnel_released_at varchar(64),
	origin jsonb,
	generation integer NOT NULL DEFAULT 0,
	created_at varchar(64) NOT NULL,
	updated_at varchar(64) NOT NULL,
	PRIMARY KEY (user_id, machine_id)
);
CREATE UNIQUE INDEX idx_relay_managed_endpoint_allocations_hostname ON relay_managed_endpoint_allocations (hostname);
CREATE UNIQUE INDEX idx_relay_managed_endpoint_allocations_tunnel_name ON relay_managed_endpoint_allocations (tunnel_name);

-- One row per upstream API whose rate limit is shared by every relay replica,
-- so a 429 seen by one replica pauses the rest.
CREATE TABLE relay_upstream_api_pauses (
	api varchar(64) PRIMARY KEY,
	paused_until_ms bigint NOT NULL
);

CREATE TABLE relay_managed_tunnel_limits (
	user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
	max_tunnels integer NOT NULL,
	created_at varchar(64) NOT NULL,
	updated_at varchar(64) NOT NULL
);

-- Stores only a hash of the credential. Keyed by machine, not user, as in T3.
CREATE TABLE relay_machine_credentials (
	credential_id varchar(64) PRIMARY KEY,
	machine_id varchar(191) NOT NULL,
	machine_public_key text NOT NULL,
	credential_hash varchar(191) NOT NULL,
	revoked_at varchar(64),
	created_at varchar(64) NOT NULL,
	updated_at varchar(64) NOT NULL
);
CREATE UNIQUE INDEX idx_relay_machine_credentials_hash ON relay_machine_credentials (credential_hash);
CREATE INDEX idx_relay_machine_credentials_machine ON relay_machine_credentials (machine_id, revoked_at);
CREATE INDEX idx_relay_machine_credentials_machine_key ON relay_machine_credentials (machine_id, machine_public_key, revoked_at);

CREATE TABLE relay_agent_activity_rows (
	machine_id varchar(191) NOT NULL,
	machine_public_key text NOT NULL,
	thread_id varchar(512) NOT NULL,
	state_json jsonb NOT NULL,
	updated_at varchar(64) NOT NULL,
	created_at varchar(64) NOT NULL,
	PRIMARY KEY (machine_id, machine_public_key, thread_id)
);
CREATE INDEX idx_relay_agent_activity_rows_updated ON relay_agent_activity_rows (updated_at);

-- Delivery log: kept when the user is deleted, with user_id cleared.
CREATE TABLE relay_delivery_attempts (
	id varchar(36) PRIMARY KEY,
	created_at varchar(64) NOT NULL,
	user_id uuid REFERENCES users (id) ON DELETE SET NULL,
	machine_id varchar(191),
	thread_id varchar(512),
	device_id varchar(255),
	kind varchar(64) NOT NULL,
	source_job_id varchar(64),
	token_suffix varchar(16),
	apns_status integer,
	apns_reason text,
	apns_id varchar(128),
	transport_error text
);
CREATE INDEX idx_relay_delivery_attempts_machine ON relay_delivery_attempts (machine_id, thread_id, created_at);
CREATE UNIQUE INDEX idx_relay_delivery_attempts_source_job ON relay_delivery_attempts (source_job_id);

CREATE TABLE relay_dpop_proofs (
	thumbprint varchar(128) NOT NULL,
	jti varchar(255) NOT NULL,
	iat integer NOT NULL,
	expires_at varchar(64) NOT NULL,
	created_at varchar(64) NOT NULL,
	PRIMARY KEY (thumbprint, jti)
);
CREATE INDEX idx_relay_dpop_proofs_expires_at ON relay_dpop_proofs (expires_at);

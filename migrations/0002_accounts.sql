-- Accounts (ours; T3 used Clerk and has no equivalent tables). Shapes from
-- docs/superpowers/plans/2026-10-23-plan-6a-research.md "Tables" and plan 6A Tasks 5-8.
-- `users` lives in 0001. Every secret (codes, tokens) is stored only as a SHA-256 hash.

CREATE TABLE identities (
	provider text NOT NULL,
	provider_user_id text NOT NULL,
	user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	email citext NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (provider, provider_user_id)
);
CREATE INDEX idx_identities_user ON identities (user_id);

-- A pending /oauth/authorize request, before the user has signed in.
CREATE TABLE auth_requests (
	id text PRIMARY KEY,
	client_id text NOT NULL,
	redirect_uri text NOT NULL,
	code_challenge text NOT NULL,
	state text,
	created_at timestamptz NOT NULL DEFAULT now(),
	expires_at timestamptz NOT NULL
);

CREATE TABLE auth_codes (
	code_hash text PRIMARY KEY,
	user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	client_id text NOT NULL,
	redirect_uri text NOT NULL,
	code_challenge text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	expires_at timestamptz NOT NULL,
	used_at timestamptz
);

CREATE TABLE magic_links (
	token_hash text PRIMARY KEY,
	email citext NOT NULL,
	auth_request_id text REFERENCES auth_requests (id) ON DELETE CASCADE,
	code_hash text NOT NULL,
	code_attempts integer NOT NULL DEFAULT 0,
	created_at timestamptz NOT NULL DEFAULT now(),
	expires_at timestamptz NOT NULL,
	used_at timestamptz
);
CREATE INDEX idx_magic_links_email ON magic_links (email, created_at);

-- RFC 8628 device grant. user_id is set when the user approves.
CREATE TABLE device_codes (
	device_code_hash text PRIMARY KEY,
	user_code text NOT NULL UNIQUE,
	client_id text NOT NULL,
	user_agent text,
	user_id uuid REFERENCES users (id) ON DELETE CASCADE,
	status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
	interval_seconds integer NOT NULL DEFAULT 5,
	last_polled_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	expires_at timestamptz NOT NULL
);

CREATE TABLE refresh_tokens (
	hash text PRIMARY KEY,
	family_id uuid NOT NULL,
	user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	client_id text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	expires_at timestamptz NOT NULL,
	rotated_at timestamptz,
	revoked_at timestamptz
);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);

CREATE TABLE signup_allowlist (
	email citext PRIMARY KEY,
	added_at timestamptz NOT NULL DEFAULT now(),
	note text
);

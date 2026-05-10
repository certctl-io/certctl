-- Bundle 1 Phase 6 (bootstrap path): runtime-minted operator API keys.
--
-- Pre-Bundle-1 the only operator API keys lived in CERTCTL_API_KEYS_NAMED
-- (env-var config; static at boot). The bootstrap endpoint
-- POST /v1/auth/bootstrap mints the first admin key without requiring
-- the operator to know the env-var format up front; that key has to
-- survive a process restart and authenticate against the auth
-- middleware's keystore on subsequent requests, which means it lives
-- here.
--
-- Storage rules: ONLY the SHA-256 hash of the key value is stored
-- (key_hash). The plaintext key value is returned to the operator in
-- the bootstrap HTTP response body once and never persisted. Lost?
-- Mint a new admin key via the regular RBAC API and revoke the old
-- one — the api_keys row is the source of truth for "this name +
-- hash authenticates", so revoking it via the RBAC API removes the
-- row and the next request lookup fails 401.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS, indexes IF NOT EXISTS.

BEGIN;

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,                     -- prefix `ak-`
    name TEXT NOT NULL UNIQUE,               -- operator-visible name; matches actor_roles.actor_id
    key_hash TEXT NOT NULL UNIQUE,           -- SHA-256 hex of the plaintext key
    tenant_id TEXT NOT NULL DEFAULT 't-default'
        REFERENCES tenants(id) ON DELETE CASCADE,
    -- Admin is a denormalized hint replicated from the actor's
    -- standing role grant so the auth middleware can populate
    -- AdminKey context without joining actor_roles on every request.
    -- Source of truth remains actor_roles; this column is rebuilt by
    -- the boot loader from "actor holds r-admin?" queries.
    admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_by TEXT NOT NULL,                -- actor_id of the creator; "bootstrap" for the first one
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Decoration columns for forward-compat: bundle 2 will add
    -- expiry + last_used + rotation tracking. Reserved as nullable
    -- now so the migration in Bundle 2 doesn't reshape the table.
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON api_keys(created_by);

COMMIT;

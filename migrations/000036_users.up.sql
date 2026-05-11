-- 000036_users.up.sql
-- Auth Bundle 2 / Phase 2: federated-human user identity table.
--
-- Distinction from Bundle 1's `actor_roles`: actor_roles indexes
-- `actor_id` strings (free-form, e.g. API-key names). For federated
-- humans, the user's actor_id IS users.id; so for SSO logins,
-- `actor_roles.actor_id = users.id` and the actor_type column is
-- `'User'` (matches domain.ActorTypeUser).
--
-- Identity is per-(provider, oidc_subject) tuple. A person who
-- authenticates against multiple OIDC providers gets multiple rows by
-- design; identity is per-provider, not global. The future managed
-- offering can collapse identities at the application layer if a
-- customer requires it.
--
-- webauthn_credentials JSONB column reserved for v3 (Decision 12).
-- Bundle 2 always stores `[]`; v3's WebAuthn enrollment populates it.
--
-- All operations idempotent. Wrapped in a single transaction.

BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id                    TEXT PRIMARY KEY,                         -- prefix `u-`
    tenant_id             TEXT NOT NULL DEFAULT 't-default'
                              REFERENCES tenants(id) ON DELETE CASCADE,
    email                 TEXT NOT NULL,
    display_name          TEXT NOT NULL DEFAULT '',
    oidc_subject          TEXT NOT NULL,
    oidc_provider_id      TEXT NOT NULL REFERENCES oidc_providers(id) ON DELETE RESTRICT,
    last_login_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    webauthn_credentials  JSONB NOT NULL DEFAULT '[]'::JSONB,        -- reserved for v3; always [] in Bundle 2
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Identity invariant: one row per (provider, oidc_subject) tuple.
    -- Phase 3 HandleCallback uses this to look up an existing user
    -- before deciding to insert.
    UNIQUE (oidc_provider_id, oidc_subject)
);

-- Email lookup (operator GUI 'find user by email' surface). Not
-- unique because the same email can appear in multiple providers
-- (per the per-provider identity model above).
CREATE INDEX IF NOT EXISTS idx_users_email
    ON users (tenant_id, email);

-- ON DELETE RESTRICT on oidc_provider_id keeps Phase 3's
-- "delete provider only when no users authenticated via it" rule
-- enforced at the DB layer; the OIDCProviderRepository.Delete
-- implementation translates the SQLSTATE 23503 into
-- repository.ErrAuthRoleInUse-equivalent for HTTP 409.

COMMIT;

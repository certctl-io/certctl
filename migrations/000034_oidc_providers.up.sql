-- 000034_oidc_providers.up.sql
-- Auth Bundle 2 / Phase 2: OIDC provider configuration + group→role
-- mapping tables. Backs internal/auth/oidc/domain/{OIDCProvider,
-- GroupRoleMapping}. Phase 3 (OIDC service) reads these rows to
-- validate ID tokens against the configured IdP allow-list.
--
-- All operations use IF NOT EXISTS / IF EXISTS / ON CONFLICT DO NOTHING
-- so the migration is idempotent: safe to re-run on every
-- certctl-server boot per the project's "Idempotent migrations"
-- architecture decision. Wrapped in a single transaction so a
-- partial-fail leaves no half-state.
--
-- Schema convention follows CLAUDE.md "Architecture Decisions": TEXT
-- primary keys with prefixes (`op-`, `grm-`), TIMESTAMPTZ for time
-- columns, FK cascade behaviour explicit (group_role_mappings cascades
-- on provider deletion).
--
-- Multi-tenant readiness: every row carries tenant_id with
-- DEFAULT 't-default'. Bundle 2 ships single-tenant; the future
-- managed-service multi-tenant offering activates by inserting
-- additional tenants without a schema migration.
--
-- client_secret_encrypted holds the v2 blob produced by
-- `internal/crypto/encryption.go` (magic byte 0x02 || salt(16) ||
-- nonce(12) || ciphertext+tag). Plaintext NEVER lives in the DB.

BEGIN;

-- OIDC providers: operator-configured IdP records. One row per IdP.
-- N providers supported from day one for the future managed-service
-- offering where a multi-team customer may have multiple IdPs.
CREATE TABLE IF NOT EXISTS oidc_providers (
    id                       TEXT PRIMARY KEY,                       -- prefix `op-`
    tenant_id                TEXT NOT NULL DEFAULT 't-default'
                                 REFERENCES tenants(id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    issuer_url               TEXT NOT NULL,                          -- must be https:// (validated at app layer)
    client_id                TEXT NOT NULL,
    client_secret_encrypted  BYTEA NOT NULL,                         -- v2 blob; never plaintext
    redirect_uri             TEXT NOT NULL,                          -- must be https:// (validated at app layer)
    groups_claim_path        TEXT NOT NULL DEFAULT 'groups',
    groups_claim_format      TEXT NOT NULL DEFAULT 'string-array',
    fetch_userinfo           BOOLEAN NOT NULL DEFAULT FALSE,
    scopes                   TEXT[] NOT NULL DEFAULT ARRAY['openid','profile','email'],
    allowed_email_domains    TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    iat_window_seconds       INTEGER NOT NULL DEFAULT 300,           -- min 1, max 600 enforced at app layer
    jwks_cache_ttl_seconds   INTEGER NOT NULL DEFAULT 3600,          -- min 60 enforced at app layer
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, name),

    -- Closed enum for groups_claim_format. Phase 3's resolver
    -- dispatches on this column.
    CONSTRAINT oidc_providers_claim_format_check
        CHECK (groups_claim_format IN ('string-array', 'json-path')),

    -- Defense-in-depth: app-layer Validate() also enforces these.
    CONSTRAINT oidc_providers_iat_window_bounds
        CHECK (iat_window_seconds > 0 AND iat_window_seconds <= 600),
    CONSTRAINT oidc_providers_jwks_ttl_bounds
        CHECK (jwks_cache_ttl_seconds >= 60)
);

-- Group→role mappings: one row per (provider, group_name, role) tuple.
-- ON DELETE CASCADE on provider so deleting a provider cleans up its
-- mappings. Name-based per the forward-compat seam: if the IdP renames
-- a group, the operator updates the mapping. We don't depend on
-- IdP-internal identifiers (which differ per IdP and resist
-- documentation).
CREATE TABLE IF NOT EXISTS group_role_mappings (
    id          TEXT PRIMARY KEY,                                    -- prefix `grm-`
    tenant_id   TEXT NOT NULL DEFAULT 't-default'
                    REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    group_name  TEXT NOT NULL,
    role_id     TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One mapping per (provider, group_name, role_id) tuple. An
    -- operator can map one group to multiple roles by inserting
    -- multiple rows with different role_ids; the unique constraint
    -- prevents accidental duplicates.
    UNIQUE (provider_id, group_name, role_id)
);

-- Indexes for the hot paths Phase 3's service consumes:
-- ListByProvider walks all mappings for a given provider; Map(group_names)
-- reads the same rows then filters in-memory.
CREATE INDEX IF NOT EXISTS idx_group_role_mappings_provider_id
    ON group_role_mappings (provider_id);

COMMIT;

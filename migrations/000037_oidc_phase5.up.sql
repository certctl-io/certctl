-- 000037_oidc_phase5.up.sql
-- Auth Bundle 2 / Phase 5: HTTP handler surface.
--
-- Two things land here:
--
--   1. oidc_pre_login_sessions table — short-lived rows holding the
--      OIDC state + nonce + PKCE verifier across the IdP redirect.
--      Distinct from the sessions table because the schema for sessions
--      doesn't carry OIDC-specific columns and bolting them on would
--      bloat every row. 10-minute absolute TTL; GC sweep deletes
--      expired rows alongside the post-login session GC sweep.
--
--      Cookie name `certctl_oidc_pending` (Path=/auth/oidc/) carries the
--      same v1.<id>.<signing_key_id>.<HMAC-SHA256> wire format as the
--      post-login cookie. The signing key is the active SessionSigningKey
--      so we don't need a separate key lifecycle for pre-login cookies.
--
--   2. Seven new permissions extending the canonical catalogue:
--        auth.session.list       — list one's own sessions
--        auth.session.list.all   — list every session in the tenant (admin)
--        auth.session.revoke     — revoke a session that isn't yours
--        auth.oidc.list          — list OIDC providers + group mappings
--        auth.oidc.create        — register a new OIDC provider
--        auth.oidc.edit          — update OIDC provider config / mappings
--        auth.oidc.delete        — delete OIDC provider (only when no
--                                  users have authenticated via it)
--      Granted to r-admin only by default. Operators who want session
--      revocation across actors granted to r-operator can add the row
--      via the role-permission API after migration.
--
-- All operations idempotent. Wrapped in a single transaction.

BEGIN;

-- =============================================================================
-- oidc_pre_login_sessions table
-- =============================================================================

CREATE TABLE IF NOT EXISTS oidc_pre_login_sessions (
    -- id is the prefix-`pl-` opaque identifier signed into the cookie.
    -- Format on the wire: v1.pl-<base64url>.sk-<base64url>.<base64url HMAC>.
    id                  TEXT PRIMARY KEY,

    tenant_id           TEXT NOT NULL DEFAULT 't-default'
                            REFERENCES tenants(id) ON DELETE CASCADE,

    -- The signing key id pinning which SessionSigningKey row signed
    -- the cookie. Validation re-derives the HMAC against this key.
    signing_key_id      TEXT NOT NULL
                            REFERENCES session_signing_keys(id) ON DELETE RESTRICT,

    -- The OIDC provider being authenticated against. References
    -- oidc_providers(id) with ON DELETE CASCADE so deleting a provider
    -- mid-handshake invalidates in-flight pre-login rows. (Provider
    -- deletion is itself gated on no users having authenticated via
    -- the provider; this is the second-line defense.)
    oidc_provider_id    TEXT NOT NULL
                            REFERENCES oidc_providers(id) ON DELETE CASCADE,

    -- OIDC state: 32 random bytes base64url-no-pad. Constant-time
    -- compared at callback against the IdP-returned state param.
    state               TEXT NOT NULL,

    -- OIDC nonce: 32 random bytes base64url-no-pad. Constant-time
    -- compared at callback against the ID token's nonce claim.
    nonce               TEXT NOT NULL,

    -- PKCE-S256 verifier: 43-128 chars base64url-no-pad. Sent to the
    -- IdP token endpoint to prove possession of the original challenge.
    pkce_verifier       TEXT NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Phase 5 spec: 10-minute absolute TTL. The GC sweep treats this
    -- as the cutoff (rows older than 10 minutes are deleted).
    absolute_expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '10 minutes'),

    CONSTRAINT oidc_pre_login_expiry_after_created
        CHECK (absolute_expires_at > created_at)
);

-- Index for the GC sweep — `WHERE absolute_expires_at < NOW()` hot path.
CREATE INDEX IF NOT EXISTS idx_oidc_pre_login_expires
    ON oidc_pre_login_sessions (absolute_expires_at);

-- Index for the lookup-by-provider hot path (admin "active pending logins"
-- surface, optional Phase 8 GUI extension).
CREATE INDEX IF NOT EXISTS idx_oidc_pre_login_provider
    ON oidc_pre_login_sessions (oidc_provider_id);

-- =============================================================================
-- Seven new permissions extending the Bundle 1 catalogue.
-- =============================================================================

INSERT INTO permissions (id, name, namespace) VALUES
    ('p-auth-session-list',     'auth.session.list',     'auth.session'),
    ('p-auth-session-list-all', 'auth.session.list.all', 'auth.session'),
    ('p-auth-session-revoke',   'auth.session.revoke',   'auth.session'),
    ('p-auth-oidc-list',        'auth.oidc.list',        'auth.oidc'),
    ('p-auth-oidc-create',      'auth.oidc.create',      'auth.oidc'),
    ('p-auth-oidc-edit',        'auth.oidc.edit',        'auth.oidc'),
    ('p-auth-oidc-delete',      'auth.oidc.delete',      'auth.oidc')
ON CONFLICT (id) DO NOTHING;

-- Grant all seven to r-admin (and only r-admin by default). The
-- role-permission API can hand auth.session.revoke to r-operator
-- post-deploy if the operator wants their support staff to revoke
-- sessions; we ship locked-down by default.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-admin', id, 'global', NULL
FROM permissions
WHERE id IN (
    'p-auth-session-list',
    'p-auth-session-list-all',
    'p-auth-session-revoke',
    'p-auth-oidc-list',
    'p-auth-oidc-create',
    'p-auth-oidc-edit',
    'p-auth-oidc-delete'
)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- Every actor who has been federated-authenticated needs to list AND
-- revoke their OWN session. That gate is encoded at the handler layer
-- via "is the actor_id in the path the caller's actor_id?" rather
-- than via a permission, since granting `auth.session.list` to
-- everyone would be tantamount to making it a no-op. The handler
-- pattern: `if path.id == ctx.actor_id { allow } else { require(auth.session.revoke) }`.

COMMIT;

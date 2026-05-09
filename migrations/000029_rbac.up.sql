-- 000029_rbac.up.sql
-- Bundle 1 / Phase 1: RBAC primitive. Roles, permissions, role-permission
-- grants, actor-role assignments, plus a reserved tenant table for the
-- future managed-service multi-tenant offering.
--
-- All operations use IF NOT EXISTS / IF EXISTS / ON CONFLICT DO NOTHING
-- so the migration is idempotent: safe to re-run on every certctl-server
-- boot per the project's "Idempotent migrations" architecture decision.
-- Wrapped in a single transaction so a partial-fail leaves no half-state.
--
-- Schema convention follows CLAUDE.md "Architecture Decisions": TEXT
-- primary keys with prefixes (`t-`, `r-`, `p-`, `ar-`), TIMESTAMPTZ for
-- time columns, FK cascade behaviour explicit (RESTRICT on roles with
-- active actor_roles, CASCADE on tenant + actor deletion).
--
-- Backwards compatibility: existing API keys configured via
-- CERTCTL_API_KEYS_NAMED retain their behaviour. The migration backfills
-- one actor_role row per named key (mapping admin keys to r-admin and
-- non-admin keys to r-viewer) at server startup; the actual seed lives
-- in cmd/server/main.go because the named-key list is configured via
-- environment variable, not stored in the DB.
--
-- Demo-mode preservation: this migration UNCONDITIONALLY seeds
-- actor-demo-anon with the admin role. Bundle 1 Phase 3 wires the auth
-- middleware to inject this actor into the request context when
-- CERTCTL_AUTH_TYPE=none is configured (the demo path); when api-key
-- mode is active, the actor exists in the schema but is unreferenced.

BEGIN;

-- Tenants. Bundle 1 ships single-tenant; the future managed-service
-- offering activates multi-tenant by inserting additional tenants.
CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,                       -- prefix `t-`
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Roles. Each role is a named bag of permissions; actors hold zero or
-- more roles via actor_roles.
CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,                       -- prefix `r-`
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, name)
);

-- Permissions: typed strings in the canonical catalog. Treated as rows
-- so role_permissions can FK-join. The catalog is documented in
-- internal/domain/auth/validate.go::CanonicalPermissions; adding a new
-- permission requires a migration AND a code update in lockstep.
CREATE TABLE IF NOT EXISTS permissions (
    id        TEXT PRIMARY KEY,                       -- prefix `p-`
    name      TEXT NOT NULL UNIQUE,                   -- e.g. "cert.read"
    namespace TEXT NOT NULL                            -- e.g. "cert"
);

-- Role-permission grants with explicit scope. ScopeType is one of
-- 'global', 'profile', 'issuer'; ScopeID is NULL when global, otherwise
-- references the resource id (managed at the application layer because
-- profiles + issuers live in different tables; we don't FK on scope_id).
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
    scope_type    TEXT NOT NULL DEFAULT 'global',
    scope_id      TEXT,                                -- NULL for global

    PRIMARY KEY (role_id, permission_id, scope_type, scope_id),
    CONSTRAINT role_permission_scope_check CHECK (
        scope_type IN ('global', 'profile', 'issuer')
    ),
    CONSTRAINT role_permission_scope_id_consistency CHECK (
        (scope_type = 'global' AND scope_id IS NULL)
        OR (scope_type IN ('profile', 'issuer') AND scope_id IS NOT NULL)
    )
);

-- Actor-role assignments. ExpiresAt + GrantedBy reserved for future
-- time-bound grants and JIT elevation; Bundle 1 leaves them NULL for
-- standing grants.
CREATE TABLE IF NOT EXISTS actor_roles (
    id         TEXT PRIMARY KEY,                       -- prefix `ar-`
    actor_id   TEXT NOT NULL,
    actor_type TEXT NOT NULL,                          -- domain.ActorType
    role_id    TEXT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,                            -- NULL = standing
    granted_by TEXT NOT NULL DEFAULT 'system',
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    UNIQUE (actor_id, actor_type, role_id, tenant_id),
    CONSTRAINT actor_type_enum CHECK (
        actor_type IN ('User', 'System', 'Agent', 'APIKey', 'Anonymous')
    )
);

CREATE INDEX IF NOT EXISTS idx_actor_roles_actor
    ON actor_roles(actor_id, actor_type, tenant_id);
CREATE INDEX IF NOT EXISTS idx_actor_roles_role
    ON actor_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role
    ON role_permissions(role_id);

-- Default tenant.
INSERT INTO tenants (id, name, description)
VALUES ('t-default', 'default', 'Single-tenant default; future multi-tenant managed offering activates by inserting additional tenants.')
ON CONFLICT (id) DO NOTHING;

-- Default roles.
INSERT INTO roles (id, tenant_id, name, description) VALUES
    ('r-admin',    't-default', 'admin',    'Full access. All permissions, global scope.'),
    ('r-operator', 't-default', 'operator', 'Cert lifecycle + read access. No RBAC management.'),
    ('r-viewer',   't-default', 'viewer',   'Read-only access across cert / profile / issuer / target / agent / audit.'),
    ('r-agent',    't-default', 'agent',    'certctl-agent identity. cert.read + agent.heartbeat + agent.job.* perms.'),
    ('r-mcp',      't-default', 'mcp',      'MCP server identity. Operator-equivalent minus destructive verbs.'),
    ('r-cli',      't-default', 'cli',      'CLI user. Operator-equivalent plus auth.key.* for self-management.'),
    ('r-auditor',  't-default', 'auditor',  'Read-only audit access. Phase 8 splits this from admin for compliance reviewers.')
ON CONFLICT (id) DO NOTHING;

-- Canonical permission catalog.
-- Bundle 2 will add auth.session.* and auth.oidc.* permissions; this
-- catalog is Bundle-1 minimum.
INSERT INTO permissions (id, name, namespace) VALUES
    ('p-cert-read',           'cert.read',           'cert'),
    ('p-cert-issue',          'cert.issue',          'cert'),
    ('p-cert-revoke',         'cert.revoke',         'cert'),
    ('p-cert-delete',         'cert.delete',         'cert'),
    ('p-profile-read',        'profile.read',        'profile'),
    ('p-profile-edit',        'profile.edit',        'profile'),
    ('p-profile-delete',      'profile.delete',      'profile'),
    ('p-issuer-read',         'issuer.read',         'issuer'),
    ('p-issuer-edit',         'issuer.edit',         'issuer'),
    ('p-issuer-delete',       'issuer.delete',       'issuer'),
    ('p-target-read',         'target.read',         'target'),
    ('p-target-edit',         'target.edit',         'target'),
    ('p-target-delete',       'target.delete',       'target'),
    ('p-agent-read',          'agent.read',          'agent'),
    ('p-agent-edit',          'agent.edit',          'agent'),
    ('p-agent-retire',        'agent.retire',        'agent'),
    ('p-agent-heartbeat',     'agent.heartbeat',     'agent'),
    ('p-agent-job-poll',      'agent.job.poll',      'agent.job'),
    ('p-agent-job-complete',  'agent.job.complete',  'agent.job'),
    ('p-agent-job-report',    'agent.job.report',    'agent.job'),
    ('p-audit-read',          'audit.read',          'audit'),
    ('p-audit-export',        'audit.export',        'audit'),
    ('p-auth-role-list',      'auth.role.list',      'auth.role'),
    ('p-auth-role-create',    'auth.role.create',    'auth.role'),
    ('p-auth-role-edit',      'auth.role.edit',      'auth.role'),
    ('p-auth-role-delete',    'auth.role.delete',    'auth.role'),
    ('p-auth-role-assign',    'auth.role.assign',    'auth.role'),
    ('p-auth-role-revoke',    'auth.role.revoke',    'auth.role'),
    ('p-auth-key-list',       'auth.key.list',       'auth.key'),
    ('p-auth-key-create',     'auth.key.create',     'auth.key'),
    ('p-auth-key-rotate',     'auth.key.rotate',     'auth.key'),
    ('p-auth-key-delete',     'auth.key.delete',     'auth.key'),
    ('p-auth-bootstrap-use',  'auth.bootstrap.use',  'auth.bootstrap')
ON CONFLICT (id) DO NOTHING;

-- Default-role permission grants. Each row: (role_id, permission_id, 'global', NULL).
-- Generated programmatically from internal/domain/auth/validate.go::DefaultRoles
-- and pinned here so the schema and the code stay in lockstep.

-- admin: every permission.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-admin', id, 'global', NULL FROM permissions
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- operator: cert lifecycle + read across resources, no RBAC management.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-operator', 'p-cert-read',      'global', NULL),
    ('r-operator', 'p-cert-issue',     'global', NULL),
    ('r-operator', 'p-cert-revoke',    'global', NULL),
    ('r-operator', 'p-cert-delete',    'global', NULL),
    ('r-operator', 'p-profile-read',   'global', NULL),
    ('r-operator', 'p-profile-edit',   'global', NULL),
    ('r-operator', 'p-issuer-read',    'global', NULL),
    ('r-operator', 'p-issuer-edit',    'global', NULL),
    ('r-operator', 'p-target-read',    'global', NULL),
    ('r-operator', 'p-target-edit',    'global', NULL),
    ('r-operator', 'p-target-delete',  'global', NULL),
    ('r-operator', 'p-agent-read',     'global', NULL),
    ('r-operator', 'p-agent-edit',     'global', NULL),
    ('r-operator', 'p-audit-read',     'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- viewer: read-only across resources.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-viewer', 'p-cert-read',     'global', NULL),
    ('r-viewer', 'p-profile-read',  'global', NULL),
    ('r-viewer', 'p-issuer-read',   'global', NULL),
    ('r-viewer', 'p-target-read',   'global', NULL),
    ('r-viewer', 'p-agent-read',    'global', NULL),
    ('r-viewer', 'p-audit-read',    'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- agent: certctl-agent identity. cert.read + agent.heartbeat + agent.job.*.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-agent', 'p-cert-read',          'global', NULL),
    ('r-agent', 'p-agent-heartbeat',    'global', NULL),
    ('r-agent', 'p-agent-job-poll',     'global', NULL),
    ('r-agent', 'p-agent-job-complete', 'global', NULL),
    ('r-agent', 'p-agent-job-report',   'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- mcp: operator-equivalent minus destructive verbs.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-mcp', 'p-cert-read',     'global', NULL),
    ('r-mcp', 'p-cert-issue',    'global', NULL),
    ('r-mcp', 'p-cert-revoke',   'global', NULL),
    ('r-mcp', 'p-profile-read',  'global', NULL),
    ('r-mcp', 'p-profile-edit',  'global', NULL),
    ('r-mcp', 'p-issuer-read',   'global', NULL),
    ('r-mcp', 'p-issuer-edit',   'global', NULL),
    ('r-mcp', 'p-target-read',   'global', NULL),
    ('r-mcp', 'p-target-edit',   'global', NULL),
    ('r-mcp', 'p-agent-read',    'global', NULL),
    ('r-mcp', 'p-audit-read',    'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- cli: operator-equivalent + key self-management.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-cli', 'p-cert-read',        'global', NULL),
    ('r-cli', 'p-cert-issue',       'global', NULL),
    ('r-cli', 'p-cert-revoke',      'global', NULL),
    ('r-cli', 'p-cert-delete',      'global', NULL),
    ('r-cli', 'p-profile-read',     'global', NULL),
    ('r-cli', 'p-profile-edit',     'global', NULL),
    ('r-cli', 'p-issuer-read',      'global', NULL),
    ('r-cli', 'p-issuer-edit',      'global', NULL),
    ('r-cli', 'p-target-read',      'global', NULL),
    ('r-cli', 'p-target-edit',      'global', NULL),
    ('r-cli', 'p-target-delete',    'global', NULL),
    ('r-cli', 'p-agent-read',       'global', NULL),
    ('r-cli', 'p-agent-edit',       'global', NULL),
    ('r-cli', 'p-audit-read',       'global', NULL),
    ('r-cli', 'p-auth-key-list',    'global', NULL),
    ('r-cli', 'p-auth-key-create',  'global', NULL),
    ('r-cli', 'p-auth-key-rotate',  'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- auditor: read-only audit access. Phase 8 splits this from admin
-- formally; Phase 1 reserves the role and its permission set.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-auditor', 'p-audit-read',   'global', NULL),
    ('r-auditor', 'p-audit-export', 'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- Demo-mode preservation: synthetic `actor-demo-anon` with admin role.
-- Bundle 1 Phase 3 will wire the auth middleware to inject this actor
-- into the request context when CERTCTL_AUTH_TYPE=none is configured.
-- The row exists unconditionally; the env-var check happens in code.
-- Reserved system actor: API rejects mutations / deletions targeting
-- this id with 409 Conflict.
INSERT INTO actor_roles (id, actor_id, actor_type, role_id, granted_at, granted_by, tenant_id)
VALUES (
    'ar-demo-anon-admin',
    'actor-demo-anon',
    'Anonymous',
    'r-admin',
    NOW(),
    'system',
    't-default'
)
ON CONFLICT (actor_id, actor_type, role_id, tenant_id) DO NOTHING;

COMMIT;

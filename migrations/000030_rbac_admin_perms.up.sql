-- 000030_rbac_admin_perms.up.sql
-- Bundle 1 / Phase 3.5: admin-only fine-grained permissions for the
-- legacy admin handlers (bulk_revocation, admin_crl_cache,
-- admin_scep_intune, admin_est, intermediate_ca). Phase 3.5 wraps the
-- routes with auth.RequirePermission middleware in router.go and
-- removes the in-body auth.IsAdmin checks; this migration ships the
-- permission catalogue rows the wraps reference.
--
-- All five permissions are seeded into the admin role only; operator,
-- viewer, agent, mcp, cli, auditor do NOT receive them by default.
-- Operators can grant these to a custom role via the Phase 4 RBAC API
-- (POST /api/v1/auth/roles/{id}/permissions) without re-running the
-- migration; ON CONFLICT preserves idempotency for fresh deployments.
--
-- Naming convention follows the canonical catalogue documented in
-- internal/domain/auth/validate.go. Bundle 2 will add auth.session.*
-- and auth.oidc.* permissions in a separate migration.

BEGIN;

INSERT INTO permissions (id, name, namespace) VALUES
    ('p-cert-bulk-revoke',    'cert.bulk_revoke',    'cert'),
    ('p-crl-admin',           'crl.admin',           'crl'),
    ('p-scep-admin',           'scep.admin',          'scep'),
    ('p-est-admin',           'est.admin',           'est'),
    ('p-ca-hierarchy-manage', 'ca.hierarchy.manage', 'ca.hierarchy')
ON CONFLICT (id) DO NOTHING;

-- Grant all five new permissions to the admin role at global scope.
-- The admin role already holds every Phase 1 permission; this migration
-- extends it with the Phase 3.5 admin-only set.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-admin', 'p-cert-bulk-revoke',    'global', NULL),
    ('r-admin', 'p-crl-admin',           'global', NULL),
    ('r-admin', 'p-scep-admin',          'global', NULL),
    ('r-admin', 'p-est-admin',           'global', NULL),
    ('r-admin', 'p-ca-hierarchy-manage', 'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

COMMIT;

-- 000039_audit_crit1_perms.up.sql
--
-- ARCH-L3 (2026-05-13): this migration's INSERT statements don't carry
-- the literal `IF NOT EXISTS` token because Postgres' INSERT syntax
-- doesn't accept it on the INSERT keyword itself. Idempotency comes
-- from the `ON CONFLICT (...) DO NOTHING` clauses on every INSERT —
-- re-running the migration on a tree where the rows already exist is
-- a no-op.
--
-- Audit 2026-05-10 CRIT-1 closure: legacy-CRUD permission set.
--
-- The Bundle 1 + Bundle 2 audit surfaced that the RBAC permission
-- catalogue declared at internal/domain/auth/validate.go was being
-- enforced on roughly 24 admin-only routes — the bulk of state-
-- changing routes (POST /api/v1/certificates, PUT /api/v1/profiles/{id},
-- DELETE /api/v1/issuers/{id}, POST /api/v1/agents/{id}/csr, even
-- POST /api/v1/auth/roles and POST /api/v1/auth/keys/{id}/roles) were
-- registered as plain http.HandlerFunc with no rbacGate wrap. A
-- r-viewer Bearer was essentially r-admin minus five fine-grained
-- verbs at the wire layer. CWE-862.
--
-- This migration adds the 30 missing catalogue permissions and seeds
-- them into the default roles per internal/domain/auth/validate.go's
-- DefaultRoles map. The router-level enforcement lands in the same
-- commit via rbacGate / rbacGateScoped on every state-changing route
-- + every list/read endpoint. An AST-level CI guard
-- (TestRouterRBACGateCoverage) pins the enforcement going forward.
--
-- Auditor pin (audit.read + audit.export ONLY) preserved — the
-- TestAuditorRoleHoldsExactlyAuditReadAndExport regression test
-- continues to pass.
--
-- All operations idempotent. Wrapped in a single transaction.

BEGIN;

-- =============================================================================
-- Catalogue additions (30 permissions across 12 namespaces)
-- =============================================================================

INSERT INTO permissions (id, name, namespace) VALUES
    -- Cert metadata edit (PUT, deploy trigger, bulk-reassign)
    ('p-cert-edit',                   'cert.edit',                   'cert'),

    -- Job lifecycle
    ('p-job-read',                    'job.read',                    'job'),
    ('p-job-cancel',                  'job.cancel',                  'job'),

    -- Approval workflow (Rank 7 primitive — was ungated pre-fix)
    ('p-approval-read',               'approval.read',               'approval'),
    ('p-approval-approve',            'approval.approve',            'approval'),
    ('p-approval-reject',             'approval.reject',             'approval'),

    -- Policies (compliance rules)
    ('p-policy-read',                 'policy.read',                 'policy'),
    ('p-policy-edit',                 'policy.edit',                 'policy'),
    ('p-policy-delete',               'policy.delete',               'policy'),

    -- Teams
    ('p-team-read',                   'team.read',                   'team'),
    ('p-team-edit',                   'team.edit',                   'team'),
    ('p-team-delete',                 'team.delete',                 'team'),

    -- Owners
    ('p-owner-read',                  'owner.read',                  'owner'),
    ('p-owner-edit',                  'owner.edit',                  'owner'),
    ('p-owner-delete',                'owner.delete',                'owner'),

    -- Notifications
    ('p-notification-read',           'notification.read',           'notification'),
    ('p-notification-edit',           'notification.edit',           'notification'),

    -- Discovery (agent + cloud-secret-store)
    ('p-discovery-read',              'discovery.read',              'discovery'),
    ('p-discovery-run',               'discovery.run',               'discovery'),
    ('p-discovery-claim',             'discovery.claim',             'discovery'),

    -- Network scan + SCEP probing
    ('p-network-scan-read',           'network_scan.read',           'network_scan'),
    ('p-network-scan-edit',           'network_scan.edit',           'network_scan'),
    ('p-network-scan-run',            'network_scan.run',            'network_scan'),

    -- Health checks (uptime monitors)
    ('p-healthcheck-read',            'healthcheck.read',            'healthcheck'),
    ('p-healthcheck-edit',            'healthcheck.edit',            'healthcheck'),
    ('p-healthcheck-delete',          'healthcheck.delete',          'healthcheck'),
    ('p-healthcheck-acknowledge',     'healthcheck.acknowledge',     'healthcheck'),

    -- Digest (operator-summary emails)
    ('p-digest-read',                 'digest.read',                 'digest'),
    ('p-digest-send',                 'digest.send',                 'digest'),

    -- Verification (post-deploy probe)
    ('p-verification-read',           'verification.read',           'verification'),
    ('p-verification-run',            'verification.run',            'verification'),

    -- Read-only observability
    ('p-stats-read',                  'stats.read',                  'stats'),
    ('p-metrics-read',                'metrics.read',                'metrics')
ON CONFLICT (id) DO NOTHING;

-- =============================================================================
-- Role grants
--
-- r-admin: every new permission (admin gets all catalogued perms).
-- r-operator: full new CRUD set (operator-tier).
-- r-viewer: read-only set + audit.read (already held).
-- r-mcp: operator-equivalent minus destructive ops (delete / config delete).
-- r-cli: operator-tier with policy CRUD + notification edit.
-- r-agent: just discovery.run (agents submit discovery reports).
-- r-auditor: NOTHING new — pinned at {audit.read, audit.export}.
-- =============================================================================

-- r-admin: every new perm.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-admin', id, 'global', NULL
FROM permissions
WHERE id IN (
    'p-cert-edit',
    'p-job-read', 'p-job-cancel',
    'p-approval-read', 'p-approval-approve', 'p-approval-reject',
    'p-policy-read', 'p-policy-edit', 'p-policy-delete',
    'p-team-read', 'p-team-edit', 'p-team-delete',
    'p-owner-read', 'p-owner-edit', 'p-owner-delete',
    'p-notification-read', 'p-notification-edit',
    'p-discovery-read', 'p-discovery-run', 'p-discovery-claim',
    'p-network-scan-read', 'p-network-scan-edit', 'p-network-scan-run',
    'p-healthcheck-read', 'p-healthcheck-edit', 'p-healthcheck-delete', 'p-healthcheck-acknowledge',
    'p-digest-read', 'p-digest-send',
    'p-verification-read', 'p-verification-run',
    'p-stats-read', 'p-metrics-read'
)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- r-operator: full operator-tier set.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-operator', id, 'global', NULL
FROM permissions
WHERE id IN (
    'p-cert-edit',
    'p-job-read', 'p-job-cancel',
    'p-approval-read', 'p-approval-approve', 'p-approval-reject',
    'p-policy-read', 'p-policy-edit', 'p-policy-delete',
    'p-team-read', 'p-team-edit', 'p-team-delete',
    'p-owner-read', 'p-owner-edit', 'p-owner-delete',
    'p-notification-read', 'p-notification-edit',
    'p-discovery-read', 'p-discovery-run', 'p-discovery-claim',
    'p-network-scan-read', 'p-network-scan-edit', 'p-network-scan-run',
    'p-healthcheck-read', 'p-healthcheck-edit', 'p-healthcheck-delete', 'p-healthcheck-acknowledge',
    'p-digest-read', 'p-digest-send',
    'p-verification-read', 'p-verification-run',
    'p-stats-read', 'p-metrics-read'
)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- r-viewer: read-only across the new surface (+ already-held audit.read).
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-viewer', id, 'global', NULL
FROM permissions
WHERE id IN (
    'p-job-read',
    'p-approval-read',
    'p-policy-read',
    'p-team-read',
    'p-owner-read',
    'p-notification-read',
    'p-discovery-read',
    'p-network-scan-read',
    'p-healthcheck-read',
    'p-digest-read',
    'p-verification-read',
    'p-stats-read', 'p-metrics-read'
)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- r-mcp: operator-equivalent minus destructive ops.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-mcp', id, 'global', NULL
FROM permissions
WHERE id IN (
    'p-cert-edit',
    'p-job-read', 'p-job-cancel',
    'p-approval-read', 'p-approval-approve', 'p-approval-reject',
    'p-policy-read',
    'p-team-read',
    'p-owner-read',
    'p-notification-read', 'p-notification-edit',
    'p-discovery-read', 'p-discovery-claim',
    'p-network-scan-read', 'p-network-scan-run',
    'p-healthcheck-read', 'p-healthcheck-acknowledge',
    'p-digest-read',
    'p-verification-read', 'p-verification-run',
    'p-stats-read', 'p-metrics-read'
)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- r-cli: operator-tier (matches r-operator new perms).
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-cli', id, 'global', NULL
FROM permissions
WHERE id IN (
    'p-cert-edit',
    'p-job-read', 'p-job-cancel',
    'p-approval-read', 'p-approval-approve', 'p-approval-reject',
    'p-policy-read', 'p-policy-edit', 'p-policy-delete',
    'p-team-read', 'p-team-edit',
    'p-owner-read', 'p-owner-edit',
    'p-notification-read', 'p-notification-edit',
    'p-discovery-read', 'p-discovery-run', 'p-discovery-claim',
    'p-network-scan-read', 'p-network-scan-edit', 'p-network-scan-run',
    'p-healthcheck-read', 'p-healthcheck-edit', 'p-healthcheck-acknowledge',
    'p-digest-read', 'p-digest-send',
    'p-verification-read', 'p-verification-run',
    'p-stats-read', 'p-metrics-read'
)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- r-agent: agents submit discovery reports (network scan + cert findings).
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-agent', id, 'global', NULL
FROM permissions
WHERE id IN (
    'p-discovery-run'
)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- r-auditor: NOTHING new. Pin enforced by TestAuditorRoleHoldsExactly...

COMMIT;

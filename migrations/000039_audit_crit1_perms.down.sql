-- 000039_audit_crit1_perms.down.sql
-- Reverse of 000039_audit_crit1_perms.up.sql.
--
-- role_permissions.permission_id is ON DELETE RESTRICT, so the down
-- migration explicitly removes the role grants first, then the
-- permission rows themselves. Wrapped in a single transaction.

BEGIN;

DELETE FROM role_permissions WHERE permission_id IN (
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
);

DELETE FROM permissions WHERE id IN (
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
);

COMMIT;

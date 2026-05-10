-- 000030_rbac_admin_perms.down.sql
-- Reverse of 000030_rbac_admin_perms.up.sql. Drops the role grants
-- first (FK ON DELETE RESTRICT on permissions), then the permissions
-- themselves. Idempotent.

BEGIN;

DELETE FROM role_permissions
WHERE permission_id IN (
    'p-cert-bulk-revoke',
    'p-crl-admin',
    'p-scep-admin',
    'p-est-admin',
    'p-ca-hierarchy-manage'
);

DELETE FROM permissions
WHERE id IN (
    'p-cert-bulk-revoke',
    'p-crl-admin',
    'p-scep-admin',
    'p-est-admin',
    'p-ca-hierarchy-manage'
);

COMMIT;

-- 000037_oidc_phase5.down.sql
-- DESTRUCTIVE: drops the oidc_pre_login_sessions table (which holds
-- mid-handshake OIDC state — losing it forces in-flight logins to
-- restart) AND removes the seven new auth permissions. role_permissions
-- rows referring to the dropped permissions cascade away via the
-- ON DELETE CASCADE on permissions(id).
--
-- Idempotent (IF EXISTS / DELETE-WHERE-IN-LIST).

BEGIN;

DROP INDEX IF EXISTS idx_oidc_pre_login_provider;
DROP INDEX IF EXISTS idx_oidc_pre_login_expires;
DROP TABLE IF EXISTS oidc_pre_login_sessions;

DELETE FROM role_permissions
WHERE permission_id IN (
    'p-auth-session-list',
    'p-auth-session-list-all',
    'p-auth-session-revoke',
    'p-auth-oidc-list',
    'p-auth-oidc-create',
    'p-auth-oidc-edit',
    'p-auth-oidc-delete'
);

DELETE FROM permissions
WHERE id IN (
    'p-auth-session-list',
    'p-auth-session-list-all',
    'p-auth-session-revoke',
    'p-auth-oidc-list',
    'p-auth-oidc-create',
    'p-auth-oidc-edit',
    'p-auth-oidc-delete'
);

COMMIT;

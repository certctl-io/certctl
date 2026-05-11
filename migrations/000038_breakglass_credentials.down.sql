-- 000038_breakglass_credentials.down.sql
-- DESTRUCTIVE: drops the breakglass_credentials table (every stored
-- Argon2id hash is lost — re-enabling break-glass requires re-running
-- SetPassword for every actor) AND removes the two
-- auth.breakglass.{admin,login} permissions. role_permissions rows
-- referring to the dropped permissions cascade away via the ON DELETE
-- CASCADE on permissions(id).
--
-- Idempotent (IF EXISTS / DELETE-WHERE-IN-LIST).

BEGIN;

DROP INDEX IF EXISTS idx_breakglass_credentials_locked_until;
DROP INDEX IF EXISTS idx_breakglass_credentials_actor_id;
DROP TABLE IF EXISTS breakglass_credentials;

DELETE FROM role_permissions
WHERE permission_id IN ('p-auth-breakglass-admin', 'p-auth-breakglass-login');

DELETE FROM permissions
WHERE id IN ('p-auth-breakglass-admin', 'p-auth-breakglass-login');

COMMIT;

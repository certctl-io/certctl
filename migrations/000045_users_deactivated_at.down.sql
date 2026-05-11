-- Down for 000045 — remove the deactivated_at column + 2 user perms.
BEGIN;

DELETE FROM role_permissions
 WHERE permission IN ('auth.user.read', 'auth.user.deactivate');

DELETE FROM permissions
 WHERE name IN ('auth.user.read', 'auth.user.deactivate');

ALTER TABLE users
    DROP COLUMN IF EXISTS deactivated_at;

COMMIT;

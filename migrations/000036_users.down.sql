-- 000036_users.down.sql
-- Reverses 000036_users.up.sql. Destructive: every federated-human
-- user record is dropped. Operators MUST take a backup before
-- running this; SSO logins fail until a fresh login re-creates rows.
--
-- The actor_roles table (Bundle 1's RBAC) does NOT cascade-delete
-- here because actor_roles.actor_id is a TEXT column without an FK
-- to users. Down-migrating users orphans actor_roles rows whose
-- actor_id matches a deleted user; those rows become unreachable
-- via the normal UI but are not auto-cleaned.
BEGIN;

DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;

COMMIT;

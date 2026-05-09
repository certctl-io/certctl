-- 000029_rbac.down.sql
-- Reverse of 000029_rbac.up.sql. Drops in FK-safe order. Idempotent
-- (DROP TABLE IF EXISTS).

BEGIN;

DROP INDEX IF EXISTS idx_role_permissions_role;
DROP INDEX IF EXISTS idx_actor_roles_role;
DROP INDEX IF EXISTS idx_actor_roles_actor;

DROP TABLE IF EXISTS actor_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS tenants;

COMMIT;

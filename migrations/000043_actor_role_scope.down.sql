-- Rollback for 000043_actor_role_scope.up.sql
-- Note: TRUNCATE is destructive of any rows added with non-global scope.
-- That's acceptable for a rollback (forward-only design).
ALTER TABLE actor_roles
    DROP CONSTRAINT IF EXISTS actor_roles_actor_role_scope_unique;
ALTER TABLE actor_roles
    DROP CONSTRAINT IF EXISTS actor_roles_scope_id_required_when_not_global;
ALTER TABLE actor_roles
    DROP CONSTRAINT IF EXISTS actor_roles_scope_type_enum;
DROP INDEX IF EXISTS idx_actor_roles_scope;
ALTER TABLE actor_roles
    DROP COLUMN IF EXISTS scope_type,
    DROP COLUMN IF EXISTS scope_id;
ALTER TABLE actor_roles
    ADD CONSTRAINT actor_roles_actor_id_actor_type_role_id_tenant_id_key
        UNIQUE (actor_id, actor_type, role_id, tenant_id);

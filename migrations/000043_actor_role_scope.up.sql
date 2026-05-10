-- =============================================================================
-- 2026-05-10 Audit / HIGH-10 closure
-- =============================================================================
--
-- Per-actor scope override on role grants. Pre-fix, actor_roles had
-- expires_at (already shipped) but no scope_type/scope_id columns, so
-- "give Alice operator over profile X only" wasn't expressible at the
-- grant layer — the only path was creating a scoped role and granting
-- that. This migration adds the per-grant scope tuple so an operator
-- can attach Alice to the standing r-operator role but scope the
-- grant to profile X.
--
-- scope_type defaults to 'global' to preserve existing rows; scope_id
-- stays NULL when scope_type='global'. Authorizer.CheckPermission
-- already understands the tuple shape (role_permissions carries the
-- same columns); the actor-role addition gives operators a second
-- knob without forcing them to fork roles.
-- =============================================================================

ALTER TABLE actor_roles
    ADD COLUMN IF NOT EXISTS scope_type TEXT NOT NULL DEFAULT 'global',
    ADD COLUMN IF NOT EXISTS scope_id   TEXT;

ALTER TABLE actor_roles
    ADD CONSTRAINT actor_roles_scope_type_enum
        CHECK (scope_type IN ('global', 'profile', 'issuer'));

ALTER TABLE actor_roles
    ADD CONSTRAINT actor_roles_scope_id_required_when_not_global
        CHECK (
            (scope_type = 'global' AND scope_id IS NULL) OR
            (scope_type IN ('profile', 'issuer') AND scope_id IS NOT NULL)
        );

-- The (actor_id, actor_type, role_id, tenant_id) uniqueness must
-- relax: an operator can grant the same role to the same actor at
-- different scopes (e.g. r-operator on profile-A AND on profile-B).
ALTER TABLE actor_roles
    DROP CONSTRAINT IF EXISTS actor_roles_actor_id_actor_type_role_id_tenant_id_key;

ALTER TABLE actor_roles
    ADD CONSTRAINT actor_roles_actor_role_scope_unique
        UNIQUE (actor_id, actor_type, role_id, scope_type, scope_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_actor_roles_scope
    ON actor_roles(scope_type, scope_id) WHERE scope_id IS NOT NULL;

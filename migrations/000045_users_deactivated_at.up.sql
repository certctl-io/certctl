-- 000045_users_deactivated_at.up.sql
-- Audit 2026-05-10 MED-11 closure: federated-user admin surface.
--
-- Adds the deactivated_at column to users so the admin DELETE-by-id
-- path can soft-delete a federated identity without destroying the
-- row (the row is the OIDC binding — destroying it would re-mint a
-- fresh user on the next IdP login under the same subject, losing
-- the audit trail). Also seeds two new catalogue permissions:
--
--   auth.user.read       — list / get a user. Seeded into r-admin,
--                          r-operator, r-auditor.
--   auth.user.deactivate — set deactivated_at + cascade-revoke
--                          sessions. Seeded into r-admin ONLY.
--
-- Idempotent. Single transaction.

BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ;

-- v2.1.0 Phase-9 cold-DB-smoke fix: the original commit set just
-- (name) and used a `permission` column in role_permissions. The
-- 000029 schema actually defines `permissions (id PK, name UNIQUE,
-- namespace NOT NULL)` and `role_permissions (..., permission_id, ...)`.
-- testcontainers schema-per-test never exercised this path; the cold
-- compose-up smoke caught it on a fresh Postgres.
INSERT INTO permissions (id, name, namespace) VALUES
    ('p-auth-user-read',       'auth.user.read',       'auth.user'),
    ('p-auth-user-deactivate', 'auth.user.deactivate', 'auth.user')
ON CONFLICT (id) DO NOTHING;

-- Read is broad (admin / operator / auditor).
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-admin',    'p-auth-user-read', 'global', NULL),
    ('r-operator', 'p-auth-user-read', 'global', NULL),
    ('r-auditor',  'p-auth-user-read', 'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

-- Deactivate is admin-only.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id) VALUES
    ('r-admin', 'p-auth-user-deactivate', 'global', NULL)
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

COMMIT;

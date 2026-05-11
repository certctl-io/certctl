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

INSERT INTO permissions (name) VALUES
    ('auth.user.read'),
    ('auth.user.deactivate')
ON CONFLICT (name) DO NOTHING;

-- Read is broad (admin / operator / auditor).
INSERT INTO role_permissions (role_id, permission, scope_type, scope_id) VALUES
    ('r-admin',    'auth.user.read', 'global', NULL),
    ('r-operator', 'auth.user.read', 'global', NULL),
    ('r-auditor',  'auth.user.read', 'global', NULL)
ON CONFLICT DO NOTHING;

-- Deactivate is admin-only.
INSERT INTO role_permissions (role_id, permission, scope_type, scope_id) VALUES
    ('r-admin', 'auth.user.deactivate', 'global', NULL)
ON CONFLICT DO NOTHING;

COMMIT;

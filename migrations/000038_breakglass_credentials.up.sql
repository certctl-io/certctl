-- 000038_breakglass_credentials.up.sql
-- Auth Bundle 2 / Phase 7.5: break-glass admin (local password,
-- Argon2id + lockout, default-OFF).
--
-- Decision 4: enabled per-deployment via CERTCTL_BREAKGLASS_ENABLED;
-- the entire surface is invisible (handler returns 404, not 403) when
-- disabled. Paired with WebAuthn 2FA in v3 (Decision 12). Threat model
-- explicit: enabling break-glass is a deliberate bypass of the SSO
-- security boundary; an attacker who phishes the password OR finds it
-- in a compromised password manager bypasses MFA, OIDC, and every
-- group-claim gate. Operators turn it on during SSO incidents and
-- turn it off after recovery.
--
-- Two things land here:
--
--   1. breakglass_credentials table — at most one row per actor
--      (UNIQUE(actor_id)). Stores the Argon2id PHC-format password
--      hash + lockout state machine (failure_count, locked_until,
--      last_failure_at). The service layer's Authenticate path does
--      constant-time-compare against the hash AND maintains identical
--      timing/error-shape parity for the wrong-password / locked-
--      account / non-existent-actor paths so an attacker can't probe
--      whether a given actor has break-glass configured.
--
--   2. Two new permissions extending the canonical catalogue:
--        auth.breakglass.admin  — set/rotate/unlock/remove break-glass
--                                 credentials. Granted to r-admin.
--        auth.breakglass.login  — the actor itself uses break-glass to
--                                 log in. Granted automatically by
--                                 SetPassword to the target actor's
--                                 row in actor_roles (scope=global so
--                                 the lockup state machine applies
--                                 uniformly).
--
-- All operations idempotent. Wrapped in a single transaction.

BEGIN;

-- =============================================================================
-- breakglass_credentials table
-- =============================================================================

CREATE TABLE IF NOT EXISTS breakglass_credentials (
    -- id is the prefix-`bg-` opaque identifier. One row per actor;
    -- the (actor_id) UNIQUE index pins the cardinality.
    id                          TEXT PRIMARY KEY,

    tenant_id                   TEXT NOT NULL DEFAULT 't-default'
                                    REFERENCES tenants(id) ON DELETE CASCADE,

    -- actor_id references users(id); ON DELETE CASCADE so deleting a
    -- user atomically removes their break-glass credential.
    actor_id                    TEXT NOT NULL
                                    REFERENCES users(id) ON DELETE CASCADE,

    -- Argon2id PHC-format string: $argon2id$v=19$m=65536,t=3,p=4$
    -- <salt-base64>$<hash-base64>. NEVER stored in plaintext; the
    -- domain type's PasswordHash field is `json:"-"` so a misconfigured
    -- handler that marshals the row directly cannot wire-leak the hash.
    password_hash               TEXT NOT NULL,

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_password_change_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Lockout state machine. failure_count increments on every wrong-
    -- password attempt; when it crosses CERTCTL_BREAKGLASS_LOCKOUT_THRESHOLD
    -- (default 5) the row is locked for CERTCTL_BREAKGLASS_LOCKOUT_DURATION
    -- (default 15m). After CERTCTL_BREAKGLASS_LOCKOUT_RESET_INTERVAL of
    -- idleness (default 1h since last_failure_at) the counter resets.
    failure_count               INT NOT NULL DEFAULT 0,
    locked_until                TIMESTAMPTZ NULL,
    last_failure_at             TIMESTAMPTZ NULL,

    CONSTRAINT breakglass_failure_count_non_negative
        CHECK (failure_count >= 0)
);

-- At-most-one-credential-per-actor invariant.
CREATE UNIQUE INDEX IF NOT EXISTS idx_breakglass_credentials_actor_id
    ON breakglass_credentials (actor_id);

-- Index for "is this actor currently locked" hot path during the
-- Authenticate fast-fail check.
CREATE INDEX IF NOT EXISTS idx_breakglass_credentials_locked_until
    ON breakglass_credentials (locked_until)
    WHERE locked_until IS NOT NULL;

-- =============================================================================
-- Two new permissions extending the Bundle 1 + Bundle 2 catalogue.
-- =============================================================================

INSERT INTO permissions (id, name, namespace) VALUES
    ('p-auth-breakglass-admin', 'auth.breakglass.admin', 'auth.breakglass'),
    ('p-auth-breakglass-login', 'auth.breakglass.login', 'auth.breakglass')
ON CONFLICT (id) DO NOTHING;

-- Grant auth.breakglass.admin to r-admin only by default. The role-
-- permission API can rotate this post-deploy if the operator wants
-- a dedicated "break-glass operator" role.
INSERT INTO role_permissions (role_id, permission_id, scope_type, scope_id)
SELECT 'r-admin', id, 'global', NULL
FROM permissions
WHERE id IN ('p-auth-breakglass-admin', 'p-auth-breakglass-login')
ON CONFLICT (role_id, permission_id, scope_type, scope_id) DO NOTHING;

COMMIT;

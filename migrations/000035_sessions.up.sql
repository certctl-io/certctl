-- 000035_sessions.up.sql
-- Auth Bundle 2 / Phase 2: server-side session management. Two cookie
-- shapes share the `sessions` table:
--
--   1. Post-login row: minted by SessionService.Create after a
--      successful OIDC callback or break-glass authenticate. Carries
--      the cookie HMAC-signed via the active session_signing_keys row.
--      Idle timeout 1h default, absolute timeout 8h default.
--
--   2. Pre-login row: minted at /auth/oidc/login to hold OIDC state +
--      nonce + PKCE verifier across the IdP redirect. Same row shape,
--      `is_pre_login = true`, 10-minute absolute TTL, GC'd by the same
--      scheduler sweep as expired post-login sessions.
--
-- session_signing_keys holds the HMAC key material. Phase 4's
-- Service.RotateSigningKey mints new keys and retires old ones; the
-- retention window keeps retired keys valid for verification of
-- cookies signed under them so existing sessions don't immediately
-- fail.
--
-- All operations idempotent. Wrapped in a single transaction.
-- Multi-tenant ready (tenant_id on every row).

BEGIN;

-- Session signing keys. The "active" key is the most recently created
-- non-retired row; Phase 4's Service.GetActive returns it. Retired keys
-- (RetiredAt IS NOT NULL) stay in the table for the configurable
-- retention window so cookies signed under them still verify.
CREATE TABLE IF NOT EXISTS session_signing_keys (
    id                       TEXT PRIMARY KEY,                       -- prefix `sk-`
    tenant_id                TEXT NOT NULL DEFAULT 't-default'
                                 REFERENCES tenants(id) ON DELETE CASCADE,
    key_material_encrypted   BYTEA NOT NULL,                         -- v2 blob; never plaintext
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at               TIMESTAMPTZ NULL,

    CONSTRAINT session_signing_keys_retired_after_created
        CHECK (retired_at IS NULL OR retired_at >= created_at)
);

-- Index on (tenant_id, retired_at IS NULL, created_at DESC) backs the
-- GetActive query: most-recently-created non-retired key per tenant.
CREATE INDEX IF NOT EXISTS idx_session_signing_keys_active
    ON session_signing_keys (tenant_id, created_at DESC)
    WHERE retired_at IS NULL;

-- Sessions table. Holds both post-login and pre-login rows; is_pre_login
-- discriminates. CSRFTokenHash is SHA-256 hex of the operator-facing
-- CSRF token (the plaintext lives in a separate JS-readable cookie so
-- the GUI can echo it into the X-CSRF-Token header).
CREATE TABLE IF NOT EXISTS sessions (
    id                  TEXT PRIMARY KEY,                            -- prefix `ses-`
    tenant_id           TEXT NOT NULL DEFAULT 't-default'
                            REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id            TEXT NOT NULL,
    actor_type          TEXT NOT NULL,                               -- matches domain.ActorType strings
    signing_key_id      TEXT NOT NULL REFERENCES session_signing_keys(id) ON DELETE RESTRICT,
    is_pre_login        BOOLEAN NOT NULL DEFAULT FALSE,
    csrf_token_hash     TEXT NOT NULL DEFAULT '',                    -- 64 lowercase hex chars when set; '' for pre-login rows
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address          TEXT NOT NULL DEFAULT '',
    user_agent          TEXT NOT NULL DEFAULT '',
    revoked_at          TIMESTAMPTZ NULL,

    CONSTRAINT sessions_expiry_order
        CHECK (absolute_expires_at > idle_expires_at),
    CONSTRAINT sessions_idle_after_created
        CHECK (idle_expires_at > created_at)
);

-- Index for "list sessions for me" hot path (Phase 5
-- GET /v1/auth/sessions) — actor_id is the WHERE clause.
CREATE INDEX IF NOT EXISTS idx_sessions_actor_id
    ON sessions (actor_id, actor_type)
    WHERE revoked_at IS NULL AND is_pre_login = FALSE;

-- Index for the active-session lookup (Phase 4 Validate hot path).
-- Partial index (revoked_at IS NULL) keeps it small; revoked sessions
-- are GC'd separately.
CREATE INDEX IF NOT EXISTS idx_sessions_active
    ON sessions (id)
    WHERE revoked_at IS NULL;

-- Index for the pre-login GC sweep: walk pre-login rows older than
-- the 10-minute TTL.
CREATE INDEX IF NOT EXISTS idx_sessions_pre_login_gc
    ON sessions (created_at)
    WHERE is_pre_login = TRUE;

-- Index for the absolute-expired GC sweep: walk rows past the absolute
-- expiry window.
CREATE INDEX IF NOT EXISTS idx_sessions_absolute_expires_at
    ON sessions (absolute_expires_at);

COMMIT;

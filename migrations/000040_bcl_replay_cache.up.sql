-- 000040_bcl_replay_cache.up.sql
-- Audit 2026-05-10 HIGH-3 closure: BCL logout_token replay defense.
--
-- Pre-fix, the BCL handler (auth_session_oidc.go::BackChannelLogout)
-- required `iat != 0` and `jti != ""` but never (a) checked iat
-- freshness against a skew window, or (b) checked jti against a
-- consumed-set. A captured logout_token was replayable indefinitely;
-- once CRIT-2 was fixed, every replay would revoke the user's current
-- sessions — persistent DoS.
--
-- RFC 9700 §2.7 + OIDC BCL 1.0 §2.5 require jti replay defense.
--
-- This table stores accepted (jti, issuer) pairs with a TTL. The
-- handler's ConsumeJTI call uses INSERT...ON CONFLICT DO NOTHING
-- semantics for atomic single-use. The scheduler GC loop sweeps
-- expired rows.
--
-- Composite PK on (jti, issuer_url) because OIDC `jti` uniqueness is
-- per-issuer per RFC 7519 §4.1.7 — a Keycloak jti=abc and an Auth0
-- jti=abc are distinct events.

BEGIN;

CREATE TABLE IF NOT EXISTS oidc_bcl_consumed_jtis (
    jti          TEXT NOT NULL,
    issuer_url   TEXT NOT NULL,
    consumed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (jti, issuer_url)
);

-- TTL index for the GC sweep (`WHERE expires_at < now()`).
CREATE INDEX IF NOT EXISTS idx_oidc_bcl_consumed_jtis_expires
    ON oidc_bcl_consumed_jtis (expires_at);

COMMIT;

-- 000024_ocsp_response_cache.up.sql
--
-- Production hardening II Phase 2: pre-signed OCSP response cache.
--
-- Mirrors the crl_cache pattern from migration 000019 — same
-- read-through facade, same scheduler-driven refresh — but per
-- (issuer_id, serial) instead of per-issuer. Without this cache, every
-- inbound OCSP request triggers a fresh signature with the dedicated
-- responder cert, which becomes the bottleneck for high-volume relying
-- parties (Apple Push, Microsoft Edge SmartScreen, etc.).
--
-- After this migration the scheduler's ocspCacheRefreshLoop pre-signs
-- responses for every active (issuer_id, serial) at a configurable
-- interval (default 1h, env var CERTCTL_OCSP_CACHE_REFRESH_INTERVAL),
-- and CAOperationsSvc.GetOCSPResponseWithNonce reads from the cache
-- on the hot path. On cache miss the service falls back to live
-- signing AND writes the result back to the cache (read-through).
--
-- LOAD-BEARING SECURITY INVARIANT: the revocation service MUST call
-- OCSPResponseCacheService.InvalidateOnRevoke after a successful
-- revoke. Without that wire, a revoked cert keeps returning the
-- stale "good" response from cache until the next scheduler tick —
-- a security incident. The Phase 2 prompt's frozen decision 0.4
-- mandates this.
--
-- Idempotent: every CREATE uses IF NOT EXISTS so re-running the
-- migration is safe (matches the project's migration convention).

CREATE TABLE IF NOT EXISTS ocsp_response_cache (
    issuer_id          TEXT NOT NULL REFERENCES issuers(id) ON DELETE CASCADE,
    serial_hex         TEXT NOT NULL,
    response_der       BYTEA NOT NULL,
    cert_status        TEXT NOT NULL,                       -- 'good' | 'revoked' | 'unknown'
    revocation_reason  INTEGER,                             -- nullable; set only when cert_status='revoked'
    revoked_at         TIMESTAMPTZ,                         -- nullable; set only when cert_status='revoked'
    this_update        TIMESTAMPTZ NOT NULL,
    next_update        TIMESTAMPTZ NOT NULL,
    generated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (issuer_id, serial_hex)
);

-- Lets the scheduler refresh loop quickly identify entries whose
-- next_update has fallen behind the current time. Runs at every
-- ocspCacheRefreshLoop tick.
CREATE INDEX IF NOT EXISTS idx_ocsp_response_cache_next_update
    ON ocsp_response_cache(next_update);

-- Lets the admin observability endpoint efficiently list per-issuer
-- entries for the GUI cache stats panel (Phase 8 wires this into the
-- AdminCRLCacheHandler-equivalent).
CREATE INDEX IF NOT EXISTS idx_ocsp_response_cache_issuer
    ON ocsp_response_cache(issuer_id);

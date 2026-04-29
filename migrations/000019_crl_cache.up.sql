-- 000019_crl_cache.up.sql
--
-- CRL cache + generation event log for the scheduler-driven CRL
-- pre-generation work (CRL/OCSP responder bundle).
--
-- Before this migration the CRL endpoint at /.well-known/pki/crl/{issuer_id}
-- regenerated the entire CRL on every HTTP request — every relying party
-- fetch hit the certificate_revocations table, built the entry list,
-- signed the CRL, and discarded the result. For a busy CA with many
-- relying parties this DOSes itself.
--
-- After this migration the scheduler's crlGenerationLoop pre-generates
-- CRLs at a configurable interval (default 1h, env var
-- CERTCTL_CRL_GENERATION_INTERVAL) and the HTTP handler reads from
-- crl_cache. On cache miss / staleness the cache service triggers an
-- immediate generation via singleflight (to coalesce concurrent miss
-- requests for the same issuer into a single generation).
--
-- Idempotent: every CREATE uses IF NOT EXISTS so re-running the
-- migration is safe (matches the project's migration convention).

CREATE TABLE IF NOT EXISTS crl_cache (
    issuer_id              TEXT PRIMARY KEY REFERENCES issuers(id) ON DELETE CASCADE,
    crl_der                BYTEA NOT NULL,
    crl_number             BIGINT NOT NULL,             -- monotonic per RFC 5280 §5.2.3
    this_update            TIMESTAMPTZ NOT NULL,
    next_update            TIMESTAMPTZ NOT NULL,
    generated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generation_duration_ms INTEGER NOT NULL,
    revoked_count          INTEGER NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lets the scheduler quickly find issuers whose cache is stale (next_update
-- already in the past). The query "find issuers needing regeneration" runs
-- at every tick of crlGenerationLoop.
CREATE INDEX IF NOT EXISTS idx_crl_cache_next_update ON crl_cache(next_update);

-- Track every (re)generation event for ops visibility. Failed generations
-- (succeeded=false) leave a breadcrumb operators can grep when
-- troubleshooting "why isn't the CRL fresh." The id is bigserial so the
-- table is naturally ordered by insertion; the (issuer_id, started_at)
-- index serves the GUI's "recent generations for this issuer" query.
CREATE TABLE IF NOT EXISTS crl_generation_events (
    id            BIGSERIAL PRIMARY KEY,
    issuer_id     TEXT NOT NULL,
    crl_number    BIGINT NOT NULL,
    duration_ms   INTEGER NOT NULL,
    revoked_count INTEGER NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    succeeded     BOOLEAN NOT NULL,
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_crl_generation_events_issuer_started
    ON crl_generation_events(issuer_id, started_at DESC);

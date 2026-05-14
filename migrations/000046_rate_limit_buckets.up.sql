-- Phase 13 Sprint 13.2 closure (2026-05-14, architecture diligence audit
-- ARCH-M1): introduce a postgres-backed sliding-window rate limiter so
-- per-process / in-memory limits become cross-replica-consistent when
-- the operator sets CERTCTL_RATELIMIT_BACKEND=postgres (wired in
-- Sprint 13.3).
--
-- One row per (bucket_key) — caller composes the key the same way the
-- memory backend already does (e.g. "subject|issuer" for SCEP/Intune,
-- "srcIP|peek" for EST failed-basic, raw "actor" for export, etc.).
-- The `timestamps` array stores the in-window log; prune-on-Allow
-- keeps it bounded by the limiter's maxN cap.
--
-- updated_at + the index on it support the Sprint 13.3 scheduler
-- janitor loop: any row whose updated_at is older than the longest
-- configured window is safely deletable.
--
-- Per CLAUDE.md "Idempotent migrations" architecture decision:
-- IF NOT EXISTS on every statement. Re-running this migration is
-- a no-op on a database that already has the table.

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    bucket_key TEXT          PRIMARY KEY,
    timestamps TIMESTAMPTZ[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS rate_limit_buckets_updated_at_idx
    ON rate_limit_buckets (updated_at);

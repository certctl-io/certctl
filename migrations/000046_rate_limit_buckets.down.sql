-- Phase 13 Sprint 13.2 reversal — drop the rate-limit bucket table.
-- Down migrations are not run in production; this file exists for
-- developer-side rollback during integration testing.

DROP INDEX IF EXISTS rate_limit_buckets_updated_at_idx;
DROP TABLE IF EXISTS rate_limit_buckets;

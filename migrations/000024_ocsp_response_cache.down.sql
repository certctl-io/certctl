-- 000024_ocsp_response_cache.down.sql
--
-- Rollback the production hardening II Phase 2 OCSP cache. Idempotent.

DROP INDEX IF EXISTS idx_ocsp_response_cache_issuer;
DROP INDEX IF EXISTS idx_ocsp_response_cache_next_update;
DROP TABLE IF EXISTS ocsp_response_cache;

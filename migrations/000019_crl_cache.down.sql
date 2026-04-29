-- 000019_crl_cache.down.sql — reverses 000019_crl_cache.up.sql.
--
-- Drop in reverse FK order. crl_generation_events has no FK so order
-- between the two table drops is mechanical only.

DROP INDEX IF EXISTS idx_crl_generation_events_issuer_started;
DROP TABLE IF EXISTS crl_generation_events;

DROP INDEX IF EXISTS idx_crl_cache_next_update;
DROP TABLE IF EXISTS crl_cache;

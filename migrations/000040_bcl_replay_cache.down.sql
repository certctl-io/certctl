-- 000040_bcl_replay_cache.down.sql
-- Reverse of 000040_bcl_replay_cache.up.sql.

BEGIN;
DROP INDEX IF EXISTS idx_oidc_bcl_consumed_jtis_expires;
DROP TABLE IF EXISTS oidc_bcl_consumed_jtis;
COMMIT;

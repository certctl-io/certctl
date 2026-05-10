-- 000035_sessions.down.sql
-- Reverses 000035_sessions.up.sql. Destructive: every active session
-- + every signing key is dropped. Operators MUST take a backup before
-- running this; sessions cannot be recovered.
--
-- FK-safe order: sessions → session_signing_keys (sessions ref
-- signing_key_id, so sessions drop first).
BEGIN;

DROP INDEX IF EXISTS idx_sessions_absolute_expires_at;
DROP INDEX IF EXISTS idx_sessions_pre_login_gc;
DROP INDEX IF EXISTS idx_sessions_active;
DROP INDEX IF EXISTS idx_sessions_actor_id;
DROP TABLE IF EXISTS sessions;

DROP INDEX IF EXISTS idx_session_signing_keys_active;
DROP TABLE IF EXISTS session_signing_keys;

COMMIT;

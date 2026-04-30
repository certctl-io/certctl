-- EST RFC 7030 hardening master bundle Phase 11.1 rollback.
ALTER TABLE managed_certificates DROP COLUMN IF EXISTS source;

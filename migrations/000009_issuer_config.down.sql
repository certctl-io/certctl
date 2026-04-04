-- Rollback migration 000009: Remove dynamic issuer configuration columns
ALTER TABLE issuers DROP COLUMN IF EXISTS encrypted_config;
ALTER TABLE issuers DROP COLUMN IF EXISTS last_tested_at;
ALTER TABLE issuers DROP COLUMN IF EXISTS test_status;
ALTER TABLE issuers DROP COLUMN IF EXISTS source;

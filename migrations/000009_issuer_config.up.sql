-- Migration 000009: Add dynamic issuer configuration columns
-- Supports M34: Dynamic Issuer Configuration (GUI)

-- encrypted_config stores AES-GCM encrypted config blob containing all fields including secrets.
-- The existing `config` JSONB column is retained for backward compatibility and holds a redacted copy.
ALTER TABLE issuers ADD COLUMN IF NOT EXISTS encrypted_config BYTEA;

-- last_tested_at tracks when the issuer connection was last successfully tested.
ALTER TABLE issuers ADD COLUMN IF NOT EXISTS last_tested_at TIMESTAMPTZ;

-- test_status tracks the latest connection test result.
ALTER TABLE issuers ADD COLUMN IF NOT EXISTS test_status TEXT NOT NULL DEFAULT 'untested';

-- source tracks where the issuer configuration originated from.
-- 'database' = created via GUI, 'env' = seeded from environment variables.
ALTER TABLE issuers ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'database';

-- Migration 000010: Add dynamic target configuration columns
-- Supports M35: Dynamic Target Configuration (GUI)

-- encrypted_config stores AES-GCM encrypted config blob containing all fields including secrets.
-- The existing `config` JSONB column is retained for backward compatibility and holds a redacted copy.
ALTER TABLE deployment_targets ADD COLUMN IF NOT EXISTS encrypted_config BYTEA;

-- last_tested_at tracks when the target connection was last tested (agent heartbeat check).
ALTER TABLE deployment_targets ADD COLUMN IF NOT EXISTS last_tested_at TIMESTAMPTZ;

-- test_status tracks the latest connection test result.
ALTER TABLE deployment_targets ADD COLUMN IF NOT EXISTS test_status TEXT NOT NULL DEFAULT 'untested';

-- source tracks where the target configuration originated from.
-- 'database' = created via GUI, 'env' = seeded from environment variables.
ALTER TABLE deployment_targets ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'database';

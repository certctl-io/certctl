-- Rollback migration 000010: Remove dynamic target configuration columns
ALTER TABLE deployment_targets DROP COLUMN IF EXISTS encrypted_config;
ALTER TABLE deployment_targets DROP COLUMN IF EXISTS last_tested_at;
ALTER TABLE deployment_targets DROP COLUMN IF EXISTS test_status;
ALTER TABLE deployment_targets DROP COLUMN IF EXISTS source;

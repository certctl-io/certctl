-- Rollback for 000042_oidc_provider_enabled.up.sql
ALTER TABLE oidc_providers
    DROP COLUMN IF EXISTS enabled;

-- 000034_oidc_providers.down.sql
-- Reverses 000034_oidc_providers.up.sql. Destructive: every configured
-- OIDC provider + every group→role mapping is dropped. Existing OIDC
-- sessions in the `sessions` table (000035) become orphaned but are
-- not auto-revoked here; operators run `certctl-cli auth sessions
-- revoke-all` after a down-migration if they need clean state.
--
-- FK-safe order: group_role_mappings → oidc_providers (mappings ref
-- provider_id, so mappings drop first).
BEGIN;

DROP INDEX IF EXISTS idx_group_role_mappings_provider_id;
DROP TABLE IF EXISTS group_role_mappings;
DROP TABLE IF EXISTS oidc_providers;

COMMIT;

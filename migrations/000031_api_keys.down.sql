-- Bundle 1 Phase 6: drop the operator API-keys table. Down is destructive;
-- keys minted by bootstrap will fail to authenticate after this runs.
BEGIN;
DROP INDEX IF EXISTS idx_api_keys_created_by;
DROP INDEX IF EXISTS idx_api_keys_tenant_id;
DROP TABLE IF EXISTS api_keys;
COMMIT;

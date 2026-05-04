-- 000028_intermediate_ca_hierarchy.down.sql — reverse of the up migration.
-- Drops the intermediate_cas table + its indexes + the hierarchy_mode
-- column on issuers. Idempotent (IF EXISTS everywhere).

DROP INDEX IF EXISTS idx_intermediate_ca_expiring;
DROP INDEX IF EXISTS idx_intermediate_ca_state;
DROP INDEX IF EXISTS idx_intermediate_ca_parent;
DROP INDEX IF EXISTS idx_intermediate_ca_owning_issuer;
DROP INDEX IF EXISTS idx_intermediate_ca_unique_name_per_issuer;
DROP INDEX IF EXISTS idx_intermediate_ca_active_root_per_issuer;

DROP TABLE IF EXISTS intermediate_cas;

ALTER TABLE issuers
    DROP COLUMN IF EXISTS hierarchy_mode;

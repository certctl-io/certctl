-- Rollback: remove agent metadata columns

DROP INDEX IF EXISTS idx_agents_os;
DROP INDEX IF EXISTS idx_agents_architecture;

ALTER TABLE agents DROP COLUMN IF EXISTS os;
ALTER TABLE agents DROP COLUMN IF EXISTS architecture;
ALTER TABLE agents DROP COLUMN IF EXISTS ip_address;
ALTER TABLE agents DROP COLUMN IF EXISTS version;

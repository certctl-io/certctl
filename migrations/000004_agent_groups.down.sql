-- Rollback migration 000004: Agent Groups
ALTER TABLE renewal_policies DROP COLUMN IF EXISTS agent_group_id;
DROP TABLE IF EXISTS agent_group_members;
DROP TABLE IF EXISTS agent_groups;

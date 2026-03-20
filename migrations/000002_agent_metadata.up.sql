-- Add agent metadata columns for M10: Agent Metadata + Targets
-- Agents report OS, platform, architecture, and IP address via heartbeat

ALTER TABLE agents ADD COLUMN IF NOT EXISTS os VARCHAR(100) DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS architecture VARCHAR(100) DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45) DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS version VARCHAR(50) DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_agents_os ON agents(os);
CREATE INDEX IF NOT EXISTS idx_agents_architecture ON agents(architecture);

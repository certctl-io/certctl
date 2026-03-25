-- Migration 000004: Agent Groups
-- Adds dynamic device grouping by agent metadata criteria with manual override.

CREATE TABLE IF NOT EXISTS agent_groups (
    id TEXT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    -- Dynamic matching criteria (empty = manual-only group)
    match_os VARCHAR(100) DEFAULT '',
    match_architecture VARCHAR(100) DEFAULT '',
    match_ip_cidr VARCHAR(45) DEFAULT '',
    match_version VARCHAR(50) DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Manual group membership overrides (agents explicitly added/excluded)
CREATE TABLE IF NOT EXISTS agent_group_members (
    agent_group_id TEXT NOT NULL REFERENCES agent_groups(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    membership_type VARCHAR(20) NOT NULL DEFAULT 'include',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_group_id, agent_id)
);

-- Optional: scope renewal policies to an agent group
ALTER TABLE renewal_policies ADD COLUMN IF NOT EXISTS agent_group_id TEXT REFERENCES agent_groups(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_agent_groups_name ON agent_groups(name);
CREATE INDEX IF NOT EXISTS idx_agent_groups_enabled ON agent_groups(enabled);
CREATE INDEX IF NOT EXISTS idx_agent_group_members_agent ON agent_group_members(agent_id);

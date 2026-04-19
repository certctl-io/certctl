-- Migration 000015 rollback: reverse the agent retirement surface.
--
-- Contract (enforced by migration_000015_test.go Stage 3):
--   * retired_at + retired_reason columns removed from agents
--   * retired_at + retired_reason columns removed from deployment_targets
--   * deployment_targets.agent_id FK restored to ON DELETE CASCADE
--
-- WARNING: dropping the soft-retire columns also drops the audit history of
-- which agents have been retired and why. Operators rolling back should first
-- export the retired_at/retired_reason values they care about preserving.
--
-- Order matters: drop supporting indexes BEFORE dropping the columns they
-- reference. DROP INDEX IF EXISTS + DROP COLUMN IF EXISTS keep the down safe
-- to re-apply.

-- Drop supporting indexes first (they reference columns we're about to drop).
DROP INDEX IF EXISTS idx_agents_retired_at;
DROP INDEX IF EXISTS idx_deployment_targets_retired_at;

-- Reverse the FK flip: restore CASCADE semantics so the rolled-back server
-- behaves identically to pre-000015 behavior.
ALTER TABLE deployment_targets
  DROP CONSTRAINT IF EXISTS deployment_targets_agent_id_fkey;
ALTER TABLE deployment_targets
  ADD CONSTRAINT deployment_targets_agent_id_fkey
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE;

-- Remove the soft-retirement columns.
ALTER TABLE deployment_targets DROP COLUMN IF EXISTS retired_reason;
ALTER TABLE deployment_targets DROP COLUMN IF EXISTS retired_at;
ALTER TABLE agents DROP COLUMN IF EXISTS retired_reason;
ALTER TABLE agents DROP COLUMN IF EXISTS retired_at;

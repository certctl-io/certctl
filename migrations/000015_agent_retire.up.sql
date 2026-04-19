-- Migration 000015: Agent retirement (I-004 fail-closed coverage-gap fix).
--
-- Adds a soft-delete surface for agents and their deployment_targets, and
-- replaces the fail-open DELETE CASCADE on deployment_targets.agent_id (see
-- migration 000001 line 104) with a fail-closed DELETE RESTRICT.
--
-- Rationale (audit finding I-004):
--   Today a bare `DELETE FROM agents WHERE id = $1` silently cascades through
--   deployment_targets (CASCADE) and blanks jobs.agent_id (SET NULL, migration
--   000001 line 146). The cascade vaporises the deployment audit trail — "who
--   deployed what, to where, when" — and leaves nothing behind to answer
--   forensic questions after an operator mis-types an agent ID. Flipping the
--   deployment_targets FK to RESTRICT forces any DELETE to fail at the DB
--   layer unless dependencies are cleared first; the new retired_at +
--   retired_reason pair give the service layer a soft-retirement path that
--   preserves history.
--
-- Mirrors migration 000005 (revocation) in shape: nullable timestamp +
-- nullable reason string. Column type is TEXT (not VARCHAR(50)) so retirement
-- reasons can include full operator comments and audit context without
-- truncation.
--
-- Idempotency guarantees (enforced by migration_000015_test.go Stage 4):
--   * ADD COLUMN IF NOT EXISTS → re-running is a no-op
--   * DROP CONSTRAINT IF EXISTS + ADD CONSTRAINT → always converges to
--     RESTRICT; safe to re-apply after a partial rollback
--   * CREATE INDEX IF NOT EXISTS → re-running is a no-op

-- Agents: soft-retirement surface.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS retired_reason TEXT;

-- Deployment targets: soft-retirement surface. Cascade-retire via the service
-- layer copies the agent's retired_at/retired_reason onto its targets so the
-- "who owned this deployment" trail stays intact after an agent is retired.
ALTER TABLE deployment_targets ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;
ALTER TABLE deployment_targets ADD COLUMN IF NOT EXISTS retired_reason TEXT;

-- Flip deployment_targets.agent_id FK from ON DELETE CASCADE (migration 000001
-- line 104) to ON DELETE RESTRICT. Auto-named constraint per Postgres default
-- (`<table>_<column>_fkey`). Drop-then-add so this migration is self-healing:
-- re-running always lands on RESTRICT regardless of prior state.
ALTER TABLE deployment_targets
  DROP CONSTRAINT IF EXISTS deployment_targets_agent_id_fkey;
ALTER TABLE deployment_targets
  ADD CONSTRAINT deployment_targets_agent_id_fkey
  FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE RESTRICT;

-- Supporting indexes for the retired-filter queries that replace the default
-- "active only" list paths in the agent repository (ListActive / ListRetired).
-- Partial indexes keep them cheap — only retired rows are indexed, which is a
-- tiny fraction of the table in a healthy fleet.
CREATE INDEX IF NOT EXISTS idx_agents_retired_at
  ON agents(retired_at) WHERE retired_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_deployment_targets_retired_at
  ON deployment_targets(retired_at) WHERE retired_at IS NOT NULL;

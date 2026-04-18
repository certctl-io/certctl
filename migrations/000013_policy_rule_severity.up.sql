-- Migration 000013: Per-Rule Severity on policy_rules
--
-- Prior to this migration, PolicyRule had no severity column. The TypeScript
-- frontend (PoliciesPage.tsx) sent a `severity` field on create/update, but
-- Go's json.Decoder silently dropped it (no matching struct field) and the
-- value never reached PostgreSQL. Reloading the page always showed severity
-- reverting to a default — the classic "silent drop" bug.
--
-- This migration adds severity as a first-class column on policy_rules.
-- Default `'Warning'` covers pre-existing rows; the CHECK constraint gives
-- defense-in-depth against casing drift (the application-layer validator in
-- internal/api/handler/validation.go already enforces the TitleCase allowlist,
-- but the DB should reject a bypassed write too).
--
-- No index: three-value column on a table that stays in the low thousands of
-- rows. The planner will seq-scan regardless; write cost without read benefit.
-- If measurements later justify it, add the index then.
--
-- PG 11+ makes ADD COLUMN with a literal DEFAULT a metadata-only operation
-- (no table rewrite), so this is safe to run on a live server.

ALTER TABLE policy_rules
    ADD COLUMN IF NOT EXISTS severity VARCHAR(50) NOT NULL DEFAULT 'Warning'
        CHECK (severity IN ('Warning', 'Error', 'Critical'));

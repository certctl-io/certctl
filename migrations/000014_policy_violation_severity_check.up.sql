-- Migration 000014: CHECK constraint on policy_violations.severity
--
-- ARCH-L3 (2026-05-13): this migration's `ALTER TABLE ... ADD CONSTRAINT
-- ... CHECK` statement does not carry the literal `IF NOT EXISTS`
-- token because Postgres' ALTER TABLE ADD CONSTRAINT syntax does not
-- accept it. Idempotency comes from the DROP CONSTRAINT IF EXISTS
-- preamble: re-running this migration on a tree with the constraint
-- already in place drops + re-adds, which is a no-op in observable
-- behavior.
--
-- Sibling to migration 000013, which added severity + CHECK to policy_rules.
-- policy_violations has carried a severity column since the initial schema
-- (000001, line 183) but without any CHECK. The engine used to hardcode
-- `Warning` on every violation regardless of the triggering rule's severity
-- (see pre-D-008 internal/service/policy.go:evaluateRule), so the column
-- value was uniform by accident of implementation, not by constraint.
--
-- D-008 rewrites evaluateRule to copy rule.Severity into the violation. The
-- engine now writes values drawn from the application-layer PolicySeverity
-- allowlist, but nothing at the DB level prevents a future caller — or a
-- bypassed write from a migration or psql session — from inserting casing
-- drift ('warning', 'ERROR', etc.) and re-opening the same class of bug
-- that D-005 and D-006 closed. This constraint is the defense-in-depth
-- complement to the handler validator.
--
-- Pre-existing seed_demo.sql rows use lowercase severity values. D-008
-- updates those in the same commit so this migration can apply cleanly
-- against both a fresh install and an upgraded install that has already
-- seeded the demo data.
--
-- Named constraint (policy_violations_severity_check) so the down migration
-- can DROP it by name without ambiguity; un-named CHECK constraints use
-- a synthesized PostgreSQL name that varies by environment.

-- Bundle C / Audit M-006 (CWE-913): idempotency guard. Drop-if-exists
-- before ADD so a re-run of this migration against a partially-applied
-- DB doesn't fail with "constraint already exists". Mirrors the down
-- migration's DROP CONSTRAINT IF EXISTS shape and the M-7 idempotent-
-- index idiom.
ALTER TABLE policy_violations
    DROP CONSTRAINT IF EXISTS policy_violations_severity_check;

ALTER TABLE policy_violations
    ADD CONSTRAINT policy_violations_severity_check
    CHECK (severity IN ('Warning', 'Error', 'Critical'));

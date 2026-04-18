-- Migration 000014: CHECK constraint on policy_violations.severity
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

ALTER TABLE policy_violations
    ADD CONSTRAINT policy_violations_severity_check
    CHECK (severity IN ('Warning', 'Error', 'Critical'));

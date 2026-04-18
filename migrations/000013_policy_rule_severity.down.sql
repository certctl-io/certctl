-- Rollback migration 000013: remove per-rule severity.
--
-- DROP COLUMN removes the column, its CHECK constraint, and the default in
-- one statement. Any downstream code still referencing severity after
-- rollback will fail at query time — that's intentional, since running this
-- rollback implies severity as a concept is being abandoned.

ALTER TABLE policy_rules DROP COLUMN IF EXISTS severity;

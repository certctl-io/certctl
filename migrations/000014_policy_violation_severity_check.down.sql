-- Rollback migration 000014: drop the policy_violations severity CHECK.
--
-- Drops the named CHECK constraint added by the up migration. The severity
-- column itself stays (it predates this migration — see 000001 line 183),
-- so any application code that reads/writes the column continues to work.
-- Only the DB-level enforcement of the TitleCase allowlist is removed.

ALTER TABLE policy_violations
    DROP CONSTRAINT IF EXISTS policy_violations_severity_check;

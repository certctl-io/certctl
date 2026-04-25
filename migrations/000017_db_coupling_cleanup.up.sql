-- Migration 000017: DB coupling cleanup (U-3 bundle).
--
-- Closes three audit findings that share the migrations/ surface and the
-- "schema vs Go vs label drifts in different directions" pattern:
--
--   * cat-o-retry_interval_unit_mismatch (P1):
--     renewal_policies.retry_interval_minutes column stored seconds, named
--     minutes. Operators running raw SQL got 60x confusion.
--
--   * cat-o-notification_created_at_dead_field (P2):
--     internal/domain/notification.go::NotificationEvent.CreatedAt was
--     tagged json:"created_at" with no DB column behind it. Every API
--     response serialized 0001-01-01T00:00:00Z. Visible zero-value
--     timestamp on every notification row in the dashboard.
--
--   * cat-o-health_check_column_orphans (P1):
--     migration 000011 added network_scan_targets.health_check_enabled +
--     .health_check_interval_seconds. No Go field decoded either column;
--     no handler exposed them; OpenAPI schema didn't carry them. The
--     auto-health-check feature was never wired through. Removing dead
--     schema is cheaper than completing dead code; if the feature gets
--     revived, a future migration can re-add the columns alongside the
--     Go-side wiring.
--
-- Idempotency: RunMigrations at internal/repository/postgres/db.go has
-- no applied-tracking table — every server restart re-applies every
-- migration in sequence. Each block in this file MUST be safe to re-run
-- on a database that has already had it applied. The RENAME COLUMN in
-- block (1) is wrapped in a DO $$ guard that checks information_schema
-- before renaming; the ADD COLUMN in (2) and the DROP COLUMNs in (3)
-- use the standard IF NOT EXISTS / IF EXISTS clauses.
--
-- See the U-3 closure entry in
-- coverage-gap-audit-2026-04-24-v5/unified-audit.md and CHANGELOG.md
-- for the full rationale, the bundled-fix list, and the architectural
-- shift to runtime-only migration application.

-- (1) cat-o-retry_interval_unit_mismatch — rename column to match unit.
--
-- The values stored in this column have always been seconds (validator
-- at internal/service/renewal_policy.go enforces a [60, 86400] range
-- inclusive — 60 seconds to 24 hours, unambiguously seconds). The
-- column name was the bug; data conversion is a no-op. The Go field
-- has always been tagged json:"retry_interval_seconds", so the API
-- shape is unchanged.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'renewal_policies'
          AND column_name = 'retry_interval_minutes'
    ) THEN
        ALTER TABLE renewal_policies
            RENAME COLUMN retry_interval_minutes TO retry_interval_seconds;
    END IF;
END $$;

-- (2) cat-o-notification_created_at_dead_field — add the missing column.
--
-- DEFAULT NOW() back-fills existing rows with the migration apply
-- timestamp. Acceptable trade-off: those rows had no real CreatedAt
-- info anyway (the field was a Go-only zero-value), and approximating
-- them with the migration time gives the dashboard a usable rendering
-- instead of '0001-01-01'. NOT NULL is enforced because the repo
-- INSERT path will set CreatedAt on every new row post-fix.
ALTER TABLE notification_events
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- (3) cat-o-health_check_column_orphans — drop unwired columns.
--
-- migrations/000011_health_checks.up.sql added these two columns with
-- the intent of wiring auto-health-checks for network-scan-discovered
-- endpoints. The Go side was never written; no handler reads or writes
-- them; the OpenAPI NetworkScanTarget schema doesn't expose them. The
-- columns have been carrying their default values (false / 300) on
-- every row since shipping. Dropping them removes dead schema; the
-- network_scan_targets row size shrinks marginally and operators stop
-- seeing flag/interval columns that don't actually do anything.
ALTER TABLE network_scan_targets
    DROP COLUMN IF EXISTS health_check_enabled,
    DROP COLUMN IF EXISTS health_check_interval_seconds;

-- Rank 4 of the 2026-05-03 Infisical deep-research deliverable
-- (cowork/infisical-deep-research-results.md Part 5). Adds the
-- per-policy channel matrix that the multi-channel expiry-alert
-- routing reads from. Two JSONB columns:
--
--   alert_channels      — map[severity_tier][]channel_name. Default
--                         is '{}' so the runtime falls through to
--                         domain.DefaultAlertChannels() (Email-only
--                         across all tiers, the back-compat
--                         behaviour).
--   alert_severity_map  — map[threshold_days]severity_tier. Default
--                         is '{}' so the runtime falls through to
--                         domain.DefaultAlertSeverityMap() (the
--                         canonical 30/14/7/0 → informational/warning/
--                         warning/critical mapping).
--
-- Both columns use IF NOT EXISTS so the migration is idempotent —
-- safe to re-run on every certctl-server boot per the
-- "Idempotent migrations" architecture decision in CLAUDE.md.

ALTER TABLE renewal_policies
    ADD COLUMN IF NOT EXISTS alert_channels JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS alert_severity_map JSONB NOT NULL DEFAULT '{}'::jsonb;

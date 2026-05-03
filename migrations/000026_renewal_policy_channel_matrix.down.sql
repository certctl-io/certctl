-- Down migration for 000026 — drop the per-policy channel-matrix
-- columns. IF EXISTS makes this safe to apply on a database that
-- was never upgraded (no-op).

ALTER TABLE renewal_policies
    DROP COLUMN IF EXISTS alert_channels,
    DROP COLUMN IF EXISTS alert_severity_map;

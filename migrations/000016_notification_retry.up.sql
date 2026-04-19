-- Migration 000016: Notification retry + dead-letter queue (I-005 coverage-gap fix).
--
-- Adds retry bookkeeping to notification_events so transient webhook / SMTP
-- failures no longer silently drop critical alerts, and introduces a terminal
-- "dead" status that an operator can triage from the UI.
--
-- Rationale (audit finding I-005):
--   Today `internal/service/notification.go:282-288` flips status to 'failed'
--   with a zero-valued sent_at and returns. `ProcessPendingNotifications`
--   (line 243) only lists rows whose status='pending', so a failed row is
--   orphaned: no retry, no backoff, no escalation, no dead-letter. The only
--   way an operator learns about the drop is by reading the server log.
--
--   The fix mirrors the I-001 job retry loop: a sibling scheduler loop sweeps
--   notification_events for rows whose (status='failed', next_retry_at <= now())
--   and, while retry_count < max_attempts, requeues them to 'pending'. Once
--   retry_count crosses max_attempts the row is promoted to 'dead' and a
--   Prometheus counter is bumped for alerting. The UI exposes a manual Requeue
--   button on dead rows for when the operator has resolved the underlying
--   notifier outage.
--
-- Column design mirrors migration 000015 (agent_retire) style:
--   * retry_count INTEGER NOT NULL DEFAULT 0 — explicit NOT NULL + default so
--     existing rows backfill cleanly and the service layer never needs to
--     nil-check the counter.
--   * next_retry_at TIMESTAMPTZ NULL — nullable because the field is only
--     meaningful while a row is in 'failed' state; 'sent', 'pending', 'dead'
--     and 'read' rows all leave it NULL. The partial index below is what makes
--     the retry sweep O(retry-eligible) rather than O(total).
--   * last_error TEXT NULL — preserves the most recent transient failure
--     string for operator triage. TEXT (not VARCHAR(N)) because notifier
--     errors can include full HTTP bodies, stack traces, or stringified
--     TLS handshake diagnostics without truncation risk.
--
-- Idempotency guarantees (enforced by notification repository integration tests):
--   * ADD COLUMN IF NOT EXISTS → re-running is a no-op
--   * CREATE INDEX IF NOT EXISTS → re-running is a no-op

-- Retry counter. DEFAULT 0 backfills every existing row at zero attempts.
ALTER TABLE notification_events ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;

-- Next-retry timestamp. Populated by the service layer on the failed→pending
-- transition using exponential backoff (2^retry_count minutes, capped at 1h).
ALTER TABLE notification_events ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;

-- Last transient error preserved for operator triage and dashboard display.
ALTER TABLE notification_events ADD COLUMN IF NOT EXISTS last_error TEXT;

-- Partial index for the retry-sweep hot path. Only rows in 'failed' state with
-- a scheduled next_retry_at participate in the index; everything else (sent,
-- pending, dead, read, and unscheduled failures) is excluded. Keeps the index
-- tiny in healthy fleets where transient failures are rare.
CREATE INDEX IF NOT EXISTS idx_notification_events_retry_sweep
  ON notification_events(next_retry_at)
  WHERE status = 'failed' AND next_retry_at IS NOT NULL;

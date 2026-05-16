# Privacy & retention (federated-user PII)

> Last reviewed: 2026-05-16

Sprint 6 COMP-002-RETENTION closure. certctl stores three categories
of personally-identifiable information for federated humans (Auth
Bundle 2 OIDC users):

| Column | Source | Used by |
|---|---|---|
| `users.email` | IdP claim (`email`) | Operator GUI "find user by email", display in lists, audit attribution. |
| `users.display_name` | IdP claim (`name`) | UI display string for the human. |
| `users.oidc_subject` | IdP claim (`sub`) | Stable identifier — joined with `oidc_provider_id` in the (provider, subject) UNIQUE constraint. |

Pre-fix, deactivating a user (admin-side `auth.user.deactivate`)
soft-deleted the row by setting `deactivated_at` but left the PII
columns populated indefinitely. The Sprint 6 fix adds an automatic
purge pipeline.

## Retention pipeline shape

```
Day 0   admin → POST /api/v1/auth/users/u-X/deactivate
                ├─ users.deactivated_at = NOW()
                └─ all active sessions for u-X revoked

Day N   scheduler's userRetentionLoop tick (default cadence 24h)
        └─ UserRetentionService.PurgeDeactivatedUsers
           ├─ SELECT users WHERE deactivated_at < NOW() - retention_window
           ├─ For each row (batch-capped per tick):
           │     UserRetentionService.DeleteUserPII(u.id)
           │     ├─ revoke all active sessions (defense-in-depth)
           │     ├─ email        := "purged@redacted.local"
           │     ├─ display_name := "[purged]"
           │     ├─ oidc_subject := "sha256:" || hex(sha256(original))
           │     └─ audit_events row (action=user.purge_pii, category=auth)
```

`users.id` is **preserved**. Historical `audit_events.actor = u-X`
rows still resolve to the row (now scrubbed). This is the
forensic-attribution guarantee — the operator can prove "user u-X
performed action Y on date Z" even after the PII is gone.

`oidc_subject` is **hashed**, not nullified, for two reasons:

1. The `(oidc_provider_id, oidc_subject)` UNIQUE constraint would
   trip if multiple purged users converged on the same NULL.
2. Re-login under the same IdP subject creates a fresh row (different
   `u-` id) because `GetByOIDCSubject` won't match the hashed token —
   the original subject is unrecoverable from the hash. This is the
   "right-to-be-forgotten" behavior: the same human logging back in
   is functionally a new account.

## Operator configuration

| Env var | Default | Notes |
|---|---|---|
| `CERTCTL_USER_RETENTION_INTERVAL` | `24h` | Tick cadence for the scheduler's userRetentionLoop. Zero or negative ignored. |
| `CERTCTL_USER_RETENTION_WINDOW` | `30 * 24h` (30 days) | How long after `deactivated_at` a row's PII stays in the table. Operators with stricter GDPR/CCPA expectations may shorten. |
| `CERTCTL_USER_RETENTION_BATCH_CAP` | `200` | Per-tick row budget. Larger backlogs spread across multiple ticks. 0 = unbounded (test fixtures only). |

## How to verify retention is working

1. Deactivate a test user via the admin path:

   ```bash
   curl -X POST -H "X-API-Key: $ADMIN_KEY" \
     https://certctl.example.com/api/v1/auth/users/u-test/deactivate
   ```

2. Confirm the row's `deactivated_at` is set:

   ```sql
   SELECT id, email, deactivated_at FROM users WHERE id = 'u-test';
   ```

3. Backdate `deactivated_at` to past the retention window (only for
   testing — never in production):

   ```sql
   UPDATE users SET deactivated_at = NOW() - INTERVAL '60 days'
   WHERE id = 'u-test';
   ```

   (Note: this UPDATE will succeed because `users` doesn't have a
   WORM trigger; the audit-events WORM trigger is unrelated.)

4. Wait for the next `userRetentionLoop` tick (or restart the server
   to force an immediate sweep). Confirm scrub:

   ```sql
   SELECT id, email, display_name, oidc_subject
     FROM users
    WHERE id = 'u-test';
   ```

   Expected: `email = 'purged@redacted.local'`,
   `display_name = '[purged]'`,
   `oidc_subject LIKE 'sha256:%'`.

5. Confirm an audit row was emitted:

   ```sql
   SELECT id, actor, action, resource_id, timestamp
     FROM audit_events
    WHERE action = 'user.purge_pii' AND resource_id = 'u-test'
    ORDER BY timestamp DESC LIMIT 1;
   ```

## What's NOT covered (deferred work)

The Sprint 6 fix is Phase 1 of the audit's COMP-002-RETENTION
recommendation. Two further pieces are forward-looking:

- **GDPR data-subject access request (DSAR) export.** A "show me
  everything you know about me" endpoint is not yet implemented.
  Operators on EU-resident data should treat this as a manual SQL
  procedure today; track for Phase 2.
- **Cascade purge of related rows.** Sessions are revoked (above);
  api_keys with `created_by = u-X` are NOT yet purged on scrub. The
  api_keys table doesn't have a foreign key to users (it indexes by
  `actor_id` strings, free-form), so the cascade is a service-layer
  concern that needs explicit wiring. Track for Phase 2.
- **Per-event PII redaction in `audit_events.details`.** The existing
  `RedactDetailsForAudit` (`internal/service/audit_redact.go`) scrubs
  credential + PII keys at write time. A future feature for
  "retroactively re-redact existing rows" would interact with the WORM
  trigger; out of scope today.

## See also

- `internal/service/user_retention.go` — `UserRetentionService` source.
- `internal/scheduler/scheduler.go::userRetentionLoop` — scheduler loop.
- `migrations/000036_users.up.sql` — `users` table definition.
- `migrations/000045_users_deactivated_at.up.sql` — `deactivated_at` column.
- `docs/operator/audit-chain.md` — paired Sprint 6 tamper-evidence work.

# Issuance approval workflow

> Last reviewed: 2026-05-05

certctl can gate certificate issuance + renewal on a per-profile, two-person-integrity check. Compliance customers (PCI-DSS Level 1, FedRAMP Moderate / High, SOC 2 Type II, HIPAA) configure this on production-tier `CertificateProfile` rows so every renewal-loop tick or manual `POST /api/v1/certificates/{id}/renew` blocks at `JobStatusAwaitingApproval` until a different actor approves.

Closes the procurement-checklist question "How do you enforce two-person integrity on cert issuance?" — without this surface the answer is "we don't"; with `requires_approval=true` on the profile, the answer is "here's the RBAC contract + here's the audit query that proves bypass mode is off in production."

## End-to-end flow

```mermaid
sequenceDiagram
    autonumber
    participant A as Operator A<br/>(or scheduler)
    participant SVC as CertificateService<br/>.TriggerRenewal
    participant JOB as Job + ApprovalRequest
    participant B as Operator B
    participant APR as ApprovalService.Approve
    participant SCH as Scheduler

    A->>SVC: POST /api/v1/certificates/{id}/renew<br/>(or renewal-loop tick)
    SVC->>JOB: read profile.RequiresApproval;<br/>create Job @ JobStatusAwaitingApproval;<br/>create ApprovalRequest<br/>(state=pending, requested_by=Operator A)
    Note over JOB,SCH: Scheduler skips —<br/>AwaitingApproval is NOT a dispatchable status
    B->>JOB: GET /api/v1/approvals?state=pending
    B->>APR: POST /api/v1/approvals/{id}/approve<br/>(decided_by=Operator B, note=...)
    APR->>APR: RBAC: reject if Operator B == Operator A<br/>→ ErrApproveBySameActor (HTTP 403)
    APR->>JOB: ApprovalRequest → state=approved;<br/>Job AwaitingApproval → Pending;<br/>audit row (action=approval_approved,<br/>actor=Operator B);<br/>certctl_approval_decisions_total<br/>{outcome=approved,profile_id=...}++
    SCH->>JOB: pick up Pending → dispatch to issuer connector
    JOB-->>A: cert issues normally
```

## Configuration

Set `requires_approval=true` on a `CertificateProfile`:

```bash
curl -X PUT https://certctl/api/v1/profiles/p-prod-cdn \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "Production CDN",
        "requires_approval": true,
        ...
      }'
```

Every certificate bound to that profile is now gated. The default is `requires_approval=false` — existing profiles keep the historical unattended renewal path.

## RBAC: the two-person integrity rule

The actor that triggers a renewal **cannot** be the actor that approves it. The check happens at the service layer and surfaces as **HTTP 403** at the handler. The error message contains the substring `two-person integrity` so server-log greps detect attempted self-approvals.

This is the load-bearing compliance contract. Pinned by:

- `internal/service/approval_test.go::TestApproval_Approve_RejectsSameActor` — service-level pin.
- `internal/api/handler/approval_test.go::TestApproval_HandlerApproveAsSameActor_Returns403` — handler-level pin (HTTP 403 + body contains "two-person integrity").

## Operator playbook: "I need to approve a renewal"

```bash
# 1. Find the pending request
curl -s "https://certctl/api/v1/approvals?state=pending" \
     -H "Authorization: Bearer $API_KEY" | jq

# 2. Inspect the request — confirm CN, SANs, requester
curl -s "https://certctl/api/v1/approvals/ar-abc123" \
     -H "Authorization: Bearer $API_KEY" | jq

# 3. Approve as a different actor than the requester
curl -X POST "https://certctl/api/v1/approvals/ar-abc123/approve" \
     -H "Authorization: Bearer $APPROVER_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"note":"approved per ticket SECOPS-12345"}'

# 4. Confirm the job transitioned to Pending
curl -s "https://certctl/api/v1/jobs?certificate_id=mc-foo" \
     -H "Authorization: Bearer $API_KEY" | jq '.[] | {id,status,type}'
```

To **reject** instead, swap the path: `POST /api/v1/approvals/{id}/reject` with the same body shape. The job transitions to `Cancelled` and the `note` is recorded in the audit row.

## Operator playbook: "approval timed out"

The scheduler reaper transitions stale pending requests + their linked jobs after `CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT` (default `168h` = 7 days):

- `ApprovalRequest.state` → `expired`
- `Job.Status` → `Cancelled` (with `error_message="approval expired"`)
- One audit row per expiry (`action=approval_expired, actor=system-reaper, actorType=System`)
- `certctl_approval_decisions_total{outcome="expired",profile_id="..."}` increments

Resolve by re-triggering the renewal once the underlying delay is sorted:

```bash
curl -X POST "https://certctl/api/v1/certificates/mc-foo/renew" \
     -H "Authorization: Bearer $API_KEY"
```

Tighten the timeout for short-window deployments via the env var, e.g. `CERTCTL_JOB_AWAITING_APPROVAL_TIMEOUT=24h`.

## Compliance control mapping

| Standard | Control | What this surface satisfies |
|---|---|---|
| PCI-DSS 4.0 | **§6.4.5** (Separation of duties for production change-management) | Same-actor RBAC pin; audit row carries both `requested_by` and `decided_by` so reviewers see two distinct identities per change. |
| NIST SP 800-53 | **SA-15** (Development process; two-person review for security-relevant changes) | Service-layer `ErrApproveBySameActor` + `TestApproval_Approve_RejectsSameActor` pin the contract. Bypass-mode emits a typed audit row (`action=approval_bypassed`) so compliance reviewers detect dev-mode misuse via `SELECT count(*) FROM audit_events WHERE actor='system-bypass'` returning > 0. |
| SOC 2 Type II | **CC6.1** (Logical access — restrict, monitor, terminate) | Per-decision audit row + `certctl_approval_decisions_total{outcome,profile_id}` Prometheus counter. Operators alert on sustained `outcome="rejected"` or `outcome="expired"` bursts. |
| HIPAA | **§164.308(a)(4)** (Information access management) | Same surface — the per-policy gating + audit trail is the access-management control. |

## Bypass mode (dev / CI ONLY)

Setting `CERTCTL_APPROVAL_BYPASS=true` short-circuits the workflow: every `RequestApproval` call auto-approves with `decided_by=system-bypass` and `actorType=System`. Used by dev / CI to keep renewal-scheduler tests fast without standing up an approver.

**Production deploys MUST leave this unset.** The bypass emits a typed audit event (`action=approval_bypassed`) so compliance auditors detect misuse via:

```sql
SELECT count(*) FROM audit_events WHERE actor = 'system-bypass';
```

returning **zero rows in production** and a high count in dev. The certctl-server logs a `WARN` line at boot when bypass is enabled — operators alert on that log line in production environments.

## Prometheus metrics

```
certctl_approval_decisions_total{outcome,profile_id}        counter
certctl_approval_pending_age_seconds                        histogram
                                  (le buckets:
                                    60, 300, 1800, 3600,
                                    21600, 86400, +Inf)
```

`outcome` is one of `approved`, `rejected`, `expired`, `bypassed`. `profile_id` is the `CertificateProfile.ID` that triggered the gate (cardinality-bounded — operators have <100 profiles in production).

The pending-age histogram observes seconds-since-creation at the moment of decision. Alert when p99 hits hours/days — compliance customers usually have a same-day decision deadline.

## Future free V2 work

- **M-of-N approver chains.** Today's primitive is single-approver. Future V2 work adds chains — e.g., "needs 2 of 3 platform-team members."
- **Time-windowed auto-approve.** Today's reaper hard-cancels at the static deadline. Policy-driven time-windowed auto-approve (T+30m unattended → cancel; T+24h business hours → escalate) is future work.
- **External ticketing integration.** ServiceNow / JIRA bridging so approval state mirrors the change-management record.
- **Per-owner / per-team routing.** Today's pool is global. Per-owner / per-team routing matches cert ownership to approver pools.
- **Approval delegation.** Today the same-actor rule is strict. Time-bounded delegation is future work.

Tracked in `WORKSPACE-ROADMAP.md` under the Future Free V2 Work section — every item ships free under BSL.

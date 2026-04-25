// StatusBadge — single source of truth for the certctl dashboard's
// per-status color mapping. Keys are the EXACT wire values Go emits
// (case-sensitive). Update this file when a new status value lands on
// the Go side; StatusBadge.test.tsx walks every value and will go red
// before users see a default-grey "what is happening?" badge.
//
// D-1 master closure (cat-d-359e92c20cbf, cat-d-9f4c8e4a91f1,
// cat-d-1447e04732e7, cat-f-cert_detail_page_key_render_fallback,
// cat-f-ae0d06b6588f) fixed the pre-master drift:
//   - Agent: 'Stale' (never emitted) → 'Degraded' (real value);
//     `internal/domain/connector.go::AgentStatusDegraded = "Degraded"`.
//   - Notification: added 'dead' (was falling through to neutral);
//     `internal/domain/notification.go::NotificationStatusDead = "dead"`.
//   - Certificate: dropped dead 'PendingIssuance' key — the real
//     `CertificateStatusPending = "Pending"` is mapped under Job
//     statuses below.
//
// Source-of-truth references (re-verify if the Go enum changes):
//   - internal/domain/connector.go::AgentStatus*
//   - internal/domain/certificate.go::CertificateStatus*
//   - internal/domain/job.go::JobStatus*
//   - internal/domain/notification.go::NotificationStatus*
//   - internal/domain/discovery.go::DiscoveryStatus*
//   - internal/domain/health_check.go::HealthStatus*
//
// Issuer 'Enabled'/'Disabled' are frontend-synthesized labels (mapped
// from the `enabled bool` field on the Issuer struct), not Go-emitted
// enum values, but they're surfaced via StatusBadge for consistency.
const statusStyles: Record<string, string> = {
  // Certificate statuses (internal/domain/certificate.go::CertificateStatus*)
  Active:              'badge-success',
  Expiring:            'badge-warning',
  Expired:             'badge-danger',
  RenewalInProgress:   'badge-info',
  Archived:            'badge-neutral',
  Revoked:             'badge-danger',
  // Job statuses (internal/domain/job.go::JobStatus*) — note: 'Pending' is
  // shared between CertificateStatusPending and JobStatusPending.
  Pending:             'badge-info',
  AwaitingCSR:         'badge-info',
  AwaitingApproval:    'badge-info',
  Running:             'badge-warning',
  Completed:           'badge-success',
  Failed:              'badge-danger',
  Cancelled:           'badge-neutral',
  // Agent statuses (internal/domain/connector.go::AgentStatus*) — D-1:
  // 'Degraded' replaces the never-emitted 'Stale' from pre-D-1 (the Go
  // domain has only Online / Offline / Degraded; mapping 'Stale' yellow
  // and letting 'Degraded' fall through to neutral hid degraded agents).
  Online:              'badge-success',
  Offline:             'badge-danger',
  Degraded:            'badge-warning',
  // Discovery statuses (internal/domain/discovery.go::DiscoveryStatus*)
  Unmanaged:           'badge-warning',
  Managed:             'badge-success',
  Dismissed:           'badge-neutral',
  // Issuer statuses (frontend-synthesized from Issuer.enabled bool)
  Enabled:             'badge-success',
  Disabled:            'badge-neutral',
  // Notification statuses (internal/domain/notification.go::NotificationStatus*)
  // — D-2: added 'dead' (retries exhausted, dead-letter queue). Pre-D-2 it
  // fell through to neutral, visually equating "needs operator attention"
  // with "operator already acknowledged" (read).
  sent:                'badge-success',
  pending:             'badge-warning',
  failed:              'badge-danger',
  dead:                'badge-danger',
  read:                'badge-neutral',
  // Health check statuses (internal/domain/health_check.go::HealthStatus*)
  healthy:             'badge-success',
  degraded:            'badge-warning',
  down:                'badge-danger',
  cert_mismatch:       'badge-warning',
  unknown:             'badge-neutral',
};

export default function StatusBadge({ status }: { status: string }) {
  const cls = statusStyles[status] || 'badge-neutral';
  return <span className={`badge ${cls}`}>{status}</span>;
}

const statusStyles: Record<string, string> = {
  // Certificate statuses
  Active:              'badge-success',
  Expiring:            'badge-warning',
  Expired:             'badge-danger',
  RenewalInProgress:   'badge-info',
  PendingIssuance:     'badge-info',
  Archived:            'badge-neutral',
  Revoked:             'badge-danger',
  // Job statuses
  Pending:             'badge-info',
  AwaitingCSR:         'badge-info',
  AwaitingApproval:    'badge-info',
  Running:             'badge-warning',
  Completed:           'badge-success',
  Failed:              'badge-danger',
  Cancelled:           'badge-neutral',
  // Agent statuses
  Online:              'badge-success',
  Offline:             'badge-danger',
  Stale:               'badge-warning',
  // Notification statuses
  sent:                'badge-success',
  pending:             'badge-warning',
  failed:              'badge-danger',
  read:                'badge-neutral',
};

export default function StatusBadge({ status }: { status: string }) {
  const cls = statusStyles[status] || 'badge-neutral';
  return <span className={`badge ${cls}`}>{status}</span>;
}

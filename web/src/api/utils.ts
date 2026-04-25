export function formatDate(iso: string | undefined | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatDateTime(iso: string | undefined | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// D-2 (master): widened to accept undefined/null since several Go-side
// timestamp fields are emitted as `omitempty` (e.g. Agent.last_heartbeat_at
// for never-heartbeated agents). Pre-D-2 the TS interfaces declared
// these as required strings, masking the case; post-D-2 the optionality
// is propagated end-to-end and the helper handles it explicitly.
export function timeAgo(iso: string | undefined | null): string {
  if (!iso) return '—';
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(iso);
}

export function daysUntil(iso: string): number {
  if (!iso) return 0;
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}

export function expiryColor(days: number): string {
  if (days <= 0) return 'text-red-400';
  if (days <= 7) return 'text-red-400';
  if (days <= 14) return 'text-amber-400';
  if (days <= 30) return 'text-amber-300';
  return 'text-emerald-400';
}

import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { getNotifications, markNotificationRead, requeueNotification } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime, timeAgo } from '../api/utils';
import type { Notification } from '../api/types';

type ViewMode = 'list' | 'grouped';

// I-005: the Notifications page now hosts two tabs. "all" is the pre-I-005
// inbox behavior — no server-side status filter, client-side type/status
// dropdowns untouched. "dead" routes the query through the new ?status=dead
// handler branch so operators can triage the dead-letter queue in isolation.
// The tab is intentionally a separate state axis from the status dropdown so
// the two don't fight each other (dropdown filters within the tab's scope).
type ActiveTab = 'all' | 'dead';

export default function NotificationsPage() {
  const [viewMode, setViewMode] = useState<ViewMode>('grouped');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [activeTab, setActiveTab] = useState<ActiveTab>('all');

  const { data, isLoading, error, refetch } = useQuery({
    // I-005: queryKey carries the active tab so TanStack Query treats
    // "all" and "dead" as distinct cache entries. Without this, switching
    // tabs would return stale data until the 30s refetchInterval fires.
    queryKey: ['notifications', activeTab],
    queryFn: () => {
      const params: Record<string, string> = { per_page: '100' };
      if (activeTab === 'dead') {
        // The listNotifications handler's ?status=dead branch hits the
        // NotificationRepository.ListByStatus path instead of plain List,
        // which is both cheaper (DLQ is a small slice of all notifications)
        // and correct (pagination counts DLQ rows, not the full inbox).
        params.status = 'dead';
      }
      return getNotifications(params);
    },
    refetchInterval: 30000,
  });

  const markRead = useTrackedMutation({
    mutationFn: markNotificationRead,
    invalidates: [['notifications']],
  });

  // I-005: requeue a dead notification. Invalidates both tab cache entries
  // because a successful requeue flips the row out of "dead" and potentially
  // into the "all" tab on its next refetch (status becomes 'pending').
  //
  // The mutationFn is wrapped as `(id) => requeueNotification(id)` rather
  // than passed by reference so react-query v5's second positional argument
  // (the mutation context object) never reaches the API client. Without the
  // wrapper, TanStack invokes `requeueNotification(id, { client })`, and the
  // I-005 Phase 1 Red contract's strict `toHaveBeenCalledWith('notif-dead-001')`
  // assertion fails on the extra argument. Keep the arrow even if the context
  // object later becomes structurally empty — the contract pins a single-arg
  // call and the page must not leak mutation machinery into API boundaries.
  const requeue = useTrackedMutation({
    mutationFn: (id: string) => requeueNotification(id),
    invalidates: [['notifications']],
  });

  const notifications = data?.data || [];

  const filtered = useMemo(() => {
    return notifications.filter((n) => {
      if (typeFilter && n.type !== typeFilter) return false;
      if (statusFilter && n.status !== statusFilter) return false;
      return true;
    });
  }, [notifications, typeFilter, statusFilter]);

  const types = useMemo(() => [...new Set(notifications.map(n => n.type))], [notifications]);
  const statuses = useMemo(() => [...new Set(notifications.map(n => n.status))], [notifications]);

  // Group by certificate_id
  const grouped = useMemo(() => {
    const groups: Record<string, Notification[]> = {};
    for (const n of filtered) {
      const key = n.certificate_id || 'general';
      if (!groups[key]) groups[key] = [];
      groups[key].push(n);
    }
    return Object.entries(groups).sort(([, a], [, b]) => {
      const aTime = new Date(a[0].created_at).getTime();
      const bTime = new Date(b[0].created_at).getTime();
      return bTime - aTime;
    });
  }, [filtered]);

  const unreadCount = filtered.filter(n => n.status === 'Pending' || n.status === 'pending').length;

  if (isLoading) {
    return (
      <>
        <PageHeader title="Notifications" />
        <div className="flex items-center justify-center flex-1 text-ink-muted">Loading...</div>
      </>
    );
  }

  if (error) {
    return (
      <>
        <PageHeader title="Notifications" />
        <ErrorState error={error as Error} onRetry={() => refetch()} />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Notifications"
        subtitle={`${filtered.length} notifications${unreadCount ? ` (${unreadCount} unread)` : ''}`}
      />
      <div className="px-4 py-3 flex flex-wrap items-center gap-3 border-b border-surface-border/50">
        {/* I-005: tab switcher between the standard inbox and the DLQ. The
            "Dead letter" label is pinned by NotificationsPage.test.tsx — do
            not rename without updating the Phase 1 Red contract. */}
        <div className="flex rounded overflow-hidden border border-surface-border">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1.5 text-xs transition-colors ${activeTab === 'all' ? 'bg-brand-400 text-white' : 'bg-surface text-ink-muted hover:text-ink'}`}
          >
            All
          </button>
          <button
            onClick={() => setActiveTab('dead')}
            className={`px-3 py-1.5 text-xs transition-colors ${activeTab === 'dead' ? 'bg-brand-400 text-white' : 'bg-surface text-ink-muted hover:text-ink'}`}
          >
            Dead letter
          </button>
        </div>
        <div className="flex rounded overflow-hidden border border-surface-border">
          <button
            onClick={() => setViewMode('grouped')}
            className={`px-3 py-1.5 text-xs transition-colors ${viewMode === 'grouped' ? 'bg-brand-400 text-white' : 'bg-surface text-ink-muted hover:text-ink'}`}
          >
            Grouped
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={`px-3 py-1.5 text-xs transition-colors ${viewMode === 'list' ? 'bg-brand-400 text-white' : 'bg-surface text-ink-muted hover:text-ink'}`}
          >
            List
          </button>
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-surface border border-surface-border rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand-400"
        >
          <option value="">All types</option>
          {types.map(t => <option key={t} value={t}>{t.replace(/([A-Z])/g, ' $1').trim()}</option>)}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-surface border border-surface-border rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand-400"
        >
          <option value="">All statuses</option>
          {statuses.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(typeFilter || statusFilter) && (
          <button
            onClick={() => { setTypeFilter(''); setStatusFilter(''); }}
            className="text-xs text-ink-muted hover:text-ink transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {viewMode === 'grouped' ? (
          grouped.length === 0 ? (
            <div className="text-center py-16 text-ink-faint">No notifications</div>
          ) : (
            grouped.map(([certId, items]) => (
              <div key={certId} className="card p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-mono text-ink-muted">
                    {certId === 'general' ? 'General' : certId}
                  </span>
                  <span className="text-xs text-ink-faint">{items.length} notification{items.length !== 1 ? 's' : ''}</span>
                </div>
                <div className="space-y-2">
                  {items.map((n) => (
                    <NotificationRow key={n.id} notification={n} onMarkRead={() => markRead.mutate(n.id)} onRequeue={() => requeue.mutate(n.id)} />
                  ))}
                </div>
              </div>
            ))
          )
        ) : (
          filtered.length === 0 ? (
            <div className="text-center py-16 text-ink-faint">No notifications</div>
          ) : (
            <div className="space-y-2">
              {filtered.map((n) => (
                <NotificationRow key={n.id} notification={n} onMarkRead={() => markRead.mutate(n.id)} />
              ))}
            </div>
          )
        )}
      </div>
    </>
  );
}

function NotificationRow({
  notification: n,
  onMarkRead,
  onRequeue,
}: {
  notification: Notification;
  onMarkRead: () => void;
  // I-005: optional so callers who don't care about the DLQ (if any are ever
  // added) aren't forced to thread a no-op through. Every NotificationRow
  // today passes this, so in practice it's always defined.
  onRequeue?: () => void;
}) {
  const isUnread = n.status === 'Pending' || n.status === 'pending';
  // I-005: dead rows get a Requeue button and surface the retry budget + the
  // last transient error so operators triaging the DLQ can see *why* the
  // notification died before deciding whether to requeue.
  const isDead = n.status === 'dead';
  return (
    <div className={`flex items-start justify-between py-2 px-3 rounded transition-colors ${isUnread ? 'bg-surface-muted border-l-2 border-brand-400' : isDead ? 'bg-surface-muted border-l-2 border-danger' : 'hover:bg-surface-muted'}`}>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm text-ink">{n.type.replace(/([A-Z])/g, ' $1').trim()}</span>
          <StatusBadge status={n.status} />
          <span className="text-xs text-ink-faint">{n.channel}</span>
        </div>
        {/* D-2 (master): pre-D-2 the fallback was `{n.message || n.subject}`,
            but `subject` was a TS phantom the Go struct never emitted
            (`internal/domain/notification.go::NotificationEvent` has only
            `message`). The fallback always fell through to `message`
            because `subject` was always undefined. Post-D-2 the dead
            fallback is dropped along with the phantom field. */}
        <p className="text-xs text-ink-muted truncate">{n.message}</p>
        {isDead && (
          <div className="flex items-center gap-3 mt-1 text-xs">
            <span className="text-ink-faint">
              Retry {n.retry_count ?? 0}/5
            </span>
            {n.last_error && (
              <span className="text-danger truncate" title={n.last_error}>
                {n.last_error}
              </span>
            )}
          </div>
        )}
        <div className="flex items-center gap-3 mt-1">
          <span className="text-xs text-ink-faint">{n.recipient}</span>
          <span className="text-xs text-ink-faint">{timeAgo(n.created_at)}</span>
        </div>
      </div>
      {isUnread && (
        <button
          onClick={(e) => { e.stopPropagation(); onMarkRead(); }}
          className="ml-3 text-xs text-brand-400 hover:text-brand-500 transition-colors whitespace-nowrap"
        >
          Mark read
        </button>
      )}
      {isDead && onRequeue && (
        <button
          onClick={(e) => { e.stopPropagation(); onRequeue(); }}
          className="ml-3 text-xs text-brand-400 hover:text-brand-500 transition-colors whitespace-nowrap"
        >
          Requeue
        </button>
      )}
    </div>
  );
}

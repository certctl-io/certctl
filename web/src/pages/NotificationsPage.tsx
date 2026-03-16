import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getNotifications, markNotificationRead } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime, timeAgo } from '../api/utils';
import type { Notification } from '../api/types';

type ViewMode = 'list' | 'grouped';

export default function NotificationsPage() {
  const [viewMode, setViewMode] = useState<ViewMode>('grouped');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const queryClient = useQueryClient();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['notifications'],
    queryFn: () => getNotifications({ per_page: '100' }),
    refetchInterval: 30000,
  });

  const markRead = useMutation({
    mutationFn: markNotificationRead,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['notifications'] }),
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
        <div className="flex items-center justify-center flex-1 text-slate-400">Loading...</div>
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
      <div className="px-4 py-3 flex flex-wrap items-center gap-3 border-b border-slate-700/50">
        <div className="flex rounded overflow-hidden border border-slate-600">
          <button
            onClick={() => setViewMode('grouped')}
            className={`px-3 py-1.5 text-xs transition-colors ${viewMode === 'grouped' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'}`}
          >
            Grouped
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={`px-3 py-1.5 text-xs transition-colors ${viewMode === 'list' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'}`}
          >
            List
          </button>
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">All types</option>
          {types.map(t => <option key={t} value={t}>{t.replace(/([A-Z])/g, ' $1').trim()}</option>)}
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">All statuses</option>
          {statuses.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {(typeFilter || statusFilter) && (
          <button
            onClick={() => { setTypeFilter(''); setStatusFilter(''); }}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {viewMode === 'grouped' ? (
          grouped.length === 0 ? (
            <div className="text-center py-16 text-slate-500">No notifications</div>
          ) : (
            grouped.map(([certId, items]) => (
              <div key={certId} className="card p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-mono text-slate-400">
                    {certId === 'general' ? 'General' : certId}
                  </span>
                  <span className="text-xs text-slate-500">{items.length} notification{items.length !== 1 ? 's' : ''}</span>
                </div>
                <div className="space-y-2">
                  {items.map((n) => (
                    <NotificationRow key={n.id} notification={n} onMarkRead={() => markRead.mutate(n.id)} />
                  ))}
                </div>
              </div>
            ))
          )
        ) : (
          filtered.length === 0 ? (
            <div className="text-center py-16 text-slate-500">No notifications</div>
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

function NotificationRow({ notification: n, onMarkRead }: { notification: Notification; onMarkRead: () => void }) {
  const isUnread = n.status === 'Pending' || n.status === 'pending';
  return (
    <div className={`flex items-start justify-between py-2 px-3 rounded-lg transition-colors ${isUnread ? 'bg-slate-700/30 border-l-2 border-blue-500' : 'hover:bg-slate-700/20'}`}>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm text-slate-200">{n.type.replace(/([A-Z])/g, ' $1').trim()}</span>
          <StatusBadge status={n.status} />
          <span className="text-xs text-slate-500">{n.channel}</span>
        </div>
        <p className="text-xs text-slate-400 truncate">{n.message || n.subject}</p>
        <div className="flex items-center gap-3 mt-1">
          <span className="text-xs text-slate-500">{n.recipient}</span>
          <span className="text-xs text-slate-600">{timeAgo(n.created_at)}</span>
        </div>
      </div>
      {isUnread && (
        <button
          onClick={(e) => { e.stopPropagation(); onMarkRead(); }}
          className="ml-3 text-xs text-blue-400 hover:text-blue-300 transition-colors whitespace-nowrap"
        >
          Mark read
        </button>
      )}
    </div>
  );
}

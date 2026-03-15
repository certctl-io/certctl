import { useQuery } from '@tanstack/react-query';
import { getNotifications } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Notification } from '../api/types';

export default function NotificationsPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['notifications'],
    queryFn: () => getNotifications(),
    refetchInterval: 30000,
  });

  const columns: Column<Notification>[] = [
    {
      key: 'type',
      label: 'Type',
      render: (n) => <span className="text-sm text-slate-200">{n.type.replace(/([A-Z])/g, ' $1').trim()}</span>,
    },
    { key: 'status', label: 'Status', render: (n) => <StatusBadge status={n.status} /> },
    { key: 'channel', label: 'Channel', render: (n) => <span className="text-xs text-slate-400">{n.channel}</span> },
    { key: 'recipient', label: 'Recipient', render: (n) => <span className="text-xs text-slate-300">{n.recipient}</span> },
    {
      key: 'message',
      label: 'Message',
      render: (n) => <span className="text-xs text-slate-400 truncate max-w-xs block">{n.message || n.subject}</span>,
    },
    { key: 'cert', label: 'Certificate', render: (n) => <span className="text-xs text-slate-500 font-mono">{n.certificate_id || '—'}</span> },
    { key: 'created', label: 'Sent', render: (n) => <span className="text-xs text-slate-400">{formatDateTime(n.created_at)}</span> },
  ];

  return (
    <>
      <PageHeader title="Notifications" subtitle={data ? `${data.total} notifications` : undefined} />
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={data?.data || []} isLoading={isLoading} emptyMessage="No notifications" />
        )}
      </div>
    </>
  );
}

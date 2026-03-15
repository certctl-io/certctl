import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getAuditEvents } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { AuditEvent } from '../api/types';

const actionColors: Record<string, string> = {
  certificate_created: 'text-emerald-400',
  renewal_triggered: 'text-blue-400',
  renewal_job_created: 'text-blue-400',
  renewal_completed: 'text-emerald-400',
  deployment_completed: 'text-emerald-400',
  deployment_failed: 'text-red-400',
  expiration_alert_sent: 'text-amber-400',
  agent_registered: 'text-blue-400',
  policy_violated: 'text-red-400',
};

const RESOURCE_TYPES = ['', 'certificate', 'agent', 'job', 'notification', 'policy', 'target', 'issuer'];
const TIME_RANGES = [
  { label: 'All time', value: '' },
  { label: 'Last hour', value: '1h' },
  { label: 'Last 24h', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'Last 30 days', value: '30d' },
];

export default function AuditPage() {
  const [resourceType, setResourceType] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [timeRange, setTimeRange] = useState('');

  const params: Record<string, string> = {};
  if (resourceType) params.resource_type = resourceType;
  if (actorFilter) params.actor = actorFilter;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['audit', params],
    queryFn: () => getAuditEvents(params),
    refetchInterval: 30000,
  });

  // Client-side time range filtering (server may not support time params)
  const filtered = (data?.data || []).filter((e) => {
    if (!timeRange) return true;
    const ts = new Date(e.timestamp).getTime();
    const now = Date.now();
    const hours = timeRange === '1h' ? 1 : timeRange === '24h' ? 24 : timeRange === '7d' ? 168 : 720;
    return now - ts < hours * 3600 * 1000;
  });

  const columns: Column<AuditEvent>[] = [
    {
      key: 'action',
      label: 'Action',
      render: (e) => (
        <span className={`text-sm font-medium ${actionColors[e.action] || 'text-slate-300'}`}>
          {e.action.replace(/_/g, ' ')}
        </span>
      ),
    },
    {
      key: 'actor',
      label: 'Actor',
      render: (e) => (
        <div>
          <div className="text-sm text-slate-200">{e.actor}</div>
          <div className="text-xs text-slate-500">{e.actor_type}</div>
        </div>
      ),
    },
    {
      key: 'resource',
      label: 'Resource',
      render: (e) => (
        <div>
          <div className="text-sm text-slate-300">{e.resource_type}</div>
          <div className="text-xs text-slate-500 font-mono">{e.resource_id}</div>
        </div>
      ),
    },
    {
      key: 'details',
      label: 'Details',
      render: (e) => {
        if (!e.details || Object.keys(e.details).length === 0) return <span className="text-slate-500">&mdash;</span>;
        return (
          <span className="text-xs text-slate-400 font-mono truncate max-w-xs block">
            {JSON.stringify(e.details).slice(0, 60)}
          </span>
        );
      },
    },
    { key: 'time', label: 'Time', render: (e) => <span className="text-xs text-slate-400">{formatDateTime(e.timestamp)}</span> },
  ];

  return (
    <>
      <PageHeader title="Audit Trail" subtitle={data ? `${filtered.length} events` : undefined} />
      <div className="px-4 py-3 flex flex-wrap gap-3 border-b border-slate-700/50">
        <select
          value={resourceType}
          onChange={(e) => setResourceType(e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">All resources</option>
          {RESOURCE_TYPES.filter(Boolean).map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Filter by actor..."
          value={actorFilter}
          onChange={(e) => setActorFilter(e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-xs text-slate-300 placeholder-slate-500 focus:outline-none focus:border-blue-500 w-40"
        />
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className="bg-slate-800 border border-slate-600 rounded px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
        >
          {TIME_RANGES.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        {(resourceType || actorFilter || timeRange) && (
          <button
            onClick={() => { setResourceType(''); setActorFilter(''); setTimeRange(''); }}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable columns={columns} data={filtered} isLoading={isLoading} emptyMessage="No audit events" />
        )}
      </div>
    </>
  );
}

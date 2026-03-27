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
  certificate_created: 'text-emerald-600',
  renewal_triggered: 'text-brand-500',
  renewal_job_created: 'text-brand-500',
  renewal_completed: 'text-emerald-600',
  deployment_completed: 'text-emerald-600',
  deployment_failed: 'text-red-600',
  expiration_alert_sent: 'text-amber-600',
  agent_registered: 'text-brand-500',
  policy_violated: 'text-red-600',
  certificate_revoked: 'text-red-600',
};

const RESOURCE_TYPES = ['', 'certificate', 'agent', 'job', 'notification', 'policy', 'target', 'issuer'];
const TIME_RANGES = [
  { label: 'All time', value: '' },
  { label: 'Last hour', value: '1h' },
  { label: 'Last 24h', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'Last 30 days', value: '30d' },
];

function downloadFile(content: string, filename: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function exportCSV(events: AuditEvent[]) {
  const headers = ['ID', 'Action', 'Actor', 'Actor Type', 'Resource Type', 'Resource ID', 'Details', 'Timestamp'];
  const rows = events.map(e => [
    e.id,
    e.action,
    e.actor,
    e.actor_type,
    e.resource_type,
    e.resource_id,
    JSON.stringify(e.details || {}),
    e.timestamp,
  ]);
  const csv = [headers, ...rows].map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
  downloadFile(csv, `audit-trail-${new Date().toISOString().slice(0, 10)}.csv`, 'text/csv');
}

function exportJSON(events: AuditEvent[]) {
  const json = JSON.stringify(events, null, 2);
  downloadFile(json, `audit-trail-${new Date().toISOString().slice(0, 10)}.json`, 'application/json');
}

export default function AuditPage() {
  const [resourceType, setResourceType] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [timeRange, setTimeRange] = useState('');
  const [actionFilter, setActionFilter] = useState('');

  const params: Record<string, string> = {};
  if (resourceType) params.resource_type = resourceType;
  if (actorFilter) params.actor = actorFilter;
  if (actionFilter) params.action = actionFilter;

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
        <span className={`text-sm font-medium ${actionColors[e.action] || 'text-ink'}`}>
          {e.action.replace(/_/g, ' ')}
        </span>
      ),
    },
    {
      key: 'actor',
      label: 'Actor',
      render: (e) => (
        <div>
          <div className="text-sm text-ink">{e.actor}</div>
          <div className="text-xs text-ink-faint">{e.actor_type}</div>
        </div>
      ),
    },
    {
      key: 'resource',
      label: 'Resource',
      render: (e) => (
        <div>
          <div className="text-sm text-ink">{e.resource_type}</div>
          <div className="text-xs text-ink-faint font-mono">{e.resource_id}</div>
        </div>
      ),
    },
    {
      key: 'details',
      label: 'Details',
      render: (e) => {
        if (!e.details || Object.keys(e.details).length === 0) return <span className="text-ink-faint">&mdash;</span>;
        return (
          <span className="text-xs text-ink-muted font-mono truncate max-w-xs block">
            {JSON.stringify(e.details).slice(0, 60)}
          </span>
        );
      },
    },
    { key: 'time', label: 'Time', render: (e) => <span className="text-xs text-ink-muted">{formatDateTime(e.timestamp)}</span> },
  ];

  const hasFilters = resourceType || actorFilter || timeRange || actionFilter;

  return (
    <>
      <PageHeader
        title="Audit Trail"
        subtitle={data ? `${filtered.length} events` : undefined}
        action={
          filtered.length > 0 ? (
            <div className="flex gap-2">
              <button onClick={() => exportCSV(filtered)} className="btn btn-ghost text-xs border border-surface-border">
                Export CSV
              </button>
              <button onClick={() => exportJSON(filtered)} className="btn btn-ghost text-xs border border-surface-border">
                Export JSON
              </button>
            </div>
          ) : undefined
        }
      />
      <div className="px-4 py-3 flex flex-wrap gap-3 border-b border-surface-border/50">
        <select
          value={resourceType}
          onChange={(e) => setResourceType(e.target.value)}
          className="bg-surface border border-surface-border rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand-400"
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
          className="bg-surface border border-surface-border rounded px-3 py-1.5 text-xs text-ink placeholder-ink-faint focus:outline-none focus:border-brand-400 w-40"
        />
        <input
          type="text"
          placeholder="Filter by action..."
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="bg-surface border border-surface-border rounded px-3 py-1.5 text-xs text-ink placeholder-ink-faint focus:outline-none focus:border-brand-400 w-40"
        />
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
          className="bg-surface border border-surface-border rounded px-3 py-1.5 text-xs text-ink focus:outline-none focus:border-brand-400"
        >
          {TIME_RANGES.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        {hasFilters && (
          <button
            onClick={() => { setResourceType(''); setActorFilter(''); setTimeRange(''); setActionFilter(''); }}
            className="text-xs text-ink-muted hover:text-ink transition-colors"
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

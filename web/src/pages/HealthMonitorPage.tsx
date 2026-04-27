import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import {
  listHealthChecks,
  createHealthCheck,
  deleteHealthCheck,
  acknowledgeHealthCheck,
  getHealthCheckSummary,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import StatusBadge from '../components/StatusBadge';
import { formatDateTime } from '../api/utils';
import type { EndpointHealthCheck, HealthCheckSummary } from '../api/types';

function CreateHealthCheckModal({ onClose, onCreate }: {
  onClose: () => void;
  onCreate: (data: Partial<EndpointHealthCheck>) => void;
}) {
  const [endpoint, setEndpoint] = useState('');
  const [expectedFingerprint, setExpectedFingerprint] = useState('');
  const [checkInterval, setCheckInterval] = useState('300');
  const [degradedThreshold, setDegradedThreshold] = useState('2');
  const [downThreshold, setDownThreshold] = useState('5');

  const handleSubmit = () => {
    onCreate({
      endpoint,
      expected_fingerprint: expectedFingerprint,
      check_interval_seconds: parseInt(checkInterval, 10),
      degraded_threshold: parseInt(degradedThreshold, 10),
      down_threshold: parseInt(downThreshold, 10),
      enabled: true,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4" onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-surface-border">
          <h3 className="text-lg font-semibold text-ink">New Health Check</h3>
          <p className="text-sm text-ink-muted mt-1">Monitor a TLS endpoint for certificate health</p>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Endpoint <span className="text-red-500">*</span></label>
            <input
              type="text"
              value={endpoint}
              onChange={e => setEndpoint(e.target.value)}
              placeholder="e.g., example.com:443"
              className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Expected Fingerprint (SHA-256)</label>
            <input
              type="text"
              value={expectedFingerprint}
              onChange={e => setExpectedFingerprint(e.target.value)}
              placeholder="Optional: auto-populated from deployment"
              className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
            <p className="text-xs text-ink-faint mt-1">Leave empty to auto-detect from first successful probe</p>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Check Interval (s)</label>
              <input
                type="number"
                value={checkInterval}
                onChange={e => setCheckInterval(e.target.value)}
                min="60"
                className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Degraded Threshold</label>
              <input
                type="number"
                value={degradedThreshold}
                onChange={e => setDegradedThreshold(e.target.value)}
                min="1"
                className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Down Threshold</label>
              <input
                type="number"
                value={downThreshold}
                onChange={e => setDownThreshold(e.target.value)}
                min="1"
                className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
          </div>
        </div>
        <div className="px-6 py-3 border-t border-surface-border flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-sm text-ink-muted hover:text-ink rounded border border-surface-border">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={!endpoint.trim()}
            className="px-4 py-2 text-sm text-white bg-brand-600 hover:bg-brand-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Create
          </button>
        </div>
      </div>
    </div>
  );
}

function SummaryBar({ summary }: { summary: HealthCheckSummary }) {
  const items = [
    { label: 'Healthy', count: summary.healthy, color: 'text-green-600' },
    { label: 'Degraded', count: summary.degraded, color: 'text-yellow-600' },
    { label: 'Down', count: summary.down, color: 'text-red-600' },
    { label: 'Cert Mismatch', count: summary.cert_mismatch, color: 'text-orange-600' },
    { label: 'Unknown', count: summary.unknown, color: 'text-gray-500' },
  ];

  return (
    <div className="grid grid-cols-5 gap-3 px-6 py-4 bg-white border-b border-surface-border">
      {items.map(item => (
        <div key={item.label} className="text-center">
          <p className={`text-2xl font-bold ${item.color}`}>{item.count}</p>
          <p className="text-xs text-ink-muted mt-1">{item.label}</p>
        </div>
      ))}
    </div>
  );
}

export default function HealthMonitorPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string | undefined>();

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['health-checks', statusFilter],
    queryFn: () => listHealthChecks({ status: statusFilter, page: 1, per_page: 100 }),
    refetchInterval: 30000,
  });

  const summaryQuery = useQuery({
    queryKey: ['health-checks-summary'],
    queryFn: () => getHealthCheckSummary(),
    refetchInterval: 30000,
  });

  // Every health-check mutation invalidates the same two queries: the list
  // (rows reflect new state) and the summary (counts reflect new state).
  const healthCheckInvalidates = [['health-checks'], ['health-checks-summary']];

  const createMutation = useTrackedMutation({
    mutationFn: createHealthCheck,
    invalidates: healthCheckInvalidates,
    onSuccess: () => {
      setShowCreate(false);
    },
  });

  const deleteMutation = useTrackedMutation({
    mutationFn: deleteHealthCheck,
    invalidates: healthCheckInvalidates,
  });

  const acknowledgeMutation = useTrackedMutation({
    mutationFn: acknowledgeHealthCheck,
    invalidates: healthCheckInvalidates,
  });

  const columns: Column<EndpointHealthCheck>[] = [
    {
      key: 'endpoint',
      label: 'Endpoint',
      render: (row) => row.endpoint,
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      key: 'response_time_ms',
      label: 'Response Time (ms)',
      render: (row) => row.response_time_ms ? `${row.response_time_ms}ms` : '—',
    },
    {
      key: 'last_checked_at',
      label: 'Last Checked',
      render: (row) => row.last_checked_at ? formatDateTime(row.last_checked_at) : '—',
    },
    {
      key: 'last_transition_at',
      label: 'Last Transition',
      render: (row) => row.last_transition_at ? formatDateTime(row.last_transition_at) : '—',
    },
    {
      key: 'acknowledged',
      label: 'Acknowledged',
      render: (row) => row.acknowledged ? '✓' : '—',
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row) => (
        <div className="flex gap-2">
          {!row.acknowledged && row.status !== 'healthy' && (
            <button
              onClick={() => acknowledgeMutation.mutate(row.id)}
              className="text-xs px-2 py-1 text-blue-600 hover:text-blue-700 font-medium"
              disabled={acknowledgeMutation.isPending}
            >
              Acknowledge
            </button>
          )}
          <button
            onClick={() => deleteMutation.mutate(row.id)}
            className="text-xs px-2 py-1 text-red-600 hover:text-red-700 font-medium"
            disabled={deleteMutation.isPending}
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  if (error) {
    return <ErrorState error={error as Error} onRetry={refetch} />;
  }

  return (
    <div className="flex flex-col overflow-hidden">
      <PageHeader
        title="Health Monitor"
        subtitle="Monitor TLS endpoints for certificate health and deployment success"
      />

      {summaryQuery.data && <SummaryBar summary={summaryQuery.data} />}

      <div className="flex-1 flex flex-col overflow-hidden bg-white m-6 rounded-lg shadow">
        <div className="px-6 py-4 border-b border-surface-border flex items-center justify-between">
          <div className="flex items-center gap-4">
            <select
              value={statusFilter || ''}
              onChange={e => setStatusFilter(e.target.value || undefined)}
              className="text-sm border border-surface-border rounded px-3 py-2 text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="">All Statuses</option>
              <option value="healthy">Healthy</option>
              <option value="degraded">Degraded</option>
              <option value="down">Down</option>
              <option value="cert_mismatch">Cert Mismatch</option>
              <option value="unknown">Unknown</option>
            </select>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="px-4 py-2 text-sm text-white bg-brand-600 hover:bg-brand-700 rounded"
          >
            New Health Check
          </button>
        </div>

        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="flex items-center justify-center h-full">
              <span className="text-ink-muted">Loading health checks...</span>
            </div>
          ) : data && data.data.length > 0 ? (
            <DataTable<EndpointHealthCheck>
              columns={columns}
              data={data.data}
              keyField="id"
            />
          ) : (
            <div className="flex items-center justify-center h-full">
              <span className="text-ink-muted">No health checks configured</span>
            </div>
          )}
        </div>
      </div>

      {showCreate && (
        <CreateHealthCheckModal
          onClose={() => setShowCreate(false)}
          onCreate={data => createMutation.mutate(data)}
        />
      )}
    </div>
  );
}

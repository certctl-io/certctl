import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import {
  getNetworkScanTargets,
  createNetworkScanTarget,
  updateNetworkScanTarget,
  deleteNetworkScanTarget,
  triggerNetworkScan,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { NetworkScanTarget } from '../api/types';

function CreateScanTargetModal({ onClose, onCreate }: {
  onClose: () => void;
  onCreate: (data: Partial<NetworkScanTarget>) => void;
}) {
  const [name, setName] = useState('');
  const [cidrs, setCidrs] = useState('');
  const [ports, setPorts] = useState('443');
  const [interval, setInterval] = useState('6');
  const [timeout, setTimeout] = useState('5000');

  const handleSubmit = () => {
    const cidrList = cidrs.split('\n').map(s => s.trim()).filter(Boolean);
    const portList = ports.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
    onCreate({
      name,
      cidrs: cidrList,
      ports: portList,
      scan_interval_hours: parseInt(interval, 10),
      timeout_ms: parseInt(timeout, 10),
      enabled: true,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4" onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-surface-border">
          <h3 className="text-lg font-semibold text-ink">New Scan Target</h3>
          <p className="text-sm text-ink-muted mt-1">Define a network range to scan for TLS certificates</p>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g., Production DMZ"
              className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">CIDR Ranges (one per line)</label>
            <textarea
              value={cidrs}
              onChange={e => setCidrs(e.target.value)}
              placeholder={"10.0.1.0/24\n10.0.2.0/24\n192.168.1.100/32"}
              className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
              rows={3}
            />
            <p className="text-xs text-ink-faint mt-1">Maximum /20 per CIDR (4096 IPs)</p>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Ports</label>
              <input
                type="text"
                value={ports}
                onChange={e => setPorts(e.target.value)}
                placeholder="443,8443"
                className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Interval (hrs)</label>
              <input
                type="number"
                value={interval}
                onChange={e => setInterval(e.target.value)}
                min="1"
                className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Timeout (ms)</label>
              <input
                type="number"
                value={timeout}
                onChange={e => setTimeout(e.target.value)}
                min="1000"
                step="1000"
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
            disabled={!name.trim() || !cidrs.trim()}
            className="px-4 py-2 text-sm text-white bg-brand-600 hover:bg-brand-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Create
          </button>
        </div>
      </div>
    </div>
  );
}

export default function NetworkScanPage() {
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['network-scan-targets'],
    queryFn: () => getNetworkScanTargets(),
    refetchInterval: 30000,
  });

  // Every network-scan-target mutation invalidates the same list query.
  const scanTargetInvalidates = [['network-scan-targets']];

  const createMutation = useTrackedMutation({
    mutationFn: createNetworkScanTarget,
    invalidates: scanTargetInvalidates,
    onSuccess: () => {
      setShowCreate(false);
    },
  });

  const deleteMutation = useTrackedMutation({
    mutationFn: deleteNetworkScanTarget,
    invalidates: scanTargetInvalidates,
  });

  const toggleMutation = useTrackedMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateNetworkScanTarget(id, { enabled }),
    invalidates: scanTargetInvalidates,
  });

  const scanMutation = useTrackedMutation({
    mutationFn: triggerNetworkScan,
    invalidates: scanTargetInvalidates,
  });

  const columns: Column<NetworkScanTarget>[] = [
    {
      key: 'name',
      label: 'Name',
      render: (t) => (
        <div>
          <div className="font-medium text-sm text-ink">{t.name}</div>
          <div className="font-mono text-xs text-ink-faint">{t.id}</div>
        </div>
      ),
    },
    {
      key: 'cidrs',
      label: 'CIDRs',
      render: (t) => (
        <div className="font-mono text-xs text-ink-muted">
          {t.cidrs?.slice(0, 2).join(', ')}{(t.cidrs?.length || 0) > 2 ? ` +${t.cidrs.length - 2}` : ''}
        </div>
      ),
    },
    {
      key: 'ports',
      label: 'Ports',
      render: (t) => <span className="font-mono text-xs text-ink-muted">{t.ports?.join(', ')}</span>,
    },
    {
      key: 'interval',
      label: 'Interval',
      render: (t) => <span className="text-sm text-ink-muted">{t.scan_interval_hours}h</span>,
    },
    {
      key: 'last_scan',
      label: 'Last Scan',
      render: (t) => (
        <div>
          <div className="text-xs text-ink-muted">{t.last_scan_at ? formatDateTime(t.last_scan_at) : 'Never'}</div>
          {t.last_scan_certs_found != null && (
            <div className="text-xs text-ink-faint">{t.last_scan_certs_found} certs found</div>
          )}
        </div>
      ),
    },
    {
      key: 'enabled',
      label: 'Enabled',
      render: (t) => (
        <button
          onClick={(e) => { e.stopPropagation(); toggleMutation.mutate({ id: t.id, enabled: !t.enabled }); }}
          className={`relative w-9 h-5 rounded-full transition-colors ${t.enabled ? 'bg-brand-500' : 'bg-gray-300'}`}
        >
          <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${t.enabled ? 'translate-x-4' : ''}`} />
        </button>
      ),
    },
    {
      key: 'actions',
      label: '',
      render: (t) => (
        <div className="flex gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); scanMutation.mutate(t.id); }}
            disabled={scanMutation.isPending}
            className="text-xs text-brand-600 hover:text-brand-700 font-medium"
          >
            Scan Now
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); deleteMutation.mutate(t.id); }}
            disabled={deleteMutation.isPending}
            className="text-xs text-red-400 hover:text-red-500"
          >
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Network Scanning"
        subtitle={data ? `${data.total} scan targets` : undefined}
        action={
          <button
            onClick={() => setShowCreate(true)}
            className="px-4 py-2 text-sm text-white bg-brand-600 hover:bg-brand-700 rounded-lg shadow-sm"
          >
            + New Target
          </button>
        }
      />

      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data || []}
            isLoading={isLoading}
            emptyMessage="No scan targets configured. Create one to start discovering certificates on your network."
          />
        )}
      </div>

      {showCreate && (
        <CreateScanTargetModal
          onClose={() => setShowCreate(false)}
          onCreate={(d) => createMutation.mutate(d)}
        />
      )}
    </>
  );
}

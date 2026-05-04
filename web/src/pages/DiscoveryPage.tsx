import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import {
  getDiscoveredCertificates,
  getDiscoverySummary,
  getDiscoveryScans,
  claimDiscoveredCertificate,
  dismissDiscoveredCertificate,
  getAgents,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { DiscoveredCertificate, DiscoveryScan } from '../api/types';

/** Map agent_id to a human-readable source type badge. */
function sourceTypeBadge(agentId: string): { label: string; style: string } {
  switch (agentId) {
    case 'server-scanner':
      return { label: 'Network', style: 'bg-blue-100 text-blue-800' };
    case 'cloud-aws-sm':
      return { label: 'AWS SM', style: 'bg-orange-100 text-orange-800' };
    case 'cloud-azure-kv':
      return { label: 'Azure KV', style: 'bg-sky-100 text-sky-800' };
    case 'cloud-gcp-sm':
      return { label: 'GCP SM', style: 'bg-green-100 text-green-800' };
    default:
      return { label: 'Filesystem', style: 'bg-gray-100 text-gray-800' };
  }
}

function ClaimModal({ cert, onClose, onClaim }: { cert: DiscoveredCertificate; onClose: () => void; onClaim: (managedCertId: string) => void }) {
  const [managedCertId, setManagedCertId] = useState('');
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-surface-border">
          <h3 className="text-lg font-semibold text-ink">Claim Certificate</h3>
          <p className="text-sm text-ink-muted mt-1">
            Link <span className="font-mono text-xs">{cert.common_name}</span> to a managed certificate
          </p>
        </div>
        <div className="px-6 py-4">
          <label className="block text-sm font-medium text-ink mb-1">Managed Certificate ID</label>
          <input
            type="text"
            value={managedCertId}
            onChange={e => setManagedCertId(e.target.value)}
            placeholder="e.g., mc-api-prod"
            className="w-full border border-surface-border rounded px-3 py-2 text-sm text-ink bg-white font-mono focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <p className="text-xs text-ink-faint mt-2">Enter the ID of the managed certificate this discovered cert belongs to.</p>
        </div>
        <div className="px-6 py-3 border-t border-surface-border flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-sm text-ink-muted hover:text-ink rounded border border-surface-border">
            Cancel
          </button>
          <button
            onClick={() => onClaim(managedCertId)}
            disabled={!managedCertId.trim()}
            className="px-4 py-2 text-sm text-white bg-brand-600 hover:bg-brand-700 rounded disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Claim
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanHistoryPanel({ scans }: { scans: DiscoveryScan[] }) {
  if (scans.length === 0) return <p className="text-sm text-ink-muted py-4 text-center">No scans recorded yet</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-ink-faint border-b border-surface-border">
            <th className="px-4 py-2">Agent</th>
            <th className="px-4 py-2">Directories</th>
            <th className="px-4 py-2">Found</th>
            <th className="px-4 py-2">New</th>
            <th className="px-4 py-2">Errors</th>
            <th className="px-4 py-2">Duration</th>
            <th className="px-4 py-2">Started</th>
          </tr>
        </thead>
        <tbody>
          {scans.map(s => (
            <tr key={s.id} className="border-b border-surface-border/50 hover:bg-surface-hover">
              <td className="px-4 py-2 font-mono text-xs">{s.agent_id}</td>
              <td className="px-4 py-2 text-xs text-ink-muted">{s.directories?.join(', ') || '—'}</td>
              <td className="px-4 py-2">{s.certificates_found}</td>
              <td className="px-4 py-2 text-green-600">{s.certificates_new}</td>
              <td className="px-4 py-2">{s.errors_count > 0 ? <span className="text-red-500">{s.errors_count}</span> : '0'}</td>
              <td className="px-4 py-2 text-ink-muted">{s.scan_duration_ms}ms</td>
              <td className="px-4 py-2 text-xs text-ink-muted">{formatDateTime(s.started_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function DiscoveryPage() {
  const [statusFilter, setStatusFilter] = useState('');
  const [agentFilter, setAgentFilter] = useState('');
  const [claimingCert, setClaimingCert] = useState<DiscoveredCertificate | null>(null);
  const [showScans, setShowScans] = useState(false);

  const params: Record<string, string> = {};
  if (statusFilter) params.status = statusFilter;
  if (agentFilter) params.agent_id = agentFilter;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['discovered-certificates', params],
    queryFn: () => getDiscoveredCertificates(params),
    refetchInterval: 30000,
  });

  const { data: summary } = useQuery({
    queryKey: ['discovery-summary'],
    queryFn: getDiscoverySummary,
    refetchInterval: 30000,
  });

  const { data: scansData } = useQuery({
    queryKey: ['discovery-scans'],
    queryFn: () => getDiscoveryScans(),
    enabled: showScans,
  });

  const { data: agentsData } = useQuery({
    queryKey: ['agents-for-filter'],
    queryFn: () => getAgents({ per_page: '200' }),
  });

  const claimMutation = useTrackedMutation({
    mutationFn: ({ id, managedCertId }: { id: string; managedCertId: string }) =>
      claimDiscoveredCertificate(id, managedCertId),
    invalidates: [['discovered-certificates'], ['discovery-summary']],
    onSuccess: () => {
      setClaimingCert(null);
    },
  });

  const dismissMutation = useTrackedMutation({
    mutationFn: dismissDiscoveredCertificate,
    invalidates: [['discovered-certificates'], ['discovery-summary']],
  });

  const formatExpiry = (notAfter?: string) => {
    if (!notAfter) return '—';
    const d = new Date(notAfter);
    const now = new Date();
    const days = Math.floor((d.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    if (days < 0) return <span className="text-red-500">Expired {Math.abs(days)}d ago</span>;
    if (days < 30) return <span className="text-amber-500">{days}d left</span>;
    return <span className="text-ink-muted">{days}d left</span>;
  };

  const discoveryStatusStyle: Record<string, string> = {
    Unmanaged: 'badge badge-warning',
    Managed: 'badge badge-success',
    Dismissed: 'badge badge-neutral',
  };

  const columns: Column<DiscoveredCertificate>[] = [
    {
      key: 'common_name',
      label: 'Common Name',
      render: (c) => (
        <div>
          <div className="font-medium text-sm text-ink">{c.common_name || '(no CN)'}</div>
          {c.sans?.length > 0 && (
            <div className="text-xs text-ink-faint truncate max-w-[200px]" title={c.sans.join(', ')}>
              {c.sans.slice(0, 2).join(', ')}{c.sans.length > 2 ? ` +${c.sans.length - 2}` : ''}
            </div>
          )}
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (c) => <span className={discoveryStatusStyle[c.status] || 'badge badge-neutral'}>{c.status}</span>,
    },
    {
      key: 'source',
      label: 'Source',
      render: (c) => {
        const badge = sourceTypeBadge(c.agent_id);
        return (
          <div>
            <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${badge.style} mr-1`}>{badge.label}</span>
            <div className="text-xs text-ink-faint truncate max-w-[180px] mt-0.5" title={c.source_path}>{c.source_path}</div>
          </div>
        );
      },
    },
    {
      key: 'issuer',
      label: 'Issuer',
      render: (c) => <span className="text-xs text-ink-muted truncate max-w-[150px]" title={c.issuer_dn}>{c.issuer_dn?.split(',')[0] || '—'}</span>,
    },
    {
      key: 'expiry',
      label: 'Expiry',
      render: (c) => <span className="text-xs">{formatExpiry(c.not_after)}</span>,
    },
    {
      key: 'key_info',
      label: 'Key',
      render: (c) => (
        <div className="flex items-center gap-1">
          <span className="text-xs text-ink-muted">{c.key_algorithm}{c.key_size ? ` ${c.key_size}` : ''}</span>
          {c.is_ca && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-100 text-purple-700 font-medium">CA</span>
          )}
        </div>
      ),
    },
    {
      key: 'fingerprint',
      label: 'Fingerprint',
      render: (c) => <span className="font-mono text-[10px] text-ink-faint">{c.fingerprint_sha256?.substring(0, 16)}...</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (c) => (
        c.status === 'Unmanaged' ? (
          <div className="flex gap-2">
            <button
              onClick={(e) => { e.stopPropagation(); setClaimingCert(c); }}
              className="text-xs text-brand-600 hover:text-brand-700 font-medium"
            >
              Claim
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); dismissMutation.mutate(c.id); }}
              disabled={dismissMutation.isPending}
              className="text-xs text-ink-faint hover:text-ink-muted"
            >
              Dismiss
            </button>
          </div>
        ) : null
      ),
    },
  ];

  return (
    <>
      <PageHeader title="Certificate Discovery" subtitle={data ? `${data.total} discovered certificates` : undefined} />

      {/* Summary stats bar */}
      {summary && (
        <div className="px-6 py-3 flex gap-4 border-b border-surface-border/50">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
            <span className="text-sm text-ink"><strong>{summary.Unmanaged || 0}</strong> Unmanaged</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-green-400"></span>
            <span className="text-sm text-ink"><strong>{summary.Managed || 0}</strong> Managed</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-gray-400"></span>
            <span className="text-sm text-ink"><strong>{summary.Dismissed || 0}</strong> Dismissed</span>
          </div>
          <div className="ml-auto">
            <button
              onClick={() => setShowScans(!showScans)}
              className="text-xs text-brand-600 hover:text-brand-700 font-medium"
            >
              {showScans ? 'Hide' : 'Show'} Scan History
            </button>
          </div>
        </div>
      )}

      {/* Scan history collapsible */}
      {showScans && (
        <div className="border-b border-surface-border/50 bg-surface-subtle">
          <div className="px-6 py-2">
            <h3 className="text-sm font-semibold text-ink mb-2">Recent Scans</h3>
            <ScanHistoryPanel scans={scansData?.data || []} />
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="px-6 py-3 flex gap-3 border-b border-surface-border/50">
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All statuses</option>
          <option value="Unmanaged">Unmanaged</option>
          <option value="Managed">Managed</option>
          <option value="Dismissed">Dismissed</option>
        </select>
        <select
          value={agentFilter}
          onChange={e => setAgentFilter(e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All agents</option>
          {agentsData?.data?.map(a => (
            <option key={a.id} value={a.id}>{a.name || a.id}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data || []}
            isLoading={isLoading}
            emptyMessage="No discovered certificates. Agents will report findings once discovery scanning is configured."
          />
        )}
      </div>

      {claimingCert && (
        <ClaimModal
          cert={claimingCert}
          onClose={() => setClaimingCert(null)}
          onClaim={(managedCertId) => claimMutation.mutate({ id: claimingCert.id, managedCertId })}
        />
      )}
    </>
  );
}

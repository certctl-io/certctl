import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import {
  getNetworkScanTargets,
  createNetworkScanTarget,
  updateNetworkScanTarget,
  deleteNetworkScanTarget,
  triggerNetworkScan,
  probeSCEPServer,
  listSCEPProbes,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { NetworkScanTarget, SCEPProbeResult } from '../api/types';

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
        <SCEPProbeSection />
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

// =============================================================================
// SCEP Probe section — Phase 11.5 of the master bundle.
// =============================================================================
//
// Operator-facing panel that runs an ad-hoc SCEP probe against a single
// URL. Used for pre-migration assessment (probe an existing EJBCA / NDES
// SCEP server before switching to certctl) and compliance posture audits
// (probe your own SCEP server periodically). Capability-only — does NOT
// POST a CSR. SSRF-defended at the backend via SafeHTTPDialContext.
//
// History table polls every 60s via TanStack Query.

function SCEPProbeSection() {
  const [url, setUrl] = useState('');
  const [latestResult, setLatestResult] = useState<SCEPProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | undefined>(undefined);

  const historyQuery = useQuery({
    queryKey: ['scep-probes'],
    queryFn: listSCEPProbes,
    refetchInterval: 60_000,
  });

  const probeMutation = useTrackedMutation<SCEPProbeResult, Error, string>({
    mutationFn: (target: string) => probeSCEPServer(target),
    invalidates: [['scep-probes']],
    onSuccess: (result) => {
      setLatestResult(result);
      setProbeError(undefined);
    },
    onError: (err: Error) => {
      setLatestResult(null);
      setProbeError(err.message);
    },
  });

  const handleProbe = () => {
    if (!url.trim()) {
      setProbeError('Enter a SCEP server URL');
      return;
    }
    setProbeError(undefined);
    probeMutation.mutate(url.trim());
  };

  return (
    <section className="px-6 py-4 mt-2 border-t border-surface-border" data-testid="scep-probe-section">
      <header className="mb-3">
        <h2 className="text-base font-semibold text-ink">SCEP server probe</h2>
        <p className="text-xs text-ink-muted">
          Probe a SCEP server URL for capability + posture (RFC 8894 GetCACaps + GetCACert).
          Use before migrating from EJBCA / NDES to verify what the existing server advertises.
          Capability-only: does NOT POST a CSR. Reserved IP ranges are rejected.
        </p>
      </header>

      <div className="bg-surface border border-surface-border rounded-lg p-4 mb-4">
        <div className="flex gap-2">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://scep.example.com/scep"
            className="flex-1 border border-surface-border rounded px-3 py-2 text-sm font-mono"
            data-testid="scep-probe-url-input"
            disabled={probeMutation.isPending}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleProbe();
            }}
          />
          <button
            type="button"
            onClick={handleProbe}
            disabled={probeMutation.isPending}
            className="px-4 py-2 text-sm text-white bg-brand-600 hover:bg-brand-700 rounded disabled:opacity-50"
            data-testid="scep-probe-submit"
          >
            {probeMutation.isPending ? 'Probing…' : 'Probe'}
          </button>
        </div>
        {probeError && (
          <div className="mt-3 rounded border border-red-300 bg-red-50 p-3 text-xs text-red-800" data-testid="scep-probe-error">
            {probeError}
          </div>
        )}
        {latestResult && <SCEPProbeResultPanel result={latestResult} />}
      </div>

      <SCEPProbeHistoryTable
        probes={historyQuery.data?.probes ?? []}
        isLoading={historyQuery.isLoading}
      />
    </section>
  );
}

function SCEPProbeResultPanel({ result }: { result: SCEPProbeResult }) {
  const tone = result.error
    ? 'bg-red-50 border-red-300 text-red-800'
    : result.reachable
      ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
      : 'bg-amber-50 border-amber-300 text-amber-900';
  return (
    <div className={`mt-3 rounded border p-3 text-xs ${tone}`} data-testid="scep-probe-result-panel">
      <div className="flex items-center justify-between mb-2">
        <strong className="text-sm">{result.target_url}</strong>
        <span>{formatDateTime(result.probed_at)} · {result.probe_duration_ms}ms</span>
      </div>
      {result.error && (
        <p className="font-mono text-[11px] mb-2">Error: {result.error}</p>
      )}
      {result.reachable && (
        <>
          <div className="flex flex-wrap gap-1 mb-2" data-testid="scep-probe-cap-badges">
            <CapBadge label="RFC 8894" supported={result.supports_rfc8894} />
            <CapBadge label="AES" supported={result.supports_aes} />
            <CapBadge label="POST" supported={result.supports_post_operation} />
            <CapBadge label="Renewal" supported={result.supports_renewal} />
            <CapBadge label="SHA-256" supported={result.supports_sha256} />
            <CapBadge label="SHA-512" supported={result.supports_sha512} />
          </div>
          {result.ca_cert_subject && (
            <dl className="grid grid-cols-2 gap-x-3 gap-y-1 mt-2">
              <dt className="font-semibold">CA cert subject:</dt>
              <dd className="font-mono text-[11px]">{result.ca_cert_subject}</dd>
              <dt className="font-semibold">Issuer:</dt>
              <dd className="font-mono text-[11px]">{result.ca_cert_issuer}</dd>
              <dt className="font-semibold">Algorithm:</dt>
              <dd>{result.ca_cert_algorithm || '(unknown)'}</dd>
              <dt className="font-semibold">Chain length:</dt>
              <dd>{result.ca_cert_chain_length}</dd>
              <dt className="font-semibold">Expires:</dt>
              <dd>
                {result.ca_cert_not_after ? formatDateTime(result.ca_cert_not_after) : '(unknown)'}
                {' '}
                {result.ca_cert_expired ? (
                  <span className="text-red-600 font-semibold">(EXPIRED)</span>
                ) : (
                  <span>({result.ca_cert_days_to_expiry}d remaining)</span>
                )}
              </dd>
            </dl>
          )}
          {result.advertised_caps && result.advertised_caps.length > 0 && (
            <p className="mt-2 text-[11px]">
              Raw caps: <code>{result.advertised_caps.join(', ')}</code>
            </p>
          )}
        </>
      )}
    </div>
  );
}

function CapBadge({ label, supported }: { label: string; supported: boolean }) {
  return (
    <span
      className={`text-[11px] uppercase px-2 py-0.5 rounded border ${
        supported ? 'bg-emerald-100 text-emerald-800 border-emerald-300' : 'bg-gray-100 text-gray-600 border-gray-300'
      }`}
      data-testid={`scep-probe-cap-${label.toLowerCase().replace(/\W/g, '-')}`}
    >
      {label} {supported ? '✓' : '✗'}
    </span>
  );
}

function SCEPProbeHistoryTable({ probes, isLoading }: { probes: SCEPProbeResult[]; isLoading: boolean }) {
  if (isLoading) {
    return <p className="text-xs text-ink-muted">Loading probe history…</p>;
  }
  if (probes.length === 0) {
    return <p className="text-xs text-ink-muted">No SCEP probes yet — probe a URL above to start.</p>;
  }
  return (
    <div className="mt-3" data-testid="scep-probe-history-table">
      <h3 className="text-xs font-semibold text-ink uppercase tracking-wide mb-2">Recent SCEP probes</h3>
      <table className="w-full text-xs">
        <thead className="text-ink-muted uppercase">
          <tr>
            <th className="text-left py-1 pr-2">When</th>
            <th className="text-left py-1 pr-2">Target</th>
            <th className="text-left py-1 pr-2">Reachable</th>
            <th className="text-left py-1 pr-2">RFC 8894</th>
            <th className="text-left py-1 pr-2">CA expiry</th>
          </tr>
        </thead>
        <tbody>
          {probes.map((p) => (
            <tr key={p.id} className="border-t border-surface-border">
              <td className="py-1 pr-2 font-mono">{formatDateTime(p.probed_at)}</td>
              <td className="py-1 pr-2 font-mono break-all">{p.target_url}</td>
              <td className="py-1 pr-2">
                {p.reachable ? (
                  <span className="text-emerald-700">Yes</span>
                ) : (
                  <span className="text-red-700">No</span>
                )}
              </td>
              <td className="py-1 pr-2">{p.supports_rfc8894 ? '✓' : '✗'}</td>
              <td className="py-1 pr-2">
                {p.ca_cert_expired ? (
                  <span className="text-red-700 font-semibold">EXPIRED</span>
                ) : p.ca_cert_subject ? (
                  `${p.ca_cert_days_to_expiry}d`
                ) : (
                  '-'
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

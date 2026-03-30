import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { getIssuer, testIssuerConnection, getCertificates } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';
import type { Certificate, Issuer } from '../api/types';
import { typeLabels, redactConfig } from '../config/issuerTypes';

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between py-2 border-b border-surface-border/50">
      <span className="text-sm text-ink-muted">{label}</span>
      <span className="text-sm text-ink">{value}</span>
    </div>
  );
}

/** Derive display status from backend enabled boolean */
function issuerStatus(issuer: Issuer): string {
  if (issuer.enabled !== undefined) {
    return issuer.enabled ? 'Enabled' : 'Disabled';
  }
  return issuer.status || 'Unknown';
}

export default function IssuerDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: issuer, isLoading, error, refetch } = useQuery({
    queryKey: ['issuer', id],
    queryFn: () => getIssuer(id!),
    enabled: !!id,
  });

  const { data: certsData } = useQuery({
    queryKey: ['certificates', { issuer_id: id }],
    queryFn: () => getCertificates({ issuer_id: id! }),
    enabled: !!id,
  });

  const testMutation = useMutation({
    mutationFn: () => testIssuerConnection(id!),
  });

  if (error) {
    return (
      <>
        <PageHeader title="Issuer Details" />
        <ErrorState error={error as Error} onRetry={() => refetch()} />
      </>
    );
  }

  if (isLoading || !issuer) {
    return (
      <>
        <PageHeader title="Issuer Details" />
        <div className="flex items-center justify-center py-20">
          <div className="text-sm text-ink-muted">Loading issuer...</div>
        </div>
      </>
    );
  }

  const safeConfig = issuer.config ? redactConfig(issuer.config) : {};

  const certColumns: Column<Certificate>[] = [
    {
      key: 'name',
      label: 'Certificate',
      render: (c) => (
        <div>
          <div className="font-medium text-ink text-sm">{c.common_name}</div>
          <div className="text-xs text-ink-faint font-mono">{c.id}</div>
        </div>
      ),
    },
    { key: 'status', label: 'Status', render: (c) => <StatusBadge status={c.status} /> },
    { key: 'expires', label: 'Expires', render: (c) => <span className="text-xs text-ink-muted">{formatDateTime(c.expires_at)}</span> },
  ];

  return (
    <>
      <PageHeader
        title={issuer.name}
        subtitle={typeLabels[issuer.type] || issuer.type}
        action={
          <div className="flex gap-2">
            <button
              onClick={() => navigate(`/issuers?edit=${issuer.id}`)}
              className="px-3 py-1.5 border border-surface-border rounded text-ink text-xs hover:bg-surface-hover transition-colors font-medium"
            >
              Edit
            </button>
            <button
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending}
              className="btn btn-primary text-xs disabled:opacity-50"
            >
              {testMutation.isPending ? 'Testing...' : 'Test Connection'}
            </button>
          </div>
        }
      />

      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
        {testMutation.isSuccess && (
          <div className="px-4 py-2.5 bg-emerald-50 border border-emerald-200 rounded-lg text-sm text-emerald-700">
            Connection test passed.
          </div>
        )}
        {testMutation.isError && (
          <div className="px-4 py-2.5 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
            Connection test failed: {(testMutation.error as Error).message}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Issuer info */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Issuer Information</h3>
            <InfoRow label="ID" value={<span className="font-mono text-xs">{issuer.id}</span>} />
            <InfoRow label="Name" value={issuer.name} />
            <InfoRow label="Type" value={typeLabels[issuer.type] || issuer.type} />
            <InfoRow label="Status" value={<StatusBadge status={issuerStatus(issuer)} />} />
            <InfoRow label="Created" value={formatDateTime(issuer.created_at)} />
          </div>

          {/* Config (redacted) */}
          <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-ink-muted mb-4">Configuration</h3>
            {Object.keys(safeConfig).length > 0 ? (
              <div className="space-y-0">
                {Object.entries(safeConfig).map(([key, val]) => (
                  <InfoRow key={key} label={key} value={
                    <span className="font-mono text-xs truncate max-w-xs inline-block">{String(val)}</span>
                  } />
                ))}
              </div>
            ) : (
              <div className="text-sm text-ink-faint py-4 text-center">No configuration data</div>
            )}
          </div>
        </div>

        {/* Issued certificates */}
        <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-ink-muted mb-4">
            Issued Certificates {certsData ? `(${certsData.total})` : ''}
          </h3>
          <DataTable
            columns={certColumns}
            data={certsData?.data || []}
            isLoading={!certsData}
            emptyMessage="No certificates issued by this issuer"
          />
        </div>
      </div>
    </>
  );
}

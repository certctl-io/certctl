import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getCertificates, getProfiles } from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDateTime, daysUntil } from '../api/utils';
import type { Certificate, CertificateProfile } from '../api/types';

function formatTTL(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

function ttlRemaining(expiresAt: string): { text: string; color: string; seconds: number } {
  const diff = new Date(expiresAt).getTime() - Date.now();
  const secs = Math.floor(diff / 1000);
  if (secs <= 0) return { text: 'Expired', color: 'text-red-400', seconds: 0 };
  if (secs < 300) return { text: `${secs}s`, color: 'text-red-400', seconds: secs };
  if (secs < 1800) return { text: `${Math.round(secs / 60)}m`, color: 'text-amber-400', seconds: secs };
  return { text: formatTTL(secs), color: 'text-emerald-400', seconds: secs };
}

export default function ShortLivedPage() {
  const navigate = useNavigate();

  const { data: certsData, isLoading: certsLoading, error: certsError, refetch } = useQuery({
    queryKey: ['certificates', {}],
    queryFn: () => getCertificates(),
    refetchInterval: 10000, // Refresh every 10s for short-lived certs
  });

  const { data: profilesData } = useQuery({
    queryKey: ['profiles'],
    queryFn: () => getProfiles(),
  });

  // Build profile lookup
  const profileMap = new Map<string, CertificateProfile>();
  profilesData?.data?.forEach(p => profileMap.set(p.id, p));

  // Filter to short-lived certificates (profile with allow_short_lived and max_ttl < 1 hour)
  const shortLivedProfileIds = new Set(
    (profilesData?.data || [])
      .filter(p => p.allow_short_lived && p.max_ttl_seconds > 0 && p.max_ttl_seconds < 3600)
      .map(p => p.id)
  );

  // Include certs that match short-lived profiles OR certs that expire within 1 hour
  const allCerts = certsData?.data || [];
  const shortLivedCerts = allCerts.filter(c => {
    if (c.status === 'Archived') return false;
    if (shortLivedProfileIds.has(c.certificate_profile_id)) return true;
    // Also include any cert with < 1 hour of life remaining that is active
    const secsRemaining = (new Date(c.expires_at).getTime() - Date.now()) / 1000;
    if (secsRemaining > 0 && secsRemaining < 3600 && c.status === 'Active') return true;
    return false;
  });

  // Sort by expiration (soonest first)
  shortLivedCerts.sort((a, b) => new Date(a.expires_at).getTime() - new Date(b.expires_at).getTime());

  // Stats
  const active = shortLivedCerts.filter(c => c.status === 'Active' && daysUntil(c.expires_at) >= 0).length;
  const expired = shortLivedCerts.filter(c => c.status === 'Expired' || daysUntil(c.expires_at) < 0).length;
  const profiles = new Set(shortLivedCerts.map(c => c.certificate_profile_id).filter(Boolean));

  const columns: Column<Certificate>[] = [
    {
      key: 'name',
      label: 'Certificate',
      render: (c) => (
        <div>
          <div className="font-medium text-slate-200">{c.common_name}</div>
          <div className="text-xs text-slate-500 mt-0.5">{c.id}</div>
        </div>
      ),
    },
    { key: 'status', label: 'Status', render: (c) => <StatusBadge status={c.status} /> },
    {
      key: 'ttl',
      label: 'TTL Remaining',
      render: (c) => {
        const ttl = ttlRemaining(c.expires_at);
        return (
          <div className="flex items-center gap-2">
            <div className={`font-mono text-sm font-medium ${ttl.color}`}>{ttl.text}</div>
            {ttl.seconds > 0 && ttl.seconds < 300 && (
              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            )}
          </div>
        );
      },
    },
    {
      key: 'profile',
      label: 'Profile',
      render: (c) => {
        const profile = profileMap.get(c.certificate_profile_id);
        return (
          <div>
            <div className="text-sm text-slate-300">{profile?.name || c.certificate_profile_id || '—'}</div>
            {profile && <div className="text-xs text-slate-500">Max TTL: {formatTTL(profile.max_ttl_seconds)}</div>}
          </div>
        );
      },
    },
    { key: 'env', label: 'Environment', render: (c) => <span className="text-slate-300">{c.environment || '—'}</span> },
    { key: 'issuer', label: 'Issuer', render: (c) => <span className="text-slate-400 text-xs">{c.issuer_id}</span> },
    { key: 'expires', label: 'Expires At', render: (c) => <span className="text-xs text-slate-400">{formatDateTime(c.expires_at)}</span> },
  ];

  return (
    <>
      <PageHeader
        title="Short-Lived Credentials"
        subtitle={`${shortLivedCerts.length} active ephemeral certificates`}
      />
      {/* Stats bar */}
      <div className="px-6 py-3 flex gap-6 border-b border-slate-700/50">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="text-xs text-slate-400">Active:</span>
          <span className="text-xs font-medium text-emerald-400">{active}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-red-400" />
          <span className="text-xs text-slate-400">Expired:</span>
          <span className="text-xs font-medium text-red-400">{expired}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-blue-400" />
          <span className="text-xs text-slate-400">Profiles:</span>
          <span className="text-xs font-medium text-blue-400">{profiles.size}</span>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto">
        {certsError ? (
          <ErrorState error={certsError as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable
            columns={columns}
            data={shortLivedCerts}
            isLoading={certsLoading}
            onRowClick={(c) => navigate(`/certificates/${c.id}`)}
            emptyMessage="No short-lived credentials found. Certificates with profiles that have TTL < 1 hour will appear here."
          />
        )}
      </div>
    </>
  );
}

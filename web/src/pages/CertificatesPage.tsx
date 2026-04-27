import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { useListParams } from '../hooks/useListParams';
import { useNavigate } from 'react-router-dom';
import { getCertificates, createCertificate, revokeCertificate, getOwners, getTeams, getRenewalPolicies, getProfiles, getIssuers, bulkRevokeCertificates, bulkRenewCertificates, bulkReassignCertificates } from '../api/client';
import { useAuth } from '../components/AuthProvider';
import { REVOCATION_REASONS } from '../api/types';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { formatDate, daysUntil, expiryColor } from '../api/utils';
import type { Certificate } from '../api/types';

function CreateCertificateModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [form, setForm] = useState({
    name: '',
    id: '',
    common_name: '',
    sans: '',
    environment: 'production',
    issuer_id: '',
    certificate_profile_id: '',
    owner_id: '',
    team_id: '',
    renewal_policy_id: '',
    tags: '',
  });
  const [error, setError] = useState('');

  const { data: profilesResp } = useQuery({
    queryKey: ['profiles'],
    queryFn: () => getProfiles(),
  });
  const { data: issuersResp } = useQuery({
    queryKey: ['issuers'],
    queryFn: () => getIssuers(),
  });
  // C-001: owner_id, team_id, and renewal_policy_id are required by the
  // server (handler in internal/api/handler/certificates.go) and by OpenAPI.
  // Load the catalog so the user selects valid FKs instead of typing free-text
  // IDs that would 400 at the server.
  const { data: ownersResp } = useQuery({
    queryKey: ['owners', 'form'],
    queryFn: () => getOwners({ per_page: '500' }),
  });
  const { data: teamsResp } = useQuery({
    queryKey: ['teams', 'form'],
    queryFn: () => getTeams({ per_page: '500' }),
  });
  // G-1: swap from getPolicies (compliance rules, pol-*) to getRenewalPolicies
  // (lifecycle policies, rp-*). managed_certificates.renewal_policy_id FK
  // points at renewal_policies(id), so the dropdown must pull from that table
  // — the previous getPolicies call populated the dropdown with pol-* IDs that
  // would 400/23503 at the server. See also OnboardingWizard.tsx:603 and
  // CertificateDetailPage.tsx:169 for the sibling fixes.
  const { data: policiesResp } = useQuery({
    queryKey: ['renewal-policies', 'form'],
    queryFn: () => getRenewalPolicies(1, 500),
  });
  const profiles = profilesResp?.data || [];
  const issuers = issuersResp?.data || [];
  const owners = ownersResp?.data || [];
  const teams = teamsResp?.data || [];
  const policies = policiesResp?.data || [];

  const selectedProfile = profiles.find(p => p.id === form.certificate_profile_id);
  const ttlLabel = selectedProfile
    ? selectedProfile.max_ttl_seconds < 3600
      ? `${Math.round(selectedProfile.max_ttl_seconds / 60)}m`
      : selectedProfile.max_ttl_seconds < 86400
        ? `${Math.round(selectedProfile.max_ttl_seconds / 3600)}h`
        : `${Math.round(selectedProfile.max_ttl_seconds / 86400)}d`
    : null;

  const mutation = useTrackedMutation({
    mutationFn: () => {
      const payload: Record<string, unknown> = { ...form };
      // Convert comma-separated SANs to array
      if (form.sans.trim()) {
        payload.sans = form.sans.split(',').map(s => s.trim()).filter(Boolean);
      } else {
        delete payload.sans;
      }
      // Convert comma-separated key=value tags to object
      if (form.tags.trim()) {
        const tags: Record<string, string> = {};
        form.tags.split(',').forEach(pair => {
          const [k, ...v] = pair.split('=');
          if (k?.trim()) tags[k.trim()] = v.join('=').trim();
        });
        payload.tags = tags;
      } else {
        delete payload.tags;
      }
      return createCertificate(payload);
    },
    invalidates: [['certificates']],
    onSuccess: () => onSuccess(),
    onError: (err: Error) => setError(err.message),
  });

  const inputClass = "w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink focus:outline-none focus:border-brand-400 focus:ring-1 focus:ring-brand-400/20";
  const selectClass = "w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink";

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-lg shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-4">New Certificate</h2>
        {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-4">{error}</div>}
        <div className="space-y-3">
          <div>
            <label className="text-xs text-ink-muted block mb-1">Name *</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className={inputClass}
              placeholder="API Production Cert" />
          </div>
          <div>
            <label className="text-xs text-ink-muted block mb-1">ID (optional)</label>
            <input value={form.id} onChange={e => setForm(f => ({ ...f, id: e.target.value }))}
              className={inputClass}
              placeholder="mc-api-prod (auto-generated if empty)" />
          </div>
          <div>
            <label className="text-xs text-ink-muted block mb-1">Common Name *</label>
            <input value={form.common_name} onChange={e => setForm(f => ({ ...f, common_name: e.target.value }))}
              className={inputClass}
              placeholder="api.example.com" />
          </div>
          <div>
            <label className="text-xs text-ink-muted block mb-1">SANs (comma-separated)</label>
            <input value={form.sans} onChange={e => setForm(f => ({ ...f, sans: e.target.value }))}
              className={inputClass}
              placeholder="api.example.com, api-v2.example.com" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-ink-muted block mb-1">Issuer *</label>
              <select value={form.issuer_id} onChange={e => setForm(f => ({ ...f, issuer_id: e.target.value }))}
                className={selectClass}>
                <option value="">Select issuer...</option>
                {issuers.map(i => (
                  <option key={i.id} value={i.id}>{i.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-ink-muted block mb-1">
                Profile {ttlLabel && <span className="text-brand-400 font-medium">(TTL: {ttlLabel})</span>}
              </label>
              <select value={form.certificate_profile_id} onChange={e => setForm(f => ({ ...f, certificate_profile_id: e.target.value }))}
                className={selectClass}>
                <option value="">Select profile...</option>
                {profiles.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name}{p.max_ttl_seconds ? ` (${p.max_ttl_seconds < 3600 ? `${Math.round(p.max_ttl_seconds / 60)}m` : p.max_ttl_seconds < 86400 ? `${Math.round(p.max_ttl_seconds / 3600)}h` : `${Math.round(p.max_ttl_seconds / 86400)}d`})` : ''}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-ink-muted block mb-1">Environment</label>
              <select value={form.environment} onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}
                className={selectClass}>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-ink-muted block mb-1">Policy *</label>
              <select value={form.renewal_policy_id} onChange={e => setForm(f => ({ ...f, renewal_policy_id: e.target.value }))}
                className={selectClass}>
                <option value="">Select policy...</option>
                {policies.map(p => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-ink-muted block mb-1">Owner *</label>
              <select value={form.owner_id} onChange={e => setForm(f => ({ ...f, owner_id: e.target.value }))}
                className={selectClass}>
                <option value="">Select owner...</option>
                {owners.map(o => (
                  <option key={o.id} value={o.id}>{o.name} ({o.email})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-ink-muted block mb-1">Team *</label>
              <select value={form.team_id} onChange={e => setForm(f => ({ ...f, team_id: e.target.value }))}
                className={selectClass}>
                <option value="">Select team...</option>
                {teams.map(t => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-ink-muted block mb-1">Tags</label>
            <input value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
              className={inputClass}
              placeholder="env=prod, team=platform, app=api" />
            <p className="text-xs text-ink-faint mt-0.5">Comma-separated key=value pairs</p>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="btn btn-ghost text-sm">Cancel</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={
              !form.name ||
              !form.common_name ||
              !form.issuer_id ||
              !form.owner_id ||
              !form.team_id ||
              !form.renewal_policy_id ||
              mutation.isPending
            }
            className="btn btn-primary text-sm disabled:opacity-50"
          >
            {mutation.isPending ? 'Creating...' : 'Create Certificate'}
          </button>
        </div>
      </div>
    </div>
  );
}

function BulkRevokeModal({ ids, onClose, onSuccess }: { ids: string[]; onClose: () => void; onSuccess: () => void }) {
  const [reason, setReason] = useState('unspecified');
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<{ total_matched: number; total_revoked: number; total_skipped: number; total_failed: number; errors?: { certificate_id: string; error: string }[] } | null>(null);

  const handleRevoke = async () => {
    setRunning(true);
    setError('');
    try {
      const res = await bulkRevokeCertificates({ reason, certificate_ids: ids });
      setResult(res);
      if (res.total_failed === 0) {
        onSuccess();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bulk revocation failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-red-700 mb-2">Bulk Revoke</h2>
        <p className="text-sm text-ink-muted mb-4">
          Revoke {ids.length} certificate{ids.length > 1 ? 's' : ''}. This cannot be undone.
        </p>
        {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-3">{error}</div>}
        {result && (
          <div className="mb-3 bg-gray-50 border border-gray-200 rounded px-3 py-2 text-sm">
            <div className="grid grid-cols-2 gap-1">
              <span className="text-ink-muted">Matched:</span><span className="font-medium">{result.total_matched}</span>
              <span className="text-ink-muted">Revoked:</span><span className="font-medium text-red-600">{result.total_revoked}</span>
              <span className="text-ink-muted">Skipped:</span><span className="font-medium text-yellow-600">{result.total_skipped}</span>
              <span className="text-ink-muted">Failed:</span><span className="font-medium text-red-700">{result.total_failed}</span>
            </div>
            {result.errors && result.errors.length > 0 && (
              <div className="mt-2 text-xs text-red-600">
                {result.errors.map((e, i) => <div key={i}>{e.certificate_id}: {e.error}</div>)}
              </div>
            )}
          </div>
        )}
        <label className="text-xs text-ink-muted block mb-2">Revocation Reason (RFC 5280)</label>
        <select value={reason} onChange={e => setReason(e.target.value)}
          className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink mb-4"
          disabled={running || result !== null}
        >
          {REVOCATION_REASONS.map(r => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="btn btn-ghost text-sm">{result ? 'Close' : 'Cancel'}</button>
          {!result && (
            <button onClick={handleRevoke} disabled={running}
              className="btn text-sm bg-red-600 hover:bg-red-500 text-white disabled:opacity-50">
              {running ? 'Revoking...' : `Revoke ${ids.length} Certificates`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function BulkReassignModal({ ids, onClose, onSuccess }: { ids: string[]; onClose: () => void; onSuccess: () => void }) {
  const [ownerId, setOwnerId] = useState('');
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);

  const { data: owners } = useQuery({
    queryKey: ['owners'],
    queryFn: () => getOwners(),
  });

  // L-2 closure (cat-l-8a1fb258a38a): pre-L-2 this looped
  // `await updateCertificate(id, { owner_id })` over the selection
  // (N HTTP round-trips). Post-L-2 it's a single POST to
  // /api/v1/certificates/bulk-reassign. The CI guardrail in
  // .github/workflows/ci.yml (`Forbidden client-side bulk-action loop
  // regression guard (L-1)`) catches reintroduction of the loop shape.
  const handleReassign = async () => {
    if (!ownerId) return;
    setRunning(true);
    setError('');
    setProgress(0);
    try {
      const result = await bulkReassignCertificates({
        certificate_ids: ids,
        owner_id: ownerId,
      });
      setProgress(result.total_reassigned);
      if (result.total_failed > 0) {
        const first = result.errors?.[0];
        setError(
          `${result.total_failed} of ${result.total_matched} failed${
            first ? `: ${first.certificate_id} — ${first.error}` : ''
          }`
        );
      } else {
        onSuccess();
      }
    } catch (err) {
      setError(`Bulk reassignment failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-surface border border-surface-border rounded p-6 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-ink mb-2">Reassign Owner</h2>
        <p className="text-sm text-ink-muted mb-4">
          Reassign {ids.length} certificate{ids.length > 1 ? 's' : ''} to a new owner.
        </p>
        {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded px-3 py-2 text-sm mb-3">{error}</div>}
        {running && (
          <div className="mb-3">
            <div className="flex justify-between text-xs text-ink-muted mb-1">
              <span>Progress</span>
              <span>{progress}/{ids.length}</span>
            </div>
            <div className="w-full bg-surface-border rounded-full h-2">
              <div className="bg-brand-400 h-2 rounded-full transition-all" style={{ width: `${(progress / ids.length) * 100}%` }} />
            </div>
          </div>
        )}
        <label className="text-xs text-ink-muted block mb-2">New Owner</label>
        <select value={ownerId} onChange={e => setOwnerId(e.target.value)}
          className="w-full bg-white border border-surface-border rounded px-3 py-2 text-sm text-ink mb-4"
          disabled={running}
        >
          <option value="">Select owner...</option>
          {owners?.data?.map(o => (
            <option key={o.id} value={o.id}>{o.name} ({o.email})</option>
          ))}
        </select>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="btn btn-ghost text-sm" disabled={running}>Cancel</button>
          <button onClick={handleReassign} disabled={running || !ownerId}
            className="btn btn-primary text-sm disabled:opacity-50">
            {running ? `Reassigning (${progress}/${ids.length})...` : `Reassign ${ids.length} Certificates`}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CertificatesPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  // M-003: bulk revocation is admin-only. The backend rejects non-admin callers
  // with 403, but we also hide the button in the GUI to avoid a misleading
  // affordance. Authoritative gate remains server-side.
  const { admin } = useAuth();
  // M-029 Pass 2 (Audit M-010): filter / sort / pagination state migrated
  // from 9 local useState hooks to useListParams — URL-resident state is
  // deep-linkable, browser-back-correct, and the hook auto-resets page
  // to 1 on filter / sort / pageSize change (preserving the F-1 contract
  // that previously had to be hand-rolled at every onChange site).
  //
  // F-1 closure (cat-e-610251c8f72d) preserved: the 8 operator-facing
  // filters (status / environment / issuer_id / owner_id / profile_id /
  // team_id / expires_before / sort) all flow through filters[] with
  // their existing keys. Default page size stays at 50 to match the
  // pre-migration F-1 baseline (the hook's global default is 25, but
  // the page-level default takes precedence).
  const { params: listParams, setPage, setPageSize, setFilter } = useListParams({ pageSize: 50 });
  const statusFilter = listParams.filters.status ?? '';
  const envFilter = listParams.filters.environment ?? '';
  const issuerFilter = listParams.filters.issuer_id ?? '';
  const ownerFilter = listParams.filters.owner_id ?? '';
  const profileFilter = listParams.filters.profile_id ?? '';
  const teamFilter = listParams.filters.team_id ?? '';
  const expiresBefore = listParams.filters.expires_before ?? '';
  const sortBy = listParams.filters.sort ?? '';
  const page = listParams.page;
  const perPage = listParams.pageSize;
  const [showCreate, setShowCreate] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showBulkRevoke, setShowBulkRevoke] = useState(false);
  const [showBulkReassign, setShowBulkReassign] = useState(false);
  const [bulkRenewProgress, setBulkRenewProgress] = useState<{ done: number; total: number; running: boolean } | null>(null);

  const { data: issuersData } = useQuery({ queryKey: ['issuers-filter'], queryFn: () => getIssuers({ per_page: '100' }) });
  const { data: ownersData } = useQuery({ queryKey: ['owners-filter'], queryFn: () => getOwners({ per_page: '100' }) });
  const { data: profilesData } = useQuery({ queryKey: ['profiles-filter'], queryFn: () => getProfiles({ per_page: '100' }) });
  // F-1 closure: hydrate the team filter dropdown.
  const { data: teamsFilterData } = useQuery({ queryKey: ['teams-filter'], queryFn: () => getTeams({ per_page: '100' }) });

  const params: Record<string, string> = {};
  if (statusFilter)  params.status         = statusFilter;
  if (envFilter)     params.environment    = envFilter;
  if (issuerFilter)  params.issuer_id      = issuerFilter;
  if (ownerFilter)   params.owner_id       = ownerFilter;
  if (profileFilter) params.profile_id     = profileFilter;
  if (teamFilter)    params.team_id        = teamFilter;
  if (expiresBefore) params.expires_before = expiresBefore;
  if (sortBy)        params.sort           = sortBy;
  // Pagination (F-1) — re-fetch on page / per_page change.
  params.page     = String(page);
  params.per_page = String(perPage);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['certificates', params],
    queryFn: () => getCertificates(params),
    refetchInterval: 30000,
  });

  // L-1 closure (cat-l-fa0c1ac07ab5): pre-L-1 this looped
  // `await triggerRenewal(ids[i])` over the selection (N HTTP round-
  // trips × ~50–200ms each = 5–20s wedge for 100 selected certs).
  // Post-L-1 it's a single POST to /api/v1/certificates/bulk-renew;
  // the server resolves the criteria, applies status filters
  // (RenewalInProgress/Revoked/Archived/Expired all silent-skip), and
  // enqueues N renewal jobs server-side, returning a per-cert
  // {certificate_id, job_id} envelope. CI guardrail at
  // .github/workflows/ci.yml catches loop-shape regression.
  const handleBulkRenewal = async () => {
    const ids = Array.from(selectedIds);
    setBulkRenewProgress({ done: 0, total: ids.length, running: true });
    try {
      const result = await bulkRenewCertificates({ certificate_ids: ids });
      setBulkRenewProgress({
        done: result.total_enqueued,
        total: result.total_matched,
        running: false,
      });
    } catch {
      // surface as a "0 of N" terminal state — no retries.
      setBulkRenewProgress({ done: 0, total: ids.length, running: false });
    }
    queryClient.invalidateQueries({ queryKey: ['certificates'] });
    setSelectedIds(new Set());
    setTimeout(() => setBulkRenewProgress(null), 5000);
  };

  const columns: Column<Certificate>[] = [
    {
      key: 'name',
      label: 'Certificate',
      render: (c) => (
        <div>
          <div className="font-medium text-ink">{c.common_name}</div>
          <div className="text-xs text-ink-faint mt-0.5">{c.id}</div>
        </div>
      ),
    },
    { key: 'status', label: 'Status', render: (c) => <StatusBadge status={c.status} /> },
    {
      key: 'expires',
      label: 'Expires',
      render: (c) => {
        const days = daysUntil(c.expires_at);
        return (
          <div>
            <div className={expiryColor(days)}>{formatDate(c.expires_at)}</div>
            <div className="text-xs text-ink-faint">{days <= 0 ? 'Expired' : `${days} days`}</div>
          </div>
        );
      },
    },
    { key: 'last_renewal', label: 'Last Renewal', render: (c) => <span className="text-xs text-ink-muted">{c.last_renewal_at ? formatDate(c.last_renewal_at) : '—'}</span> },
    { key: 'last_deploy', label: 'Last Deploy', render: (c) => <span className="text-xs text-ink-muted">{c.last_deployment_at ? formatDate(c.last_deployment_at) : '—'}</span> },
    { key: 'issuer', label: 'Issuer', render: (c) => <span className="text-ink-muted text-xs">{c.issuer_id}</span> },
    { key: 'owner', label: 'Owner', render: (c) => <span className="text-ink-muted text-xs">{c.owner_id}</span> },
  ];

  const selectedArray = Array.from(selectedIds);
  const hasSelection = selectedArray.length > 0;

  return (
    <>
      <PageHeader
        title="Certificates"
        subtitle={data ? `${data.total} certificates` : undefined}
        action={
          <button onClick={() => setShowCreate(true)} className="btn btn-primary text-xs">
            + New Certificate
          </button>
        }
      />

      {/* Bulk Action Bar */}
      {hasSelection && (
        <div className="px-6 py-3 bg-brand-50 border-b border-brand-200 flex items-center justify-between">
          <span className="text-sm text-brand-600 font-medium">{selectedArray.length} selected</span>
          <div className="flex gap-2">
            <button onClick={handleBulkRenewal} disabled={bulkRenewProgress?.running}
              className="btn btn-primary text-xs disabled:opacity-50">
              {bulkRenewProgress?.running
                ? `Renewing (${bulkRenewProgress.done}/${bulkRenewProgress.total})...`
                : 'Trigger Renewal'}
            </button>
            {admin && (
              <button onClick={() => setShowBulkRevoke(true)}
                className="btn btn-ghost text-xs text-amber-400 hover:text-amber-300 border border-amber-600/50">
                Revoke
              </button>
            )}
            <button onClick={() => setShowBulkReassign(true)}
              className="btn btn-ghost text-xs text-brand-400 hover:text-brand-300 border border-brand-600/50">
              Reassign Owner
            </button>
            <button onClick={() => setSelectedIds(new Set())}
              className="btn btn-ghost text-xs text-ink-muted">
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Bulk Renewal Success */}
      {bulkRenewProgress && !bulkRenewProgress.running && (
        <div className="px-6 py-2 bg-emerald-50 border-b border-emerald-200">
          <span className="text-sm text-emerald-700">
            Triggered renewal for {bulkRenewProgress.done} certificate{bulkRenewProgress.done > 1 ? 's' : ''}.
          </span>
        </div>
      )}

      <div className="px-6 py-3 flex gap-3 border-b border-surface-border/50">
        <select
          value={statusFilter}
          onChange={e => setFilter('status', e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All statuses</option>
          <option value="Active">Active</option>
          <option value="Expiring">Expiring</option>
          <option value="Expired">Expired</option>
          <option value="Revoked">Revoked</option>
          <option value="RenewalInProgress">Renewal In Progress</option>
          <option value="Archived">Archived</option>
        </select>
        <select
          value={envFilter}
          onChange={e => setFilter('environment', e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All environments</option>
          <option value="production">Production</option>
          <option value="staging">Staging</option>
          <option value="development">Development</option>
        </select>
        <select
          value={issuerFilter}
          onChange={e => setFilter('issuer_id', e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All issuers</option>
          {issuersData?.data?.map(i => (
            <option key={i.id} value={i.id}>{i.name}</option>
          ))}
        </select>
        <select
          value={ownerFilter}
          onChange={e => setFilter('owner_id', e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All owners</option>
          {ownersData?.data?.map(o => (
            <option key={o.id} value={o.id}>{o.name}</option>
          ))}
        </select>
        <select
          value={profileFilter}
          onChange={e => setFilter('profile_id', e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All profiles</option>
          {profilesData?.data?.map(p => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
        {/* F-1 closure (cat-e-610251c8f72d): team / expires_before / sort */}
        <select
          value={teamFilter}
          onChange={e => setFilter('team_id', e.target.value)}
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">All teams</option>
          {teamsFilterData?.data?.map(t => (
            <option key={t.id} value={t.id}>{t.name}</option>
          ))}
        </select>
        <input
          type="date"
          value={expiresBefore}
          onChange={e => setFilter('expires_before', e.target.value)}
          title="Expires before (drives the 'expiring in N days' workflow)"
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        />
        <select
          value={sortBy}
          onChange={e => setFilter('sort', e.target.value)}
          title="Sort order"
          className="bg-white border border-surface-border rounded px-3 py-1.5 text-sm text-ink"
        >
          <option value="">Default sort</option>
          <option value="notAfter">Expires soonest</option>
          <option value="-notAfter">Expires latest</option>
          <option value="createdAt">Created earliest</option>
          <option value="-createdAt">Created latest</option>
        </select>
      </div>
      <div className="flex-1 overflow-y-auto">
        {error ? (
          <ErrorState error={error as Error} onRetry={() => refetch()} />
        ) : (
          <DataTable
            columns={columns}
            data={data?.data || []}
            isLoading={isLoading}
            onRowClick={(c) => navigate(`/certificates/${c.id}`)}
            emptyMessage="No certificates found"
            selectable
            selectedKeys={selectedIds}
            onSelectionChange={setSelectedIds}
            pagination={{
              page,
              perPage,
              total: data?.total ?? 0,
              onPageChange: setPage,
              // useListParams.setPageSize auto-drops the page param from
              // the URL (page resets to 1 implicitly), preserving the
              // F-1 contract without a manual setPage(1) call.
              onPerPageChange: setPageSize,
            }}
          />
        )}
      </div>
      {showCreate && (
        <CreateCertificateModal
          onClose={() => setShowCreate(false)}
          onSuccess={() => {
            setShowCreate(false);
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
        />
      )}
      {showBulkRevoke && (
        <BulkRevokeModal
          ids={selectedArray}
          onClose={() => setShowBulkRevoke(false)}
          onSuccess={() => {
            setShowBulkRevoke(false);
            setSelectedIds(new Set());
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
        />
      )}
      {showBulkReassign && (
        <BulkReassignModal
          ids={selectedArray}
          onClose={() => setShowBulkReassign(false)}
          onSuccess={() => {
            setShowBulkReassign(false);
            setSelectedIds(new Set());
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
        />
      )}
    </>
  );
}

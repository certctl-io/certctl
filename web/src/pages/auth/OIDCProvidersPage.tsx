import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  listOIDCProviders,
  createOIDCProvider,
  type OIDCProvider,
  type OIDCProviderRequest,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';
import OIDCTestConnectionPanel from './OIDCTestConnectionPanel';
import { formatDate } from '../../api/utils';

// =============================================================================
// Bundle 2 Phase 8 — OIDCProvidersPage.
//
// Lists every configured OIDC identity provider in the tenant. Each
// row shows id, name, issuer URL, client_id, and a deep-link to the
// provider detail page.
//
// Render-time permission gating:
//   - Page itself requires auth.oidc.list; non-holders see an
//     ErrorState directing them to ask an admin.
//   - "Configure provider" button is HIDDEN unless the caller holds
//     auth.oidc.create (server-side enforcement is still load-bearing).
//
// data-testid attributes flag every interactive element so the future
// E2E suite can assert behaviour without brittle CSS selectors. Same
// pattern as Bundle 1's RolesPage.
// =============================================================================

interface CreateProviderModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

// Audit 2026-05-11 A-3 — validateEmailDomain mirrors the backend
// validator at internal/auth/oidc/domain/types.go (CRIT-5 closure).
// Rejects entries containing `@` / whitespace / `*` / mixed-case, and
// empties. Returns "" on success; a non-empty string on failure (used
// directly as the inline error message). The server is still the
// source of truth; this is the fast-feedback layer.
export function validateEmailDomain(input: string): string {
  if (!input) return 'Empty entry';
  if (input !== input.trim()) return 'Leading or trailing whitespace';
  if (input !== input.toLowerCase()) return 'Must be all lowercase';
  if (input.includes('@')) return 'Entries are domains, not email addresses — drop the "@" and the local part';
  if (input.includes(' ') || /\s/.test(input)) return 'No whitespace';
  if (input.includes('*')) return 'No wildcards — list each subdomain explicitly';
  if (!input.includes('.')) return 'Must be a fully-qualified domain (e.g. acme.com)';
  return '';
}

function CreateProviderModal({ isOpen, onClose, onSuccess }: CreateProviderModalProps) {
  const [form, setForm] = useState<OIDCProviderRequest>({
    name: '',
    issuer_url: '',
    client_id: '',
    client_secret: '',
    redirect_uri: '',
    groups_claim_path: 'groups',
    groups_claim_format: 'string-array',
    fetch_userinfo: false,
    scopes: ['openid', 'profile', 'email'],
    allowed_email_domains: [],
    iat_window_seconds: 300,
    jwks_cache_ttl_seconds: 3600,
  });
  // Audit 2026-05-11 A-3 — chip-input scratch state for the
  // allowed_email_domains tenant-isolation gate. Operators add domains
  // one at a time; each goes through validateEmailDomain before being
  // appended to form.allowed_email_domains.
  const [emailDomainInput, setEmailDomainInput] = useState('');
  const [emailDomainErr, setEmailDomainErr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  if (!isOpen) return null;

  const update = <K extends keyof OIDCProviderRequest>(k: K, v: OIDCProviderRequest[K]) => {
    setForm(prev => ({ ...prev, [k]: v }));
    setDirty(true);
  };

  const addEmailDomain = () => {
    const trimmed = emailDomainInput.trim().toLowerCase();
    setEmailDomainErr(null);
    const v = validateEmailDomain(trimmed);
    if (v !== '') {
      setEmailDomainErr(v);
      return;
    }
    const current = form.allowed_email_domains || [];
    if (current.includes(trimmed)) {
      setEmailDomainErr('Already in the list');
      return;
    }
    update('allowed_email_domains', [...current, trimmed]);
    setEmailDomainInput('');
  };

  const removeEmailDomain = (d: string) => {
    update(
      'allowed_email_domains',
      (form.allowed_email_domains || []).filter(x => x !== d),
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || !form.issuer_url.trim() || !form.client_id.trim() || !form.client_secret) return;
    setSubmitting(true);
    setError(null);
    try {
      await createOIDCProvider(form);
      setDirty(false);
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleClose = () => {
    if (dirty && !window.confirm('Discard unsaved changes?')) return;
    setDirty(false);
    setError(null);
    setEmailDomainInput('');
    setEmailDomainErr(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={handleClose}>
      <div
        className="bg-surface border border-surface-border rounded p-5 w-full max-w-lg shadow-xl max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
        data-testid="create-oidc-provider-modal"
      >
        <h2 className="text-lg font-semibold text-ink mb-4">Configure OIDC provider</h2>
        {error && (
          <div
            className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
            data-testid="create-oidc-provider-error"
          >
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Display name *</label>
            <input
              value={form.name}
              onChange={e => update('name', e.target.value)}
              className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
              required
              data-testid="oidc-provider-name-input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Issuer URL *</label>
            <input
              type="url"
              value={form.issuer_url}
              onChange={e => update('issuer_url', e.target.value)}
              placeholder="https://idp.example.com/realm/main"
              className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
              required
              data-testid="oidc-provider-issuer-url-input"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Client ID *</label>
              <input
                value={form.client_id}
                onChange={e => update('client_id', e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                required
                data-testid="oidc-provider-client-id-input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Client secret *</label>
              <input
                type="password"
                value={form.client_secret}
                onChange={e => update('client_secret', e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                required
                data-testid="oidc-provider-client-secret-input"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-ink mb-1">Redirect URI *</label>
            <input
              type="url"
              value={form.redirect_uri}
              onChange={e => update('redirect_uri', e.target.value)}
              placeholder="https://certctl.example.com/auth/oidc/callback"
              className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
              required
              data-testid="oidc-provider-redirect-uri-input"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Groups claim path</label>
              <input
                value={form.groups_claim_path}
                onChange={e => update('groups_claim_path', e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-groups-claim-path-input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Groups claim format</label>
              <select
                value={form.groups_claim_format}
                onChange={e => update('groups_claim_format', e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-groups-claim-format-select"
              >
                <option value="string-array">string-array</option>
                <option value="json-path">json-path</option>
              </select>
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={form.fetch_userinfo || false}
              onChange={e => update('fetch_userinfo', e.target.checked)}
              data-testid="oidc-provider-fetch-userinfo-checkbox"
            />
            <span>Fetch groups from userinfo endpoint when ID token claim is empty</span>
          </label>
          {/* Audit 2026-05-11 A-3 — Allowed email domains chip control.
              When the list is non-empty, only users whose email-domain
              matches one of these entries can complete OIDC login. For
              multi-tenant IdPs (Auth0, Azure AD common endpoint, Google
              Workspace) this is the only thing preventing cross-tenant
              logins; the CRIT-5 backend gate is load-bearing but the GUI
              never exposed it until this fix. */}
          <div>
            <label className="block text-sm font-medium text-ink mb-1">
              Allowed email domains (optional)
            </label>
            <p className="text-xs text-ink-muted mb-2">
              When non-empty, only users whose email domain exactly matches one of these entries
              can log in. Subdomains are NOT auto-accepted — list each one explicitly. Empty list
              means any domain. Case-insensitive exact match.
            </p>
            {(form.allowed_email_domains || []).length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2" data-testid="oidc-create-allowed-email-domains-chips">
                {(form.allowed_email_domains || []).map(d => (
                  <span
                    key={d}
                    className="inline-flex items-center gap-1 px-2 py-0.5 text-xs bg-page border border-surface-border rounded text-ink font-mono"
                    data-testid={`oidc-create-allowed-email-domain-chip-${d}`}
                  >
                    {d}
                    <button
                      type="button"
                      onClick={() => removeEmailDomain(d)}
                      className="text-ink-muted hover:text-red-600 leading-none"
                      aria-label={`Remove ${d}`}
                      data-testid={`oidc-create-allowed-email-domain-chip-remove-${d}`}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <input
                type="text"
                value={emailDomainInput}
                onChange={e => {
                  setEmailDomainInput(e.target.value);
                  if (emailDomainErr) setEmailDomainErr(null);
                }}
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addEmailDomain();
                  }
                }}
                placeholder="acme.com"
                className="flex-1 px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-create-allowed-email-domains-input"
              />
              <button
                type="button"
                onClick={addEmailDomain}
                className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
                data-testid="oidc-create-allowed-email-domains-add"
              >
                Add
              </button>
            </div>
            {emailDomainErr && (
              <p
                className="mt-1 text-xs text-red-700"
                data-testid="oidc-create-allowed-email-domains-error"
              >
                {emailDomainErr}
              </p>
            )}
          </div>
          {/* Audit 2026-05-11 Fix 09 — Test Connection panel (MED-5 GUI half).
              Dry-run the issuer URL + JWKS reachability + alg-downgrade defense
              against MED-5's POST /api/v1/auth/oidc/test. Renders inline so the
              operator sees the result before committing. */}
          <OIDCTestConnectionPanel
            issuerURL={form.issuer_url}
            clientID={form.client_id}
            scopes={form.scopes || []}
            testIDSuffix="create"
          />
          <div className="flex justify-end gap-2 pt-3">
            <button
              type="button"
              onClick={handleClose}
              className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
              data-testid="create-oidc-provider-cancel"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1.5 text-sm bg-brand-600 text-white rounded hover:bg-brand-700 disabled:opacity-50"
              data-testid="create-oidc-provider-submit"
            >
              {submitting ? 'Creating…' : 'Create provider'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function OIDCProvidersPage() {
  const { hasPerm } = useAuthMe();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const canList = hasPerm('auth.oidc.list');
  const canCreate = hasPerm('auth.oidc.create');

  const { data, isLoading, error } = useQuery({
    queryKey: ['oidc-providers'],
    queryFn: listOIDCProviders,
    enabled: canList,
  });

  if (!canList) {
    return (
      <div className="p-8">
        <PageHeader title="OIDC providers" subtitle="Identity provider configuration" />
        <ErrorState error={new Error("You need the auth.oidc.list permission to view OIDC providers. Ask an administrator to grant the permission to your role.")} />
      </div>
    );
  }

  return (
    <div className="p-8">
      <PageHeader
        title="OIDC providers"
        subtitle="Identity provider configuration"
        action={
          canCreate && (
            <button
              onClick={() => setShowCreate(true)}
              className="px-3 py-1.5 text-sm bg-brand-600 text-white rounded hover:bg-brand-700"
              data-testid="oidc-providers-create-button"
            >
              Configure provider
            </button>
          )
        }
      />

      {isLoading && (
        <div className="text-sm text-ink-muted" data-testid="oidc-providers-loading">
          Loading providers…
        </div>
      )}
      {error && <ErrorState error={error instanceof Error ? error : new Error(String(error))} />}

      {data && data.providers.length === 0 && (
        <div className="bg-surface border border-surface-border rounded p-6 text-center" data-testid="oidc-providers-empty">
          <p className="text-ink-muted text-sm">
            No OIDC providers configured.{' '}
            {canCreate ? 'Click "Configure provider" to add one.' : 'Ask an administrator to configure one.'}
          </p>
        </div>
      )}

      {data && data.providers.length > 0 && (
        <div className="bg-surface border border-surface-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-page border-b border-surface-border">
              <tr>
                <th className="text-left px-4 py-2 font-medium text-ink">Name</th>
                <th className="text-left px-4 py-2 font-medium text-ink">Issuer URL</th>
                <th className="text-left px-4 py-2 font-medium text-ink">Client ID</th>
                <th className="text-left px-4 py-2 font-medium text-ink">Created</th>
              </tr>
            </thead>
            <tbody>
              {data.providers.map((p: OIDCProvider) => (
                <tr key={p.id} className="border-b border-surface-border hover:bg-page" data-testid={`oidc-provider-row-${p.id}`}>
                  <td className="px-4 py-2">
                    <Link
                      to={`/auth/oidc/providers/${encodeURIComponent(p.id)}`}
                      className="text-brand-600 hover:underline"
                      data-testid={`oidc-provider-link-${p.id}`}
                    >
                      {p.name}
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-ink-muted font-mono text-xs">{p.issuer_url}</td>
                  <td className="px-4 py-2 text-ink-muted font-mono text-xs">{p.client_id}</td>
                  <td className="px-4 py-2 text-ink-muted">
                    {formatDate(p.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <CreateProviderModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => {
          setShowCreate(false);
          queryClient.invalidateQueries({ queryKey: ['oidc-providers'] });
        }}
      />
    </div>
  );
}

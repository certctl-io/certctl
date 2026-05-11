import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  listOIDCProviders,
  updateOIDCProvider,
  deleteOIDCProvider,
  refreshOIDCProvider,
  type OIDCProvider,
} from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';
import PageHeader from '../../components/PageHeader';
import ErrorState from '../../components/ErrorState';
import { validateEmailDomain } from './OIDCProvidersPage';

// =============================================================================
// Bundle 2 Phase 8 — OIDCProviderDetailPage.
//
// One row per provider — edit (PUT), delete (DELETE), and refresh
// discovery cache (POST .../refresh). Edit modal shares the create-
// modal field set; the client_secret field is OPTIONAL on edit (empty
// preserves the existing ciphertext on the server). Delete is gated
// behind a typed-confirmation dialog AND surfaces 409 Conflict (the
// server's ErrOIDCProviderInUse) as a non-destructive error so the
// operator knows to revoke active sessions first. Refresh discovery
// cache fires the server's RefreshKeys → re-runs the IdP downgrade-
// attack defense AND re-fetches JWKS; common operator action when an
// IdP rotates keys mid-day.
//
// Permission gates: the page itself requires auth.oidc.list. Edit
// and refresh require auth.oidc.edit. Delete requires
// auth.oidc.delete. Mappings link is rendered for any caller with
// auth.oidc.list.
// =============================================================================

export default function OIDCProviderDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { hasPerm } = useAuthMe();

  const canList = hasPerm('auth.oidc.list');
  const canEdit = hasPerm('auth.oidc.edit');
  const canDelete = hasPerm('auth.oidc.delete');

  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState('');
  const [editIssuerURL, setEditIssuerURL] = useState('');
  const [editClientID, setEditClientID] = useState('');
  const [editClientSecret, setEditClientSecret] = useState('');
  const [editRedirectURI, setEditRedirectURI] = useState('');
  const [editFetchUserinfo, setEditFetchUserinfo] = useState(false);
  // Audit 2026-05-11 A-3 — pre-populated from provider.allowed_email_domains
  // at startEdit time; saved back through the PUT body. Empty list ↔ no gate.
  const [editAllowedEmailDomains, setEditAllowedEmailDomains] = useState<string[]>([]);
  const [emailDomainInput, setEmailDomainInput] = useState('');
  const [emailDomainErr, setEmailDomainErr] = useState<string | null>(null);
  // Audit 2026-05-11 A-7 — Advanced edit fields. Pre-fix, the saveEdit
  // handler passed these through unchanged from the provider object,
  // so the read-only `<dl>` claimed the value was editable but the
  // PUT body never carried operator input. The 5 fields the backend
  // validator accepts (internal/auth/oidc/domain/types.go::Validate):
  //   - scopes (string array; min 1 entry; default openid profile email)
  //   - groups_claim_path (string; default "groups")
  //   - groups_claim_format (enum: string-array | json-path)
  //   - iat_window_seconds (int, 1–600; default 300)
  //   - jwks_cache_ttl_seconds (int, ≥60; default 3600)
  // Scopes are rendered as a space-separated text input (single-line)
  // because that's the operator's mental model — every OIDC IdP docs
  // page shows scopes as space-separated. The submit handler splits on
  // whitespace + filters empty strings; an empty input renders an
  // inline error rather than wiping the array.
  const [editScopesInput, setEditScopesInput] = useState('');
  const [editGroupsClaimPath, setEditGroupsClaimPath] = useState('');
  const [editGroupsClaimFormat, setEditGroupsClaimFormat] = useState('string-array');
  const [editIATWindow, setEditIATWindow] = useState<number>(300);
  const [editJWKSCacheTTL, setEditJWKSCacheTTL] = useState<number>(3600);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  const { data, isLoading, error: loadErr } = useQuery({
    queryKey: ['oidc-providers'],
    queryFn: listOIDCProviders,
    enabled: canList,
  });

  if (!canList) {
    return (
      <div className="p-8">
        <PageHeader title="OIDC provider" subtitle="Identity provider configuration" />
        <ErrorState error={new Error("You need the auth.oidc.list permission to view OIDC providers.")} />
      </div>
    );
  }

  const provider: OIDCProvider | undefined = data?.providers.find(p => p.id === id);

  if (isLoading) {
    return <div className="p-8 text-sm text-ink-muted" data-testid="oidc-provider-detail-loading">Loading…</div>;
  }
  if (loadErr || !provider) {
    return (
      <div className="p-8">
        <PageHeader title="OIDC provider" subtitle="Identity provider configuration" />
        <ErrorState error={loadErr instanceof Error ? loadErr : new Error("Provider not found")} />
        <Link to="/auth/oidc/providers" className="text-sm text-brand-600 hover:underline">
          ← Back to providers
        </Link>
      </div>
    );
  }

  const startEdit = () => {
    setEditName(provider.name);
    setEditIssuerURL(provider.issuer_url);
    setEditClientID(provider.client_id);
    setEditClientSecret('');
    setEditRedirectURI(provider.redirect_uri);
    setEditFetchUserinfo(provider.fetch_userinfo || false);
    // Audit 2026-05-11 A-3 — clone so chip-mutations don't reach
    // through into the cached query data and re-render every row that
    // shares the reference.
    setEditAllowedEmailDomains([...(provider.allowed_email_domains || [])]);
    setEmailDomainInput('');
    setEmailDomainErr(null);
    // Audit 2026-05-11 A-7 — pre-populate the Advanced fields from
    // the live provider so the operator sees the current values when
    // they expand the section.
    setEditScopesInput((provider.scopes ?? []).join(' '));
    setEditGroupsClaimPath(provider.groups_claim_path || 'groups');
    setEditGroupsClaimFormat(provider.groups_claim_format || 'string-array');
    setEditIATWindow(provider.iat_window_seconds || 300);
    setEditJWKSCacheTTL(provider.jwks_cache_ttl_seconds || 3600);
    setError(null);
    setSuccess(null);
    setEditing(true);
  };

  const cancelEdit = () => {
    setEditing(false);
    setEmailDomainInput('');
    setEmailDomainErr(null);
    setError(null);
  };

  // Audit 2026-05-11 A-3 — mirror of OIDCProvidersPage::addEmailDomain.
  const addEmailDomain = () => {
    const trimmed = emailDomainInput.trim().toLowerCase();
    setEmailDomainErr(null);
    const v = validateEmailDomain(trimmed);
    if (v !== '') {
      setEmailDomainErr(v);
      return;
    }
    if (editAllowedEmailDomains.includes(trimmed)) {
      setEmailDomainErr('Already in the list');
      return;
    }
    setEditAllowedEmailDomains([...editAllowedEmailDomains, trimmed]);
    setEmailDomainInput('');
  };

  const removeEmailDomain = (d: string) => {
    setEditAllowedEmailDomains(editAllowedEmailDomains.filter(x => x !== d));
  };

  const clearAllEmailDomains = () => {
    if (editAllowedEmailDomains.length === 0) return;
    if (!window.confirm(
      'Clear ALL allowed email domains?\n\n' +
      'After saving, ANY user with a valid OIDC token from this provider can log in. ' +
      'For multi-tenant IdPs (Auth0, Azure AD common, Google Workspace) this means cross-tenant ' +
      'logins are no longer blocked. Confirm only if that is intended.',
    )) return;
    setEditAllowedEmailDomains([]);
  };

  const saveEdit = async () => {
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      // Audit 2026-05-11 A-7 — client-side validation mirrors the
      // backend's internal/auth/oidc/domain/types.go::Validate rules.
      // Server is still the source of truth (we surface its 400 if
      // anything slips past); the client validator is for fast
      // feedback so operators don't round-trip just to learn that
      // "iat_window_seconds=601" is rejected.
      const trimmedPath = editGroupsClaimPath.trim();
      if (trimmedPath === '') {
        setError('Groups claim path cannot be empty (default: "groups").');
        setSubmitting(false);
        return;
      }
      if (editGroupsClaimFormat !== 'string-array' && editGroupsClaimFormat !== 'json-path') {
        setError('Groups claim format must be "string-array" or "json-path".');
        setSubmitting(false);
        return;
      }
      const scopes = editScopesInput
        .trim()
        .split(/\s+/)
        .filter(s => s.length > 0);
      if (scopes.length === 0) {
        setError('Scopes cannot be empty. At minimum include "openid".');
        setSubmitting(false);
        return;
      }
      if (!Number.isInteger(editIATWindow) || editIATWindow <= 0 || editIATWindow > 600) {
        setError('IAT window must be a positive integer ≤ 600 seconds.');
        setSubmitting(false);
        return;
      }
      if (!Number.isInteger(editJWKSCacheTTL) || editJWKSCacheTTL < 60) {
        setError('JWKS cache TTL must be an integer ≥ 60 seconds.');
        setSubmitting(false);
        return;
      }

      const req: Parameters<typeof updateOIDCProvider>[1] = {
        name: editName,
        issuer_url: editIssuerURL,
        client_id: editClientID,
        redirect_uri: editRedirectURI,
        // Audit 2026-05-11 A-7 — formerly pass-through from
        // provider.*, now wired to the operator-edited state. Lying
        // UX retired: the read-only `<dl>` no longer claims a value
        // can be changed when the saveEdit handler ignores the
        // change.
        groups_claim_path: trimmedPath,
        groups_claim_format: editGroupsClaimFormat,
        fetch_userinfo: editFetchUserinfo,
        scopes,
        // Audit 2026-05-11 A-3 — wire the chip-list value into the PUT
        // body. Backend persists [] as no-gate; the field is honest now.
        allowed_email_domains: editAllowedEmailDomains,
        iat_window_seconds: editIATWindow,
        jwks_cache_ttl_seconds: editJWKSCacheTTL,
      };
      if (editClientSecret) req.client_secret = editClientSecret;
      await updateOIDCProvider(provider.id, req);
      setSuccess('Provider updated');
      setEditing(false);
      queryClient.invalidateQueries({ queryKey: ['oidc-providers'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const doRefresh = async () => {
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      await refreshOIDCProvider(provider.id);
      setSuccess('Discovery + JWKS refreshed; IdP downgrade defense re-run');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const doDelete = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await deleteOIDCProvider(provider.id);
      navigate('/auth/oidc/providers');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSubmitting(false);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <PageHeader
        title={provider.name}
        subtitle={`OIDC provider · ${provider.id}`}
        action={
          <Link to="/auth/oidc/providers" className="text-sm text-brand-600 hover:underline">
            ← All providers
          </Link>
        }
      />

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700" data-testid="oidc-provider-detail-error">
          {error}
        </div>
      )}
      {success && (
        <div className="p-3 bg-green-50 border border-green-200 rounded text-sm text-green-700" data-testid="oidc-provider-detail-success">
          {success}
        </div>
      )}

      <div className="bg-surface border border-surface-border rounded p-5 space-y-4">
        <h2 className="text-base font-semibold text-ink">Configuration</h2>
        {!editing ? (
          <dl className="grid grid-cols-3 gap-y-2 text-sm">
            <dt className="text-ink-muted col-span-1">Issuer URL</dt>
            <dd className="col-span-2 font-mono text-xs">{provider.issuer_url}</dd>
            <dt className="text-ink-muted col-span-1">Client ID</dt>
            <dd className="col-span-2 font-mono text-xs">{provider.client_id}</dd>
            <dt className="text-ink-muted col-span-1">Redirect URI</dt>
            <dd className="col-span-2 font-mono text-xs">{provider.redirect_uri}</dd>
            <dt className="text-ink-muted col-span-1">Groups claim</dt>
            <dd className="col-span-2 font-mono text-xs">
              {provider.groups_claim_path} ({provider.groups_claim_format})
            </dd>
            <dt className="text-ink-muted col-span-1">Userinfo fallback</dt>
            <dd className="col-span-2">{provider.fetch_userinfo ? 'enabled' : 'disabled'}</dd>
            <dt className="text-ink-muted col-span-1">Scopes</dt>
            <dd className="col-span-2 font-mono text-xs">{(provider.scopes || []).join(', ')}</dd>
            {/* Audit 2026-05-11 A-3 — tenant-isolation gate. Was lying-field
                pre-fix: persisted + enforced, but never shown in the GUI. */}
            <dt className="text-ink-muted col-span-1">Allowed email domains</dt>
            <dd className="col-span-2" data-testid="oidc-provider-detail-allowed-email-domains">
              {(provider.allowed_email_domains || []).length === 0 ? (
                <span className="text-ink-muted italic">any (no gate configured)</span>
              ) : (
                <div className="flex flex-wrap gap-1">
                  {(provider.allowed_email_domains || []).map(d => (
                    <span
                      key={d}
                      className="inline-flex items-center px-2 py-0.5 text-xs bg-page border border-surface-border rounded text-ink font-mono"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              )}
            </dd>
            <dt className="text-ink-muted col-span-1">IAT window</dt>
            <dd className="col-span-2">{provider.iat_window_seconds}s</dd>
            {/* Audit 2026-05-11 A-7 — JWKS cache TTL surfaced in
                read-only view too (pre-fix the value was persisted but
                invisible). */}
            <dt className="text-ink-muted col-span-1">JWKS cache TTL</dt>
            <dd className="col-span-2">{provider.jwks_cache_ttl_seconds}s</dd>
          </dl>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Display name</label>
              <input
                value={editName}
                onChange={e => setEditName(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Issuer URL</label>
              <input
                value={editIssuerURL}
                onChange={e => setEditIssuerURL(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-issuer-url"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Client ID</label>
              <input
                value={editClientID}
                onChange={e => setEditClientID(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-client-id"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">
                Client secret (leave blank to keep current)
              </label>
              <input
                type="password"
                value={editClientSecret}
                onChange={e => setEditClientSecret(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-client-secret"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Redirect URI</label>
              <input
                value={editRedirectURI}
                onChange={e => setEditRedirectURI(e.target.value)}
                className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                data-testid="oidc-provider-edit-redirect-uri"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-ink">
              <input
                type="checkbox"
                checked={editFetchUserinfo}
                onChange={e => setEditFetchUserinfo(e.target.checked)}
                data-testid="oidc-provider-edit-fetch-userinfo"
              />
              <span>Fetch groups from userinfo endpoint when ID token claim is empty</span>
            </label>
            {/* Audit 2026-05-11 A-3 — Edit form chip control. Mirrors the
                create-modal copy; pre-populates from
                provider.allowed_email_domains at startEdit time. */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-sm font-medium text-ink">
                  Allowed email domains
                </label>
                {editAllowedEmailDomains.length > 0 && (
                  <button
                    type="button"
                    onClick={clearAllEmailDomains}
                    className="text-xs text-red-700 hover:underline"
                    data-testid="oidc-provider-edit-allowed-email-domains-clear-all"
                  >
                    Clear all
                  </button>
                )}
              </div>
              <p className="text-xs text-ink-muted mb-2">
                When non-empty, only users whose email domain exactly matches one of these entries
                can log in. Subdomains are NOT auto-accepted — list each one explicitly. Empty list
                means any domain. Case-insensitive exact match.
              </p>
              {editAllowedEmailDomains.length > 0 && (
                <div
                  className="flex flex-wrap gap-1 mb-2"
                  data-testid="oidc-provider-edit-allowed-email-domains-chips"
                >
                  {editAllowedEmailDomains.map(d => (
                    <span
                      key={d}
                      className="inline-flex items-center gap-1 px-2 py-0.5 text-xs bg-page border border-surface-border rounded text-ink font-mono"
                      data-testid={`oidc-provider-edit-allowed-email-domain-chip-${d}`}
                    >
                      {d}
                      <button
                        type="button"
                        onClick={() => removeEmailDomain(d)}
                        className="text-ink-muted hover:text-red-600 leading-none"
                        aria-label={`Remove ${d}`}
                        data-testid={`oidc-provider-edit-allowed-email-domain-chip-remove-${d}`}
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
                  data-testid="oidc-provider-edit-allowed-email-domains-input"
                />
                <button
                  type="button"
                  onClick={addEmailDomain}
                  className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
                  data-testid="oidc-provider-edit-allowed-email-domains-add"
                >
                  Add
                </button>
              </div>
              {emailDomainErr && (
                <p
                  className="mt-1 text-xs text-red-700"
                  data-testid="oidc-provider-edit-allowed-email-domains-error"
                >
                  {emailDomainErr}
                </p>
              )}
            </div>

            {/* Audit 2026-05-11 A-7 — Advanced section. Five fields the
                read-only <dl> claimed were editable but the saveEdit
                handler was passing through unchanged from the loaded
                provider object. Each input has an inline help line that
                links the operator's mental model to the backend
                semantic (`internal/auth/oidc/domain/types.go::Validate`
                rules). The section is collapsed by default — most
                edits don't touch these fields, so they shouldn't
                clutter the primary form. */}
            <details
              className="border border-surface-border rounded p-3 bg-page"
              data-testid="oidc-provider-edit-advanced"
            >
              <summary className="cursor-pointer text-sm font-medium text-ink select-none">
                Advanced (scopes, groups claim, IAT / JWKS TTL)
              </summary>
              <div className="mt-3 space-y-3">
                <div>
                  <label className="block text-sm font-medium text-ink mb-1">
                    Scopes (space-separated)
                  </label>
                  <input
                    type="text"
                    value={editScopesInput}
                    onChange={e => setEditScopesInput(e.target.value)}
                    placeholder="openid profile email"
                    className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink font-mono"
                    data-testid="oidc-provider-edit-scopes"
                  />
                  <p className="text-xs text-ink-muted mt-1">
                    Default <code>openid profile email</code>. Some IdPs need <code>groups</code> for
                    the group-claim path; Auth0 namespaces groups under a custom claim. Must include{' '}
                    <code>openid</code>.
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-ink mb-1">
                      Groups claim path
                    </label>
                    <input
                      type="text"
                      value={editGroupsClaimPath}
                      onChange={e => setEditGroupsClaimPath(e.target.value)}
                      placeholder="groups"
                      className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink font-mono"
                      data-testid="oidc-provider-edit-groups-claim-path"
                    />
                    <p className="text-xs text-ink-muted mt-1">
                      JSON path within the ID token (or userinfo if fallback enabled) that holds the
                      group list. Common: <code>groups</code>, <code>realm_access.roles</code>
                      {' '}(Keycloak), namespaced URLs (Auth0).
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-ink mb-1">
                      Groups claim format
                    </label>
                    <select
                      value={editGroupsClaimFormat}
                      onChange={e => setEditGroupsClaimFormat(e.target.value)}
                      className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                      data-testid="oidc-provider-edit-groups-claim-format"
                    >
                      <option value="string-array">string-array (default)</option>
                      <option value="json-path">json-path</option>
                    </select>
                    <p className="text-xs text-ink-muted mt-1">
                      How the IdP encodes the group list. Most IdPs emit a JSON array — keep the
                      default. Use <code>json-path</code> when the claim is a nested object the
                      path needs to traverse.
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-ink mb-1">
                      IAT window (seconds)
                    </label>
                    <input
                      type="number"
                      min={1}
                      max={600}
                      value={editIATWindow}
                      onChange={e => setEditIATWindow(Number(e.target.value))}
                      className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                      data-testid="oidc-provider-edit-iat-window-seconds"
                    />
                    <p className="text-xs text-ink-muted mt-1">
                      Maximum ID-token age at consume time (RFC 7519 §4.1.6). Default 300. Range
                      1–600. Tighter = more replay-resistant; looser = more clock-skew-tolerant.
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-ink mb-1">
                      JWKS cache TTL (seconds)
                    </label>
                    <input
                      type="number"
                      min={60}
                      value={editJWKSCacheTTL}
                      onChange={e => setEditJWKSCacheTTL(Number(e.target.value))}
                      className="w-full px-3 py-1.5 text-sm border border-surface-border rounded bg-page text-ink"
                      data-testid="oidc-provider-edit-jwks-cache-ttl-seconds"
                    />
                    <p className="text-xs text-ink-muted mt-1">
                      How long to cache the IdP's signing-key set before re-fetching. Default 3600
                      (1h); floor 60. MED-6 auto-refresh-on-cache-miss covers most rotation events;
                      this knob is for slow-rotation IdPs that want longer caching.
                    </p>
                  </div>
                </div>
              </div>
            </details>
          </div>
        )}
      </div>

      <div className="bg-surface border border-surface-border rounded p-5 space-y-3">
        <h2 className="text-base font-semibold text-ink">Actions</h2>
        <div className="flex flex-wrap gap-2">
          {canEdit && !editing && (
            <button
              onClick={startEdit}
              className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
              data-testid="oidc-provider-edit-button"
            >
              Edit
            </button>
          )}
          {editing && (
            <>
              <button
                onClick={saveEdit}
                disabled={submitting}
                className="px-3 py-1.5 text-sm bg-brand-600 text-white rounded hover:bg-brand-700 disabled:opacity-50"
                data-testid="oidc-provider-save-button"
              >
                {submitting ? 'Saving…' : 'Save'}
              </button>
              <button
                onClick={cancelEdit}
                className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
                data-testid="oidc-provider-cancel-edit-button"
              >
                Cancel
              </button>
            </>
          )}
          {canEdit && (
            <button
              onClick={doRefresh}
              disabled={submitting}
              className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink disabled:opacity-50"
              data-testid="oidc-provider-refresh-button"
              title="Re-fetch IdP discovery doc + JWKS; re-runs IdP downgrade defense"
            >
              Refresh discovery cache
            </button>
          )}
          <Link
            to={`/auth/oidc/providers/${encodeURIComponent(provider.id)}/mappings`}
            className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
            data-testid="oidc-provider-mappings-link"
          >
            Group → role mappings
          </Link>
          {canDelete && !confirmDelete && (
            <button
              onClick={() => setConfirmDelete(true)}
              className="ml-auto px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700"
              data-testid="oidc-provider-delete-button"
            >
              Delete
            </button>
          )}
        </div>

        {confirmDelete && (
          <div className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-800" data-testid="oidc-provider-delete-confirm">
            <p className="mb-2">
              Type <span className="font-mono font-semibold">{provider.name}</span> to confirm deletion.
              Deletion is refused (HTTP 409) when any user has authenticated via this provider; revoke
              their sessions first.
            </p>
            <div className="flex gap-2">
              <input
                value={deleteConfirmText}
                onChange={e => setDeleteConfirmText(e.target.value)}
                className="flex-1 px-2 py-1 text-sm border border-red-300 rounded bg-white"
                data-testid="oidc-provider-delete-confirm-input"
              />
              <button
                onClick={doDelete}
                disabled={submitting || deleteConfirmText !== provider.name}
                className="px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50"
                data-testid="oidc-provider-delete-confirm-button"
              >
                {submitting ? 'Deleting…' : 'Delete provider'}
              </button>
              <button
                onClick={() => {
                  setConfirmDelete(false);
                  setDeleteConfirmText('');
                }}
                className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink"
                data-testid="oidc-provider-delete-cancel-button"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

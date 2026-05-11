import { useState } from 'react';
import { authOIDCTestProvider, type TestDiscoveryResult } from '../../api/client';

// =============================================================================
// Audit 2026-05-11 Fix 09 — Test Connection panel (MED-5 GUI half).
//
// MED-5 backend (`POST /api/v1/auth/oidc/test`, commit 00bbef7) shipped
// the dry-run discovery + JWKS-reachability + alg-downgrade-defense probe
// behind `authOIDCTestProvider` in the API client, but no caller existed
// in the UI. Operators had to complete the create form blind, save, then
// click "Refresh" to discover whether the issuer URL worked; failures
// left a broken provider row in the DB that had to be deleted before
// retrying. This panel surfaces the dry-run result before commit.
//
// Embedded above the Submit button on both the OIDCProvidersPage create
// modal and the OIDCProviderDetailPage edit form. The component does
// NOT persist anything — it's a pure read-only probe against the
// configured issuer URL + client ID + scopes. Errors render inline; the
// operator decides whether to proceed with the save.
//
// Why each line matters:
//   - discovery_succeeded — did the well-known JSON fetch + parse?
//   - jwks_reachable — does the advertised jwks_uri respond?
//   - supported_alg_values — early warning if the IdP advertises only
//     HS-family algs (RFC 7515 §A.2 / §A.3); the backend rejects these
//     at create-time too, but seeing it here saves a round-trip.
//   - iss_param_supported — RFC 9207 advertisement check. Informational
//     only (the spec is a SHOULD, not a MUST); rendered as `·`, not ✗.
//   - userinfo_endpoint — useful to see when fetch_userinfo is
//     configured; absence means the IdP doesn't expose the endpoint at
//     all (some custom OIDC servers omit it).
//   - errors — backend-collected detail; one line per error.
// =============================================================================

interface Props {
  issuerURL: string;
  clientID: string;
  /** Optional. Backend defaults to ['openid'] when empty; the panel
   * passes whatever the caller has staged so a test against an IdP
   * with custom scope requirements (e.g. Azure AD's `.default`) can
   * verify reachability with the real scope set. */
  scopes: string[];
  /** Optional caller-supplied data-testid suffix so the same panel
   * can render twice on the same page (e.g. create vs edit) without
   * colliding test IDs. Defaults to `default`. */
  testIDSuffix?: string;
}

export default function OIDCTestConnectionPanel({
  issuerURL,
  clientID,
  scopes,
  testIDSuffix = 'default',
}: Props) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<TestDiscoveryResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const trimmedIssuer = issuerURL.trim();

  async function run() {
    if (!trimmedIssuer) {
      // Defensive — the button is disabled when issuerURL is empty,
      // but a programmatic click still goes through the same gate.
      setErr('Issuer URL is required before testing.');
      return;
    }
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const r = await authOIDCTestProvider({
        issuer_url: trimmedIssuer,
        client_id: clientID,
        scopes,
      });
      setResult(r);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const tid = (s: string) => `oidc-test-connection-${s}-${testIDSuffix}`;

  return (
    <div
      className="border border-surface-border rounded p-3 my-3"
      data-testid={tid('panel')}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1">
          <div className="font-semibold text-sm text-ink">Test connection</div>
          <div className="text-xs text-ink-muted">
            Dry-run OIDC discovery + JWKS reachability + alg-downgrade defense.
            Does NOT persist; safe to run repeatedly before saving.
          </div>
        </div>
        <button
          type="button"
          onClick={run}
          disabled={busy || !trimmedIssuer}
          className="px-3 py-1.5 text-sm border border-surface-border rounded bg-page hover:bg-surface text-ink disabled:opacity-50 whitespace-nowrap"
          data-testid={tid('run')}
        >
          {busy ? 'Running…' : 'Run test'}
        </button>
      </div>
      {err && (
        <div
          className="mt-2 text-xs text-red-700"
          data-testid={tid('error')}
        >
          {err}
        </div>
      )}
      {result && (
        <ul
          className="mt-3 text-xs space-y-1 text-ink"
          data-testid={tid('result')}
        >
          <li data-testid={tid('check-discovery')}>
            {result.discovery_succeeded ? '✓' : '✗'} Discovery fetched
            {result.issuer_echo ? ` (issuer echoes: ${result.issuer_echo})` : ''}
          </li>
          <li data-testid={tid('check-jwks')}>
            {result.jwks_reachable ? '✓' : '✗'} JWKS reachable
            {result.jwks_uri ? ` (${result.jwks_uri})` : ' (no jwks_uri advertised)'}
          </li>
          <li data-testid={tid('check-algs')}>
            {(result.supported_alg_values?.length ?? 0) > 0 ? '✓' : '⚠'} Supported algs:{' '}
            <code className="font-mono">
              {(result.supported_alg_values ?? []).join(', ') || '(none advertised)'}
            </code>
          </li>
          <li data-testid={tid('check-iss-param')}>
            {result.iss_param_supported ? '✓' : '·'} RFC 9207 iss parameter advertised:{' '}
            {result.iss_param_supported ? 'yes' : 'no (informational — spec is SHOULD)'}
          </li>
          {result.authorization_url && (
            <li className="text-ink-muted" data-testid={tid('detail-authz-url')}>
              · Authorization URL: <code className="font-mono">{result.authorization_url}</code>
            </li>
          )}
          {result.token_url && (
            <li className="text-ink-muted" data-testid={tid('detail-token-url')}>
              · Token URL: <code className="font-mono">{result.token_url}</code>
            </li>
          )}
          {result.userinfo_endpoint && (
            <li className="text-ink-muted" data-testid={tid('detail-userinfo-url')}>
              · UserInfo endpoint: <code className="font-mono">{result.userinfo_endpoint}</code>
            </li>
          )}
          {(result.errors ?? []).length > 0 && (
            <li className="text-red-700 mt-2" data-testid={tid('errors-list')}>
              <strong>Errors ({result.errors!.length}):</strong>
              <ul className="ml-4 list-disc">
                {result.errors!.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

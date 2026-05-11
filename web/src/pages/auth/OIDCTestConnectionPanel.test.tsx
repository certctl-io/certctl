import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import OIDCTestConnectionPanel from './OIDCTestConnectionPanel';

// Audit 2026-05-11 Fix 09 — OIDCTestConnectionPanel regression coverage.
// Mocks authOIDCTestProvider so the test is hermetic (no real network).
// Pins: button-disabled-without-issuer, happy-path renders all checks
// green, failure-path renders the errors list, iss_param_supported=false
// renders the informational `·` glyph rather than ✗ (since RFC 9207 is
// SHOULD, not MUST).

vi.mock('../../api/client', () => ({
  authOIDCTestProvider: vi.fn(),
}));

import * as client from '../../api/client';

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

describe('OIDCTestConnectionPanel', () => {
  it('RunButton — disabled until issuer URL is non-empty', () => {
    render(<OIDCTestConnectionPanel issuerURL="" clientID="cid" scopes={['openid']} />);
    const btn = screen.getByTestId('oidc-test-connection-run-default') as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });

  it('RunButton — enabled when issuer URL is non-empty', () => {
    render(
      <OIDCTestConnectionPanel
        issuerURL="https://idp.example.com"
        clientID="cid"
        scopes={['openid']}
      />,
    );
    const btn = screen.getByTestId('oidc-test-connection-run-default') as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
  });

  it('RunButton — also disabled when issuer URL is whitespace-only', () => {
    render(<OIDCTestConnectionPanel issuerURL="   " clientID="cid" scopes={[]} />);
    const btn = screen.getByTestId('oidc-test-connection-run-default') as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });

  it('HappyPath — renders all four primary checks green when discovery succeeds', async () => {
    vi.mocked(client.authOIDCTestProvider).mockResolvedValue({
      discovery_succeeded: true,
      jwks_reachable: true,
      supported_alg_values: ['RS256', 'ES256'],
      iss_param_supported: true,
      issuer_echo: 'https://idp.example.com',
      authorization_url: 'https://idp.example.com/authorize',
      token_url: 'https://idp.example.com/token',
      jwks_uri: 'https://idp.example.com/jwks',
      userinfo_endpoint: 'https://idp.example.com/userinfo',
      errors: [],
    });

    render(
      <OIDCTestConnectionPanel
        issuerURL="https://idp.example.com"
        clientID="certctl"
        scopes={['openid', 'profile', 'email']}
      />,
    );

    fireEvent.click(screen.getByTestId('oidc-test-connection-run-default'));
    await waitFor(() => screen.getByTestId('oidc-test-connection-result-default'));

    // All four primary checks visible + green.
    expect(screen.getByTestId('oidc-test-connection-check-discovery-default').textContent)
      .toContain('✓');
    expect(screen.getByTestId('oidc-test-connection-check-jwks-default').textContent)
      .toContain('✓');
    expect(screen.getByTestId('oidc-test-connection-check-algs-default').textContent)
      .toContain('✓');
    // iss_param SUPPORTED → ✓, not `·`.
    expect(screen.getByTestId('oidc-test-connection-check-iss-param-default').textContent)
      .toContain('✓');

    // Detail rows present.
    expect(screen.getByTestId('oidc-test-connection-detail-authz-url-default')).toBeTruthy();
    expect(screen.getByTestId('oidc-test-connection-detail-token-url-default')).toBeTruthy();
    expect(screen.getByTestId('oidc-test-connection-detail-userinfo-url-default')).toBeTruthy();

    // No errors block on happy path.
    expect(screen.queryByTestId('oidc-test-connection-errors-list-default')).toBeNull();

    // The mocked POST received the staged input.
    expect(client.authOIDCTestProvider).toHaveBeenCalledTimes(1);
    expect(client.authOIDCTestProvider).toHaveBeenCalledWith({
      issuer_url: 'https://idp.example.com',
      client_id: 'certctl',
      scopes: ['openid', 'profile', 'email'],
    });
  });

  it('FailurePath — renders the errors list when discovery_succeeded is false', async () => {
    vi.mocked(client.authOIDCTestProvider).mockResolvedValue({
      discovery_succeeded: false,
      jwks_reachable: false,
      supported_alg_values: [],
      iss_param_supported: false,
      errors: ['discovery fetch failed: connection refused', 'jwks_uri not advertised'],
    });

    render(
      <OIDCTestConnectionPanel
        issuerURL="https://broken.idp.example.com"
        clientID="cid"
        scopes={['openid']}
      />,
    );

    fireEvent.click(screen.getByTestId('oidc-test-connection-run-default'));
    await waitFor(() => screen.getByTestId('oidc-test-connection-result-default'));

    // Discovery + JWKS marked ✗.
    expect(screen.getByTestId('oidc-test-connection-check-discovery-default').textContent)
      .toContain('✗');
    expect(screen.getByTestId('oidc-test-connection-check-jwks-default').textContent)
      .toContain('✗');
    // Empty alg list → ⚠ warning, not ✗ (the IdP responded but advertised nothing).
    expect(screen.getByTestId('oidc-test-connection-check-algs-default').textContent)
      .toContain('⚠');

    // Errors list rendered with both entries.
    const errs = screen.getByTestId('oidc-test-connection-errors-list-default');
    expect(errs.textContent).toContain('connection refused');
    expect(errs.textContent).toContain('jwks_uri not advertised');
  });

  it('IssParamFalse — renders the informational `·` glyph when iss_param_supported is false', async () => {
    vi.mocked(client.authOIDCTestProvider).mockResolvedValue({
      discovery_succeeded: true,
      jwks_reachable: true,
      supported_alg_values: ['RS256'],
      iss_param_supported: false,
      issuer_echo: 'https://idp.example.com',
      jwks_uri: 'https://idp.example.com/jwks',
      errors: [],
    });

    render(
      <OIDCTestConnectionPanel
        issuerURL="https://idp.example.com"
        clientID="cid"
        scopes={['openid']}
      />,
    );

    fireEvent.click(screen.getByTestId('oidc-test-connection-run-default'));
    await waitFor(() => screen.getByTestId('oidc-test-connection-result-default'));

    const issRow = screen.getByTestId('oidc-test-connection-check-iss-param-default');
    expect(issRow.textContent).toContain('·');
    // Must NOT be ✗ — RFC 9207 is SHOULD, not MUST; the panel must
    // not visually mark this as a failure.
    expect(issRow.textContent).not.toContain('✗');
    // Body should explain that this is informational.
    expect(issRow.textContent).toContain('informational');
  });

  it('FetchError — renders a top-level error when authOIDCTestProvider throws', async () => {
    vi.mocked(client.authOIDCTestProvider).mockRejectedValue(new Error('network down'));

    render(
      <OIDCTestConnectionPanel
        issuerURL="https://idp.example.com"
        clientID="cid"
        scopes={['openid']}
      />,
    );

    fireEvent.click(screen.getByTestId('oidc-test-connection-run-default'));
    await waitFor(() => screen.getByTestId('oidc-test-connection-error-default'));

    expect(screen.getByTestId('oidc-test-connection-error-default').textContent)
      .toContain('network down');
    // The success result panel must NOT render alongside an error.
    expect(screen.queryByTestId('oidc-test-connection-result-default')).toBeNull();
  });

  it('TestIDSuffix — same component renders twice on a page without colliding test IDs', async () => {
    vi.mocked(client.authOIDCTestProvider).mockResolvedValue({
      discovery_succeeded: true,
      jwks_reachable: true,
      supported_alg_values: ['RS256'],
      iss_param_supported: false,
    });

    render(
      <>
        <OIDCTestConnectionPanel
          issuerURL="https://idp.a.example.com"
          clientID="a"
          scopes={['openid']}
          testIDSuffix="create"
        />
        <OIDCTestConnectionPanel
          issuerURL="https://idp.b.example.com"
          clientID="b"
          scopes={['openid']}
          testIDSuffix="edit"
        />
      </>,
    );

    // Both panels visible with distinct test IDs — no DOM-id collisions.
    expect(screen.getByTestId('oidc-test-connection-panel-create')).toBeTruthy();
    expect(screen.getByTestId('oidc-test-connection-panel-edit')).toBeTruthy();
    expect(screen.getByTestId('oidc-test-connection-run-create')).toBeTruthy();
    expect(screen.getByTestId('oidc-test-connection-run-edit')).toBeTruthy();
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import OIDCJWKSStatusPanel from './OIDCJWKSStatusPanel';

// Audit 2026-05-11 Fix 10 — OIDCJWKSStatusPanel regression coverage.
// Mocks the API client so tests stay hermetic. Pins: loading state,
// happy-path renders all six dt/dd rows, 403 hides panel silently,
// Refresh-now triggers refresh + cache invalidation, never-refreshed
// renders the cold-cache sentinel, current_kids empty renders the
// "not exposed" sentinel.

vi.mock('../../api/client', () => ({
  authOIDCJWKSStatus: vi.fn(),
  refreshOIDCProvider: vi.fn(),
}));

import * as client from '../../api/client';

function renderWithQueryClient(ui: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
    ),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

describe('OIDCJWKSStatusPanel', () => {
  it('LoadingState — renders the loading text while the query is in flight', async () => {
    // Never-resolving promise so we can observe the loading state.
    vi.mocked(client.authOIDCJWKSStatus).mockReturnValue(new Promise(() => {}));

    renderWithQueryClient(<OIDCJWKSStatusPanel providerID="op-okta" />);

    expect(screen.getByTestId('oidc-jwks-status-panel')).toBeTruthy();
    expect(screen.getByTestId('oidc-jwks-status-loading')).toBeTruthy();
  });

  it('HappyPath — renders all six rows from the snapshot with operator-readable values', async () => {
    vi.mocked(client.authOIDCJWKSStatus).mockResolvedValue({
      last_refresh_at: '2026-05-11T12:34:56Z',
      current_kids: ['kid-2026-04', 'kid-2026-05'],
      refresh_count: 7,
      last_error: '',
      rejected_jws_count: 2,
      iss_param_supported: true,
    });

    renderWithQueryClient(<OIDCJWKSStatusPanel providerID="op-okta" />);

    await waitFor(() => screen.getByTestId('oidc-jwks-status-fields'));

    expect(screen.getByTestId('oidc-jwks-status-last-refresh').textContent)
      .toContain('2026-05-11T12:34:56Z');
    expect(screen.getByTestId('oidc-jwks-status-refresh-count').textContent)
      .toBe('7');
    expect(screen.getByTestId('oidc-jwks-status-rejected-jws-count').textContent)
      .toBe('2');
    expect(screen.getByTestId('oidc-jwks-status-last-error').textContent)
      .toContain('(none)');
    expect(screen.getByTestId('oidc-jwks-status-iss-param').textContent)
      .toBe('supported by IdP');
    expect(screen.getByTestId('oidc-jwks-status-current-kids').textContent)
      .toContain('kid-2026-04');
    expect(screen.getByTestId('oidc-jwks-status-current-kids').textContent)
      .toContain('kid-2026-05');
  });

  it('403 — hides panel silently when authOIDCJWKSStatus rejects (caller lacks permission)', async () => {
    vi.mocked(client.authOIDCJWKSStatus).mockRejectedValue(new Error('HTTP 403: forbidden'));

    const { container } = renderWithQueryClient(
      <OIDCJWKSStatusPanel providerID="op-okta" />,
    );

    // The query fires on mount; once it errors the panel returns null.
    await waitFor(() => {
      expect(screen.queryByTestId('oidc-jwks-status-panel')).toBeNull();
    });
    // No DOM artifact left behind — full unmount.
    expect(container.querySelector('[data-testid^="oidc-jwks-status-"]')).toBeNull();
  });

  it('RefreshNow — calls refreshOIDCProvider then invalidates the status query', async () => {
    let firstCall = true;
    vi.mocked(client.authOIDCJWKSStatus).mockImplementation(async () => {
      if (firstCall) {
        firstCall = false;
        return {
          last_refresh_at: '2026-05-11T10:00:00Z',
          current_kids: ['kid-pre'],
          refresh_count: 1,
          rejected_jws_count: 0,
          iss_param_supported: true,
        };
      }
      return {
        last_refresh_at: '2026-05-11T10:05:00Z',
        current_kids: ['kid-post'],
        refresh_count: 2,
        rejected_jws_count: 0,
        iss_param_supported: true,
      };
    });
    vi.mocked(client.refreshOIDCProvider).mockResolvedValue({ refreshed: true });

    renderWithQueryClient(<OIDCJWKSStatusPanel providerID="op-okta" />);
    await waitFor(() => screen.getByTestId('oidc-jwks-status-refresh-count'));
    expect(screen.getByTestId('oidc-jwks-status-refresh-count').textContent).toBe('1');

    fireEvent.click(screen.getByTestId('oidc-jwks-refresh-now'));

    // refreshOIDCProvider was called with the right provider ID.
    await waitFor(() => {
      expect(client.refreshOIDCProvider).toHaveBeenCalledTimes(1);
    });
    expect(client.refreshOIDCProvider).toHaveBeenCalledWith('op-okta');

    // The status query was re-fetched (second authOIDCJWKSStatus call)
    // and the panel renders the new refresh_count.
    await waitFor(() => {
      expect(screen.getByTestId('oidc-jwks-status-refresh-count').textContent).toBe('2');
    });
    expect(client.authOIDCJWKSStatus).toHaveBeenCalledTimes(2);
  });

  it('RefreshNow — surfaces refresh failure inline without hiding the panel', async () => {
    vi.mocked(client.authOIDCJWKSStatus).mockResolvedValue({
      last_refresh_at: '2026-05-11T10:00:00Z',
      current_kids: ['kid-pre'],
      refresh_count: 1,
      last_error: '',
      rejected_jws_count: 0,
      iss_param_supported: true,
    });
    vi.mocked(client.refreshOIDCProvider).mockRejectedValue(
      new Error('HTTP 502: upstream IdP unreachable'),
    );

    renderWithQueryClient(<OIDCJWKSStatusPanel providerID="op-okta" />);
    await waitFor(() => screen.getByTestId('oidc-jwks-status-refresh-count'));

    fireEvent.click(screen.getByTestId('oidc-jwks-refresh-now'));

    await waitFor(() => screen.getByTestId('oidc-jwks-refresh-error'));
    expect(screen.getByTestId('oidc-jwks-refresh-error').textContent)
      .toContain('upstream IdP unreachable');
    // Panel still visible — refresh failure doesn't kill the existing snapshot.
    expect(screen.getByTestId('oidc-jwks-status-panel')).toBeTruthy();
    expect(screen.getByTestId('oidc-jwks-status-refresh-count').textContent).toBe('1');
  });

  it('NeverRefreshed — renders the "cold cache" sentinel when last_refresh_at is empty', async () => {
    vi.mocked(client.authOIDCJWKSStatus).mockResolvedValue({
      // Backend returns an empty string for "never refreshed" — the
      // panel must render an operator-readable sentinel rather than
      // a blank cell that looks like a render bug.
      last_refresh_at: '',
      current_kids: [],
      refresh_count: 0,
      rejected_jws_count: 0,
      iss_param_supported: false,
    });

    renderWithQueryClient(<OIDCJWKSStatusPanel providerID="op-okta" />);

    await waitFor(() => screen.getByTestId('oidc-jwks-status-fields'));
    expect(screen.getByTestId('oidc-jwks-status-last-refresh').textContent)
      .toContain('(never — cold cache)');
    expect(screen.getByTestId('oidc-jwks-status-iss-param').textContent)
      .toBe('not advertised');
  });

  it('CurrentKIDsEmpty — renders the "(not exposed)" sentinel rather than an empty cell', async () => {
    vi.mocked(client.authOIDCJWKSStatus).mockResolvedValue({
      last_refresh_at: '2026-05-11T12:00:00Z',
      current_kids: [],
      refresh_count: 5,
      rejected_jws_count: 0,
      iss_param_supported: true,
    });

    renderWithQueryClient(<OIDCJWKSStatusPanel providerID="op-okta" />);
    await waitFor(() => screen.getByTestId('oidc-jwks-status-current-kids'));

    expect(screen.getByTestId('oidc-jwks-status-current-kids').textContent)
      .toContain('not exposed');
  });

  it('LastError — renders the message with a red treatment when non-empty', async () => {
    vi.mocked(client.authOIDCJWKSStatus).mockResolvedValue({
      last_refresh_at: '2026-05-11T12:00:00Z',
      current_kids: [],
      refresh_count: 3,
      last_error: 'discovery fetch failed: i/o timeout',
      rejected_jws_count: 0,
      iss_param_supported: false,
    });

    renderWithQueryClient(<OIDCJWKSStatusPanel providerID="op-okta" />);
    await waitFor(() => screen.getByTestId('oidc-jwks-status-last-error'));

    expect(screen.getByTestId('oidc-jwks-status-last-error').textContent)
      .toContain('discovery fetch failed: i/o timeout');
  });

  it('CanRefreshFalse — hides the Refresh-now button for read-only callers', async () => {
    vi.mocked(client.authOIDCJWKSStatus).mockResolvedValue({
      last_refresh_at: '2026-05-11T12:00:00Z',
      current_kids: ['kid-1'],
      refresh_count: 4,
      rejected_jws_count: 0,
      iss_param_supported: true,
    });

    renderWithQueryClient(
      <OIDCJWKSStatusPanel providerID="op-okta" canRefresh={false} />,
    );
    await waitFor(() => screen.getByTestId('oidc-jwks-status-fields'));

    // Panel + counters render; button is gone.
    expect(screen.getByTestId('oidc-jwks-status-panel')).toBeTruthy();
    expect(screen.queryByTestId('oidc-jwks-refresh-now')).toBeNull();
  });
});

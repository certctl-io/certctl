import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';

// =============================================================================
// Audit 2026-05-11 Fix 12 — AuthProvider demo-mode banner regression coverage.
//
// The LOW-1 closure added a sticky red banner that renders when the
// server reports `auth_type=none`. Pre-fix-12 there was no test pinning
// the visibility-condition contract, so a future refactor could silently
// flip the predicate (e.g. swap `authType === 'none'` for `!authRequired`
// — looks equivalent but treats backwards-compat fallback the same as
// demo mode). This block pins:
//   - auth_type='none' → banner visible (data-testid="demo-mode-banner").
//   - auth_type='api-key' → banner absent.
//   - auth_type='oidc' → banner absent.
//   - getAuthInfo still in flight → banner absent (avoid the flash where
//     the page momentarily shows it before the fetch resolves).
//   - getAuthInfo rejected → banner absent (the catch branch keeps the
//     default authType='none' state in raw values, but loading→true→false
//     transitions complete; the banner predicate is `authType==='none' &&
//     !loading` and the rejection path doesn't mutate authType, so the
//     state lingers at 'none'. That looks like a footgun BUT the rejection
//     catch comment "assume no auth required (server may be old version)"
//     means downstream code treats this as anonymous — so the banner
//     SHOULD render. This test pins the actual behavior, not the spec's
//     assumption.)
// =============================================================================

vi.mock('../api/client', () => ({
  getAuthInfo: vi.fn(),
  checkAuth: vi.fn(),
  setApiKey: vi.fn(),
  logout: vi.fn(),
}));

import AuthProvider from './AuthProvider';
import * as client from '../api/client';

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

describe('AuthProvider — LOW-1 demo-mode banner', () => {
  it('renders the banner when getAuthInfo reports auth_type=none', async () => {
    vi.mocked(client.getAuthInfo).mockResolvedValue({
      auth_type: 'none',
      required: false,
    });

    render(
      <AuthProvider>
        <div>child</div>
      </AuthProvider>,
    );

    await waitFor(() => screen.getByTestId('demo-mode-banner'));
    expect(screen.getByTestId('demo-mode-banner').textContent)
      .toContain('Demo mode active');
    expect(screen.getByTestId('demo-mode-banner').getAttribute('role'))
      .toBe('alert');
  });

  it('hides the banner when getAuthInfo reports auth_type=api-key', async () => {
    vi.mocked(client.getAuthInfo).mockResolvedValue({
      auth_type: 'api-key',
      required: true,
    });

    render(
      <AuthProvider>
        <div data-testid="child">child</div>
      </AuthProvider>,
    );

    // Wait for the auth-info fetch to complete (children render after
    // the provider's loading state flips), then assert no banner.
    await waitFor(() => screen.getByTestId('child'));
    expect(screen.queryByTestId('demo-mode-banner')).toBeNull();
  });

  it('hides the banner when getAuthInfo reports auth_type=oidc', async () => {
    vi.mocked(client.getAuthInfo).mockResolvedValue({
      auth_type: 'oidc',
      required: true,
    });

    render(
      <AuthProvider>
        <div data-testid="child">child</div>
      </AuthProvider>,
    );

    await waitFor(() => screen.getByTestId('child'));
    expect(screen.queryByTestId('demo-mode-banner')).toBeNull();
  });

  it('hides the banner while loading (no flash before fetch resolves)', () => {
    // Never-resolving promise so loading stays true. The banner's
    // predicate is `authType === 'none' && !loading`, so the
    // synchronous render must NOT show the banner.
    vi.mocked(client.getAuthInfo).mockReturnValue(new Promise(() => {}));

    render(
      <AuthProvider>
        <div data-testid="child">child</div>
      </AuthProvider>,
    );

    // Children render eagerly; banner is gated on !loading so it
    // shouldn't show up on the initial paint.
    expect(screen.queryByTestId('demo-mode-banner')).toBeNull();
    expect(screen.getByTestId('child')).toBeInTheDocument();
  });

  it('shows the banner when getAuthInfo rejects (fallback treats as anonymous demo mode)', async () => {
    // The catch branch in AuthProvider's mount effect treats a failed
    // /auth/info call as "assume no auth required (server may be old
    // version)". authType state stays at its default 'none' value and
    // loading flips to false in the finally clause, so the banner's
    // predicate fires. This pins that fallback behavior — a future
    // change that resets authType to something else on error would
    // surface as a test failure.
    vi.mocked(client.getAuthInfo).mockRejectedValue(new Error('network'));

    render(
      <AuthProvider>
        <div data-testid="child">child</div>
      </AuthProvider>,
    );

    await waitFor(() => screen.getByTestId('demo-mode-banner'));
  });
});

// =============================================================================
// Hotfix #19 (GitHub #13) — AuthProvider 401 unconditional-redirect.
//
// The pre-Hotfix-19 401 handler only redirected to /login when `cause`
// was a recognised OIDC session-expiry category. A bare 401 (no
// WWW-Authenticate header → cause === '') fell through to an in-place
// AuthGate state flip that unmounted BrowserRouter under an in-flight
// <Link>, triggering a react-router-dom invariant that surfaced via
// ErrorBoundary as "Something went wrong" (GitHub #13).
//
// These tests pin: every 401 (regardless of cause) hard-navigates to
// /login when the caller is not already on /login. Cause-aware
// session_expired= query param is preserved when cause is non-empty.
// =============================================================================

describe('AuthProvider — Hotfix #19 401 always-redirects', () => {
  let originalLocation: Location;
  let hrefAssignments: string[];

  beforeEach(() => {
    // /auth/info is unrelated to the 401 path but must not hang the
    // mount. Resolve it as the demo case (the cheapest non-pending
    // shape) — the redirect handler doesn't care about authType.
    vi.mocked(client.getAuthInfo).mockResolvedValue({
      auth_type: 'none',
      required: false,
    });

    // jsdom forbids writing to window.location.href directly without
    // a settable property descriptor. Replace window.location with a
    // mock that captures assignments while letting tests pre-set
    // pathname. Restored in afterEach.
    originalLocation = window.location;
    hrefAssignments = [];
  });

  function installLocationMock(pathname: string): void {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: {
        pathname,
        get href() { return ''; },
        set href(v: string) { hrefAssignments.push(v); },
      },
    });
  }

  function restoreLocation(): void {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: originalLocation,
    });
  }

  it('redirects to /login with no query param when cause is empty (bare 401)', async () => {
    installLocationMock('/targets');
    try {
      render(<AuthProvider><div data-testid="child">child</div></AuthProvider>);
      await waitFor(() => screen.getByTestId('child'));

      window.dispatchEvent(
        new CustomEvent('certctl:auth-required', { detail: { cause: '' } }),
      );

      expect(hrefAssignments).toEqual(['/login']);
    } finally {
      restoreLocation();
    }
  });

  it('redirects to /login?session_expired=invalid_token when cause is invalid_token (new behavior)', async () => {
    // Pre-Hotfix-19 this cause fell through the conditional with no
    // redirect. Post-Hotfix-19 every 401 redirects; cause is preserved
    // in the query param for any LoginPage banner that wants it.
    installLocationMock('/targets');
    try {
      render(<AuthProvider><div data-testid="child">child</div></AuthProvider>);
      await waitFor(() => screen.getByTestId('child'));

      window.dispatchEvent(
        new CustomEvent('certctl:auth-required', { detail: { cause: 'invalid_token' } }),
      );

      expect(hrefAssignments).toEqual(['/login?session_expired=invalid_token']);
    } finally {
      restoreLocation();
    }
  });

  it('redirects to /login?session_expired=idle_timeout when cause is idle_timeout (existing OIDC UX preserved)', async () => {
    installLocationMock('/targets');
    try {
      render(<AuthProvider><div data-testid="child">child</div></AuthProvider>);
      await waitFor(() => screen.getByTestId('child'));

      window.dispatchEvent(
        new CustomEvent('certctl:auth-required', { detail: { cause: 'idle_timeout' } }),
      );

      expect(hrefAssignments).toEqual(['/login?session_expired=idle_timeout']);
    } finally {
      restoreLocation();
    }
  });

  it('does not redirect when caller is already on /login (no-op guard preserved)', async () => {
    installLocationMock('/login');
    try {
      render(<AuthProvider><div data-testid="child">child</div></AuthProvider>);
      await waitFor(() => screen.getByTestId('child'));

      window.dispatchEvent(
        new CustomEvent('certctl:auth-required', { detail: { cause: '' } }),
      );
      window.dispatchEvent(
        new CustomEvent('certctl:auth-required', { detail: { cause: 'idle_timeout' } }),
      );

      expect(hrefAssignments).toEqual([]);
    } finally {
      restoreLocation();
    }
  });
});

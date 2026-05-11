import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): LoginPage XSS-hardening + render coverage.
//
// LoginPage surfaces an error from useAuth().error verbatim into the login
// form. A backend that round-trips the user-supplied API key into an error
// message ("invalid API key XYZ123 ...") would let an attacker deliver an
// XSS payload by trying to log in with `<script>...</script>` as the key.
// React's JSX text-interpolation escapes by default, so the payload should
// render as literal text with no script execution; this test pins that
// invariant against future refactors that might switch to
// dangerouslySetInnerHTML or v-html-style rendering.
//
// Pins:
//   1. The login form renders.
//   2. An auth error containing a literal <script> tag does NOT execute.
//   3. The literal payload text appears as escaped content.
//
// Bundle 2 Phase 8 add:
//   4. When /auth/info returns oidc_providers[], a "Sign in with X" button
//      renders per provider linking to the provider's login_url.
//   5. When /auth/info returns no providers, the OIDC block does NOT render.
// -----------------------------------------------------------------------------

const xssError = '<script data-xss="login-error">window.__xss_pwned__=1;</script>';
let mockError: string | null = null;

vi.mock('../components/AuthProvider', () => ({
  useAuth: () => ({
    loading: false,
    authRequired: true,
    authenticated: false,
    authType: 'api-key',
    user: '',
    admin: false,
    login: vi.fn(),
    logout: vi.fn(),
    error: mockError,
  }),
}));

vi.mock('../api/client', () => ({
  getAuthInfo: vi.fn(),
}));

import LoginPage from './LoginPage';
import * as client from '../api/client';

function renderWithRouter(ui: ReactNode) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe('LoginPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    mockError = null;
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
    // Default: no providers configured.
    vi.mocked(client.getAuthInfo).mockResolvedValue({
      auth_type: 'api-key',
      required: true,
    });
  });

  it('renders the login form', () => {
    renderWithRouter(<LoginPage />);
    expect(screen.getByLabelText('API Key')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Sign In/i })).toBeInTheDocument();
  });

  it('does NOT execute a <script> payload surfaced via auth error', () => {
    mockError = xssError;
    renderWithRouter(<LoginPage />);

    const liveScripts = document.querySelectorAll('script[data-xss="login-error"]');
    expect(liveScripts.length, 'auth error must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'auth error <script> body must not have executed',
    ).toBeUndefined();
  });

  it('renders the literal error payload as escaped text', () => {
    mockError = xssError;
    renderWithRouter(<LoginPage />);
    // React text-interpolation escapes the payload. The literal "<script"
    // substring shows up in the document text content.
    expect(document.body.textContent ?? '').toContain('<script data-xss="login-error">');
  });

  it('does not submit when the key field is empty', () => {
    renderWithRouter(<LoginPage />);
    const submit = screen.getByRole('button', { name: /Sign In/i });
    expect(submit).toBeDisabled();
  });

  it('shows literal-text submit-disabled state when key is whitespace-only', async () => {
    renderWithRouter(<LoginPage />);
    const input = screen.getByLabelText('API Key') as HTMLInputElement;
    fireEvent.change(input, { target: { value: '   ' } });
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Sign In/i })).toBeDisabled();
    });
  });

  it('renders OIDC "Sign in with X" buttons when /auth/info returns providers (Bundle 2 Phase 8)', async () => {
    vi.mocked(client.getAuthInfo).mockResolvedValue({
      auth_type: 'api-key',
      required: true,
      oidc_providers: [
        { id: 'op-okta', display_name: 'Okta', login_url: '/auth/oidc/login?provider_id=op-okta' },
        { id: 'op-google', display_name: 'Google', login_url: '/auth/oidc/login?provider_id=op-google' },
      ],
    });
    renderWithRouter(<LoginPage />);
    await waitFor(() => {
      expect(screen.getByTestId('login-oidc-providers')).toBeTruthy();
    });
    const oktaBtn = screen.getByTestId('login-oidc-button-op-okta') as HTMLAnchorElement;
    expect(oktaBtn.href).toContain('/auth/oidc/login?provider_id=op-okta');
    expect(oktaBtn.textContent).toContain('Okta');
    const googleBtn = screen.getByTestId('login-oidc-button-op-google') as HTMLAnchorElement;
    expect(googleBtn.textContent).toContain('Google');
    // API-key form remains as fallback.
    expect(screen.getByTestId('login-api-key-form')).toBeTruthy();
  });

  it('omits the OIDC block when /auth/info returns no providers (Bundle 2 Phase 8)', async () => {
    vi.mocked(client.getAuthInfo).mockResolvedValue({
      auth_type: 'api-key',
      required: true,
    });
    renderWithRouter(<LoginPage />);
    await waitFor(() => {
      expect(screen.getByTestId('login-api-key-form')).toBeTruthy();
    });
    expect(screen.queryByTestId('login-oidc-providers')).toBeNull();
  });

  // Audit 2026-05-10 HIGH-7 — when the OIDC callback path redirects
  // here with ?error=oidc_failed&reason=<category>, the page renders
  // an operator-friendly cause banner instead of leaving the user
  // staring at a blank form.
  it('renders OIDC failure banner when ?error=oidc_failed&reason=email_domain_not_allowed (HIGH-7)', async () => {
    render(
      <MemoryRouter initialEntries={['/login?error=oidc_failed&reason=email_domain_not_allowed']}>
        <LoginPage />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('login-oidc-failure-banner')).toBeTruthy();
    });
    const banner = screen.getByTestId('login-oidc-failure-banner');
    expect(banner.getAttribute('data-reason')).toBe('email_domain_not_allowed');
    expect(banner.textContent).toContain('email domain is not in the configured allowlist');
  });

  it('falls back to unspecified text when ?reason= is unknown (HIGH-7 forward-compat)', async () => {
    render(
      <MemoryRouter initialEntries={['/login?error=oidc_failed&reason=newcat_from_future_release']}>
        <LoginPage />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('login-oidc-failure-banner')).toBeTruthy();
    });
    const banner = screen.getByTestId('login-oidc-failure-banner');
    expect(banner.textContent).toContain('OIDC sign-in failed');
  });

  it('does NOT render the OIDC failure banner without the error query param', () => {
    render(
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId('login-oidc-failure-banner')).toBeNull();
  });

  // Audit 2026-05-10 HIGH-8 — session-expired causes routed via
  // ?session_expired=<cause> render an OIDC-aware re-login banner.
  it('renders session-cause banner when ?session_expired=back_channel_revoked (HIGH-8)', async () => {
    render(
      <MemoryRouter initialEntries={['/login?session_expired=back_channel_revoked']}>
        <LoginPage />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('login-session-cause-banner')).toBeTruthy();
    });
    const banner = screen.getByTestId('login-session-cause-banner');
    expect(banner.getAttribute('data-cause')).toBe('back_channel_revoked');
    expect(banner.textContent).toContain('back-channel logout');
  });

  it('renders idle-timeout cause banner when ?session_expired=idle_timeout (HIGH-8)', async () => {
    render(
      <MemoryRouter initialEntries={['/login?session_expired=idle_timeout']}>
        <LoginPage />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(screen.getByTestId('login-session-cause-banner')).toBeTruthy();
    });
    expect(screen.getByTestId('login-session-cause-banner').textContent).toContain(
      'timed out from inactivity',
    );
  });

  it('does NOT render the session-cause banner for an unknown cause', () => {
    render(
      <MemoryRouter initialEntries={['/login?session_expired=zzz_unknown_cause']}>
        <LoginPage />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId('login-session-cause-banner')).toBeNull();
  });
});

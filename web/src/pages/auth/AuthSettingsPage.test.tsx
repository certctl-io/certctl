import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// =============================================================================
// Bundle 1 Phase 10 — AuthSettingsPage stub coverage. Pins the
// identity surface + bootstrap-status surface.
// =============================================================================

vi.mock('../../api/client', () => ({
  authMe: vi.fn(),
  authBootstrapAvailable: vi.fn(),
  // Audit 2026-05-11 Fix 12 — runtime-config panel coverage. The page
  // calls authRuntimeConfig via TanStack Query (retry: false), so a
  // rejected mock makes the panel quietly absent. Tests mock it as
  // needed; the two pre-existing tests rely on the panel being absent
  // (no positive assertion against it) so the rejected default works.
  authRuntimeConfig: vi.fn(),
}));

import AuthSettingsPage from './AuthSettingsPage';
import * as client from '../../api/client';

function renderWithProviders(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

describe('AuthSettingsPage', () => {
  it('renders identity + bootstrap status (closed)', async () => {
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'alice',
      actor_type: 'APIKey',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [{ permission: 'cert.read', scope_type: 'global' }],
    });
    vi.mocked(client.authBootstrapAvailable).mockResolvedValue({ available: false });

    renderWithProviders(<AuthSettingsPage />);

    await waitFor(() => screen.getByTestId('auth-settings-roles'));
    expect(screen.getByTestId('auth-settings-roles').textContent).toBe('r-admin');
    expect(screen.getByTestId('auth-settings-permcount').textContent).toBe('1');
    expect(screen.getByTestId('auth-settings-admin').textContent).toBe('yes');
    await waitFor(() => screen.getByTestId('auth-settings-bootstrap-status'));
    expect(screen.getByTestId('auth-settings-bootstrap-status').textContent).toBe('closed');
  });

  it('flags an open bootstrap path with the OPEN status', async () => {
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: '',
      actor_type: '',
      tenant_id: 't-default',
      admin: false,
      roles: [],
      effective_permissions: [],
    });
    vi.mocked(client.authBootstrapAvailable).mockResolvedValue({ available: true });

    renderWithProviders(<AuthSettingsPage />);
    await waitFor(() => screen.getByTestId('auth-settings-bootstrap-status'));
    expect(screen.getByTestId('auth-settings-bootstrap-status').textContent).toMatch(/OPEN/);
  });
});

// =============================================================================
// Audit 2026-05-11 Fix 12 — AuthSettingsPage runtime-config panel coverage.
//
// The MED-12 closure added the auth-runtime-config panel
// (`data-testid="auth-settings-runtime-config"`) but the pre-existing tests
// don't exercise it. This block pins:
//   - Happy path renders one <tr> per key in the flat map.
//   - Sort is alphabetical by key — operators rely on stable ordering when
//     correlating CERTCTL_* config across logs and the GUI.
//   - Empty string values render the "(empty)" placeholder, NOT a blank cell
//     (otherwise the row visually disappears).
//   - 403 / rejected query hides the panel silently — non-admins shouldn't
//     see a half-rendered shell.
// =============================================================================

function setupAuthMeAdmin() {
  vi.mocked(client.authMe).mockResolvedValue({
    actor_id: 'admin',
    actor_type: 'APIKey',
    tenant_id: 't-default',
    admin: true,
    roles: ['r-admin'],
    effective_permissions: [{ permission: 'auth.role.assign', scope_type: 'global' }],
  });
  vi.mocked(client.authBootstrapAvailable).mockResolvedValue({ available: false });
}

describe('AuthSettingsPage — runtime config panel (MED-12)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
  });

  it('renders one table row per runtime-config key', async () => {
    setupAuthMeAdmin();
    vi.mocked(client.authRuntimeConfig).mockResolvedValue({
      CERTCTL_AUTH_TYPE: 'oidc',
      CERTCTL_BREAKGLASS_ENABLED: 'false',
      CERTCTL_TRUSTED_PROXIES_COUNT: '2',
    });

    renderWithProviders(<AuthSettingsPage />);
    await waitFor(() => screen.getByTestId('auth-settings-runtime-config'));

    const panel = screen.getByTestId('auth-settings-runtime-config');
    expect(panel.textContent).toContain('CERTCTL_AUTH_TYPE');
    expect(panel.textContent).toContain('oidc');
    expect(panel.textContent).toContain('CERTCTL_BREAKGLASS_ENABLED');
    expect(panel.textContent).toContain('false');
    expect(panel.textContent).toContain('CERTCTL_TRUSTED_PROXIES_COUNT');
    expect(panel.textContent).toContain('2');
  });

  it('sorts rows alphabetically by key (stable correlation with log scraping)', async () => {
    setupAuthMeAdmin();
    vi.mocked(client.authRuntimeConfig).mockResolvedValue({
      // Intentionally out of order — the sort comparator should normalize.
      CERTCTL_TRUSTED_PROXIES_COUNT: '0',
      CERTCTL_AUTH_TYPE: 'api-key',
      CERTCTL_BREAKGLASS_ENABLED: 'true',
    });

    renderWithProviders(<AuthSettingsPage />);
    await waitFor(() => screen.getByTestId('auth-settings-runtime-config'));

    const panel = screen.getByTestId('auth-settings-runtime-config');
    const auth = panel.textContent!.indexOf('CERTCTL_AUTH_TYPE');
    const bg = panel.textContent!.indexOf('CERTCTL_BREAKGLASS_ENABLED');
    const tp = panel.textContent!.indexOf('CERTCTL_TRUSTED_PROXIES_COUNT');
    expect(auth).toBeGreaterThan(-1);
    expect(bg).toBeGreaterThan(auth);
    expect(tp).toBeGreaterThan(bg);
  });

  it('empty value renders the "(empty)" placeholder, not a blank cell', async () => {
    setupAuthMeAdmin();
    vi.mocked(client.authRuntimeConfig).mockResolvedValue({
      CERTCTL_BOOTSTRAP_OIDC_PROVIDER_ID: '',
    });

    renderWithProviders(<AuthSettingsPage />);
    await waitFor(() => screen.getByTestId('auth-settings-runtime-config'));

    expect(screen.getByTestId('auth-settings-runtime-config').textContent)
      .toContain('(empty)');
  });

  it('rejected runtime-config query hides the panel silently (e.g. 403 for non-admins)', async () => {
    setupAuthMeAdmin();
    vi.mocked(client.authRuntimeConfig).mockRejectedValue(new Error('HTTP 403: forbidden'));

    renderWithProviders(<AuthSettingsPage />);
    // Wait for the identity surface so we know render completed.
    await waitFor(() => screen.getByTestId('auth-settings-roles'));

    // Panel never renders — non-admins must not see the shell of a
    // surface they can't read.
    expect(screen.queryByTestId('auth-settings-runtime-config')).toBeNull();
  });
});

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

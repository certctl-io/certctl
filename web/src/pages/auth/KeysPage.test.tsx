import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// =============================================================================
// Bundle 1 Phase 10 — KeysPage Vitest coverage. Pins the demo-anon
// system-managed flag (no assign / revoke buttons) and the per-row
// permission gating.
// =============================================================================

vi.mock('../../api/client', () => ({
  authListKeys: vi.fn(),
  authListRoles: vi.fn(),
  authAssignKeyRole: vi.fn(),
  authRevokeKeyRole: vi.fn(),
  authMe: vi.fn(),
}));

import KeysPage from './KeysPage';
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

const adminMe = {
  actor_id: 'alice',
  actor_type: 'APIKey',
  tenant_id: 't-default',
  admin: true,
  roles: ['r-admin'],
  effective_permissions: [{ permission: 'auth.role.assign', scope_type: 'global' as const }],
};

const auditorMe = {
  actor_id: 'audrey',
  actor_type: 'APIKey',
  tenant_id: 't-default',
  admin: false,
  roles: ['r-auditor'],
  effective_permissions: [{ permission: 'audit.read', scope_type: 'global' as const }],
};

const sampleKeys = [
  { actor_id: 'alice', actor_type: 'APIKey', tenant_id: 't-default', role_ids: ['r-admin'] },
  { actor_id: 'actor-demo-anon', actor_type: 'Anonymous', tenant_id: 't-default', role_ids: ['r-admin'] },
];

describe('KeysPage', () => {
  it('flags actor-demo-anon as system-managed and hides its mutation buttons', async () => {
    vi.mocked(client.authListKeys).mockResolvedValue(sampleKeys);
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue(adminMe);

    renderWithProviders(<KeysPage />);

    await waitFor(() => screen.getByTestId('keys-table'));
    expect(screen.getByText(/system-managed/i)).toBeTruthy();
    // alice has the assign + revoke affordances; demo-anon does NOT.
    expect(screen.queryByTestId('keys-assign-alice')).toBeTruthy();
    expect(screen.queryByTestId('keys-assign-actor-demo-anon')).toBeNull();
    expect(screen.queryByTestId('keys-revoke-alice-r-admin')).toBeTruthy();
    expect(screen.queryByTestId('keys-revoke-actor-demo-anon-r-admin')).toBeNull();
  });

  it('hides the assign + revoke affordances when the caller lacks auth.role.assign', async () => {
    vi.mocked(client.authListKeys).mockResolvedValue([sampleKeys[0]]);
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue(auditorMe);

    renderWithProviders(<KeysPage />);

    await waitFor(() => screen.getByTestId('keys-table'));
    expect(screen.queryByTestId('keys-assign-alice')).toBeNull();
    expect(screen.queryByTestId('keys-revoke-alice-r-admin')).toBeNull();
  });

  it('opens the assign modal and POSTs the role choice', async () => {
    vi.mocked(client.authListKeys).mockResolvedValue([sampleKeys[0]]);
    vi.mocked(client.authListRoles).mockResolvedValue([
      { id: 'r-operator', tenant_id: 't-default', name: 'operator' },
    ]);
    vi.mocked(client.authAssignKeyRole).mockResolvedValue({});
    vi.mocked(client.authMe).mockResolvedValue(adminMe);

    renderWithProviders(<KeysPage />);

    await waitFor(() => screen.getByTestId('keys-assign-alice'));
    fireEvent.click(screen.getByTestId('keys-assign-alice'));

    await waitFor(() => screen.getByTestId('assign-role-modal'));
    fireEvent.change(screen.getByTestId('assign-role-select'), {
      target: { value: 'r-operator' },
    });
    fireEvent.click(screen.getByTestId('assign-role-submit'));

    await waitFor(() =>
      expect(client.authAssignKeyRole).toHaveBeenCalledWith('alice', 'r-operator'),
    );
  });
});

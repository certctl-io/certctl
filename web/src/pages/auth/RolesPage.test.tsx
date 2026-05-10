import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// =============================================================================
// Bundle 1 Phase 10 — RolesPage Vitest coverage. Pins:
//   - List renders when authListRoles resolves.
//   - Empty state renders when the list is empty.
//   - "Create role" button is HIDDEN when the caller lacks
//     auth.role.create. Server-side enforcement is the load-bearing
//     gate; this test pins the UX hide.
//   - "Create role" button is SHOWN when the caller has the perm.
//   - Submitting the create modal calls authCreateRole.
//   - Error state renders when authListRoles rejects.
// =============================================================================

vi.mock('../../api/client', () => ({
  authListRoles: vi.fn(),
  authCreateRole: vi.fn(),
  authMe: vi.fn(),
}));

import RolesPage from './RolesPage';
import * as client from '../../api/client';

function renderWithProviders(ui: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

const sampleRoles = [
  { id: 'r-admin', tenant_id: 't-default', name: 'admin', description: 'Full access' },
  { id: 'r-viewer', tenant_id: 't-default', name: 'viewer', description: 'Read-only' },
];

describe('RolesPage', () => {
  it('renders the role list from authListRoles', async () => {
    vi.mocked(client.authListRoles).mockResolvedValue(sampleRoles);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'alice',
      actor_type: 'APIKey',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [{ permission: 'auth.role.create', scope_type: 'global' }],
    });

    renderWithProviders(<RolesPage />);

    await waitFor(() => {
      expect(screen.getByTestId('roles-table')).toBeTruthy();
    });
    expect(screen.getByText('admin')).toBeTruthy();
    expect(screen.getByText('viewer')).toBeTruthy();
  });

  it('shows the create button when the caller has auth.role.create', async () => {
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'alice',
      actor_type: 'APIKey',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-operator'],
      effective_permissions: [{ permission: 'auth.role.create', scope_type: 'global' }],
    });

    renderWithProviders(<RolesPage />);

    await waitFor(() => {
      expect(screen.queryByTestId('roles-create-button')).toBeTruthy();
    });
  });

  it('hides the create button when the caller lacks auth.role.create', async () => {
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'audrey',
      actor_type: 'APIKey',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-auditor'],
      effective_permissions: [{ permission: 'audit.read', scope_type: 'global' }],
    });

    renderWithProviders(<RolesPage />);

    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeTruthy());
    expect(screen.queryByTestId('roles-create-button')).toBeNull();
  });

  it('renders the empty state when the list is empty', async () => {
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'alice',
      actor_type: 'APIKey',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [],
    });

    renderWithProviders(<RolesPage />);
    await waitFor(() => expect(screen.getByTestId('roles-empty')).toBeTruthy());
  });

  it('submits the create modal via authCreateRole', async () => {
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authCreateRole).mockResolvedValue({
      id: 'r-release',
      tenant_id: 't-default',
      name: 'release-manager',
    });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'alice',
      actor_type: 'APIKey',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [{ permission: 'auth.role.create', scope_type: 'global' }],
    });

    renderWithProviders(<RolesPage />);
    await waitFor(() => screen.getByTestId('roles-create-button'));
    fireEvent.click(screen.getByTestId('roles-create-button'));

    await waitFor(() => screen.getByTestId('create-role-modal'));
    fireEvent.change(screen.getByTestId('create-role-name'), {
      target: { value: 'release-manager' },
    });
    fireEvent.change(screen.getByTestId('create-role-description'), {
      target: { value: 'Cuts releases' },
    });
    fireEvent.click(screen.getByTestId('create-role-submit'));

    await waitFor(() => {
      expect(client.authCreateRole).toHaveBeenCalledWith({
        name: 'release-manager',
        description: 'Cuts releases',
      });
    });
  });

  it('renders the error state when authListRoles rejects', async () => {
    vi.mocked(client.authListRoles).mockRejectedValue(new Error('boom'));
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'alice',
      actor_type: 'APIKey',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [],
    });

    renderWithProviders(<RolesPage />);
    await waitFor(() => expect(screen.getByText(/failed to load/i)).toBeTruthy());
  });
});

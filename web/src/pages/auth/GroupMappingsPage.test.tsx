import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// Bundle 2 Phase 8 — GroupMappingsPage tests. Pins:
//   - 403 ErrorState when caller lacks auth.oidc.list.
//   - Empty mapping list renders the fail-closed-warning empty state.
//   - Mapping list renders one row per mapping.
//   - Add form HIDDEN without auth.oidc.edit.
//   - Add form SHOWN with auth.oidc.edit + submission calls addGroupMapping.

vi.mock('../../api/client', () => ({
  listGroupMappings: vi.fn(),
  addGroupMapping: vi.fn(),
  removeGroupMapping: vi.fn(),
  authListRoles: vi.fn(),
  authMe: vi.fn(),
}));

import GroupMappingsPage from './GroupMappingsPage';
import * as client from '../../api/client';

function renderRoute(ui: ReactNode, path = '/auth/oidc/providers/op-okta/mappings') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/auth/oidc/providers/:id/mappings" element={ui} />
        </Routes>
      </MemoryRouter>
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

const sampleMappings = [
  {
    id: 'gm-1',
    provider_id: 'op-okta',
    group_name: 'engineers',
    role_id: 'r-admin',
    tenant_id: 't-default',
    created_at: '2026-05-10T00:00:00Z',
  },
];

describe('GroupMappingsPage', () => {
  it('renders ErrorState when caller lacks auth.oidc.list', async () => {
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-x',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: [],
      effective_permissions: [],
    });
    renderRoute(<GroupMappingsPage />);
    await waitFor(() => {
      expect(screen.queryByText(/auth\.oidc\.list/)).toBeTruthy();
    });
  });

  it('renders empty fail-closed warning when no mappings configured', async () => {
    vi.mocked(client.listGroupMappings).mockResolvedValue({ mappings: [] });
    vi.mocked(client.authListRoles).mockResolvedValue(sampleRoles);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [{ permission: 'auth.oidc.list', scope_type: 'global' }],
    });
    renderRoute(<GroupMappingsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('group-mappings-empty')).toBeTruthy();
    });
  });

  it('renders mapping rows from listGroupMappings', async () => {
    vi.mocked(client.listGroupMappings).mockResolvedValue({ mappings: sampleMappings });
    vi.mocked(client.authListRoles).mockResolvedValue(sampleRoles);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [
        { permission: 'auth.oidc.list', scope_type: 'global' },
        { permission: 'auth.oidc.edit', scope_type: 'global' },
      ],
    });
    renderRoute(<GroupMappingsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('group-mapping-row-gm-1')).toBeTruthy();
    });
    expect(screen.getByText('engineers')).toBeTruthy();
    expect(screen.getByText('r-admin')).toBeTruthy();
    expect(screen.getByTestId('group-mapping-remove-gm-1')).toBeTruthy();
  });

  it('hides the add form when caller lacks auth.oidc.edit', async () => {
    vi.mocked(client.listGroupMappings).mockResolvedValue({ mappings: sampleMappings });
    vi.mocked(client.authListRoles).mockResolvedValue(sampleRoles);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-viewer',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-viewer'],
      effective_permissions: [{ permission: 'auth.oidc.list', scope_type: 'global' }],
    });
    renderRoute(<GroupMappingsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('group-mapping-row-gm-1')).toBeTruthy();
    });
    expect(screen.queryByTestId('group-mappings-add-form')).toBeNull();
    // Remove button is also hidden in row when caller lacks edit.
    expect(screen.queryByTestId('group-mapping-remove-gm-1')).toBeNull();
  });

  it('submitting the add form calls addGroupMapping', async () => {
    vi.mocked(client.listGroupMappings).mockResolvedValue({ mappings: [] });
    vi.mocked(client.authListRoles).mockResolvedValue(sampleRoles);
    vi.mocked(client.addGroupMapping).mockResolvedValue(sampleMappings[0]);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [
        { permission: 'auth.oidc.list', scope_type: 'global' },
        { permission: 'auth.oidc.edit', scope_type: 'global' },
      ],
    });
    renderRoute(<GroupMappingsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('group-mappings-add-form')).toBeTruthy();
    });
    fireEvent.change(screen.getByTestId('group-mappings-group-name-input'), {
      target: { value: 'engineers' },
    });
    fireEvent.change(screen.getByTestId('group-mappings-role-select'), {
      target: { value: 'r-admin' },
    });
    fireEvent.click(screen.getByTestId('group-mappings-add-button'));
    await waitFor(() => {
      expect(client.addGroupMapping).toHaveBeenCalledWith('op-okta', 'engineers', 'r-admin');
    });
  });
});

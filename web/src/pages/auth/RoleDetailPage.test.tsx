import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// =============================================================================
// Audit 2026-05-11 Fix 12 — RoleDetailPage regression coverage.
//
// The MED-8 GUI closure added the scope picker + scope_id input to the
// Add-permission form, and the LOW-11 closure hid the Delete button on
// the seven seeded default role ids. Neither change had a Vitest case.
// This block pins:
//   - Default role (e.g. r-admin) renders the
//     'role-delete-disabled-tooltip' element + does NOT render the
//     'role-delete-button'. Hides the destructive button on system
//     roles the server would refuse to delete anyway (DELETE → 409).
//   - Custom role renders the 'role-delete-button' + does NOT render
//     the tooltip.
//   - Add-permission form with scope_type=global hides the scope_id
//     input.
//   - Add-permission form with scope_type=profile reveals the
//     scope_id input + the Add button is disabled until scope_id is
//     non-empty.
//   - Submitting with profile scope POSTs body
//     {permission, scope_type: 'profile', scope_id: <trimmed>}.
//   - Submitting with global scope POSTs body {permission} (no
//     scope_type / scope_id keys).
// =============================================================================

vi.mock('../../api/client', () => ({
  authGetRole: vi.fn(),
  authListPermissions: vi.fn(),
  authUpdateRole: vi.fn(),
  authDeleteRole: vi.fn(),
  authAddRolePermission: vi.fn(),
  authRemoveRolePermission: vi.fn(),
  authMe: vi.fn(),
}));

import RoleDetailPage from './RoleDetailPage';
import * as client from '../../api/client';

function renderRoute(ui: ReactNode, path = '/auth/roles/r-customrole') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/auth/roles/:id" element={ui} />
          <Route path="/auth/roles" element={<div data-testid="roles-list-stub" />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const adminMe = {
  actor_id: 'alice',
  actor_type: 'APIKey',
  tenant_id: 't-default',
  admin: true,
  roles: ['r-admin'],
  effective_permissions: [
    { permission: 'auth.role.edit', scope_type: 'global' as const },
    { permission: 'auth.role.delete', scope_type: 'global' as const },
  ],
};

const sampleCatalogue = [
  { id: 'p-cert-read', name: 'cert.read', namespace: 'cert', description: '' },
  { id: 'p-cert-issue', name: 'cert.issue', namespace: 'cert', description: '' },
  { id: 'p-profile-edit', name: 'profile.edit', namespace: 'profile', description: '' },
];

function roleDetail(roleID: string, name: string) {
  return {
    role: { id: roleID, tenant_id: 't-default', name, description: '' },
    permissions: [], // empty so every catalogue entry is available
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
  vi.mocked(client.authMe).mockResolvedValue(adminMe);
  vi.mocked(client.authListPermissions).mockResolvedValue(sampleCatalogue);
});

describe('RoleDetailPage — LOW-11 default-role delete-button hide', () => {
  it('default role (r-admin) renders the disabled tooltip + NO delete button', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-admin', 'Admin'));

    renderRoute(<RoleDetailPage />, '/auth/roles/r-admin');
    await waitFor(() => screen.getByTestId('role-delete-disabled-tooltip'));

    expect(screen.getByTestId('role-delete-disabled-tooltip').textContent)
      .toContain('System role');
    expect(screen.queryByTestId('role-delete-button')).toBeNull();
  });

  it('default role (r-auditor) also hides delete', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-auditor', 'Auditor'));

    renderRoute(<RoleDetailPage />, '/auth/roles/r-auditor');
    await waitFor(() => screen.getByTestId('role-delete-disabled-tooltip'));
    expect(screen.queryByTestId('role-delete-button')).toBeNull();
  });

  it('custom role renders the delete button + NO disabled tooltip', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-customrole', 'Custom'));

    renderRoute(<RoleDetailPage />, '/auth/roles/r-customrole');
    await waitFor(() => screen.getByTestId('role-delete-button'));

    expect(screen.queryByTestId('role-delete-disabled-tooltip')).toBeNull();
  });
});

describe('RoleDetailPage — MED-8 Add-permission scope picker', () => {
  it('global scope hides the scope_id input', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-customrole', 'Custom'));

    renderRoute(<RoleDetailPage />, '/auth/roles/r-customrole');
    await waitFor(() => screen.getByTestId('role-add-permission-scope-type'));

    // Default state — scope_type is 'global' so the conditional
    // scope_id input is not in the DOM.
    expect(screen.queryByTestId('role-add-permission-scope-id')).toBeNull();
  });

  it('switching to profile scope reveals scope_id and gates the Add button', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-customrole', 'Custom'));

    renderRoute(<RoleDetailPage />, '/auth/roles/r-customrole');
    await waitFor(() => screen.getByTestId('role-add-permission-select'));

    // Pick a permission first so the Add button's non-perm guard is satisfied.
    fireEvent.change(screen.getByTestId('role-add-permission-select'), {
      target: { value: 'cert.read' },
    });
    fireEvent.change(screen.getByTestId('role-add-permission-scope-type'), {
      target: { value: 'profile' },
    });

    await waitFor(() => screen.getByTestId('role-add-permission-scope-id'));
    const submit = screen.getByTestId('role-add-permission-submit') as HTMLButtonElement;
    // Empty scope_id → button disabled.
    expect(submit.disabled).toBe(true);

    // Fill it; button enables.
    fireEvent.change(screen.getByTestId('role-add-permission-scope-id'), {
      target: { value: 'p-acme' },
    });
    expect(submit.disabled).toBe(false);
  });

  it('profile-scope submit POSTs body {permission, scope_type: profile, scope_id}', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-customrole', 'Custom'));
    vi.mocked(client.authAddRolePermission).mockResolvedValue({} as never);

    renderRoute(<RoleDetailPage />, '/auth/roles/r-customrole');
    await waitFor(() => screen.getByTestId('role-add-permission-select'));

    fireEvent.change(screen.getByTestId('role-add-permission-select'), {
      target: { value: 'cert.issue' },
    });
    fireEvent.change(screen.getByTestId('role-add-permission-scope-type'), {
      target: { value: 'profile' },
    });
    await waitFor(() => screen.getByTestId('role-add-permission-scope-id'));
    fireEvent.change(screen.getByTestId('role-add-permission-scope-id'), {
      target: { value: '  p-acme  ' }, // whitespace deliberate; submit trims
    });
    fireEvent.click(screen.getByTestId('role-add-permission-submit'));

    await waitFor(() => expect(client.authAddRolePermission).toHaveBeenCalledTimes(1));
    expect(client.authAddRolePermission).toHaveBeenCalledWith('r-customrole', {
      permission: 'cert.issue',
      scope_type: 'profile',
      scope_id: 'p-acme',
    });
  });

  it('global-scope submit POSTs body {permission} only (no scope_type / scope_id)', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-customrole', 'Custom'));
    vi.mocked(client.authAddRolePermission).mockResolvedValue({} as never);

    renderRoute(<RoleDetailPage />, '/auth/roles/r-customrole');
    await waitFor(() => screen.getByTestId('role-add-permission-select'));

    fireEvent.change(screen.getByTestId('role-add-permission-select'), {
      target: { value: 'cert.read' },
    });
    // scope_type stays at 'global' (default).
    fireEvent.click(screen.getByTestId('role-add-permission-submit'));

    await waitFor(() => expect(client.authAddRolePermission).toHaveBeenCalledTimes(1));
    expect(client.authAddRolePermission).toHaveBeenCalledWith('r-customrole', {
      permission: 'cert.read',
    });
    // The submit handler intentionally omits the scope keys on global
    // so the backend's default-scope path runs. Asserting the body
    // shape pins that contract.
  });

  it('issuer-scope submit POSTs body {permission, scope_type: issuer, scope_id}', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-customrole', 'Custom'));
    vi.mocked(client.authAddRolePermission).mockResolvedValue({} as never);

    renderRoute(<RoleDetailPage />, '/auth/roles/r-customrole');
    await waitFor(() => screen.getByTestId('role-add-permission-select'));

    fireEvent.change(screen.getByTestId('role-add-permission-select'), {
      target: { value: 'profile.edit' },
    });
    fireEvent.change(screen.getByTestId('role-add-permission-scope-type'), {
      target: { value: 'issuer' },
    });
    await waitFor(() => screen.getByTestId('role-add-permission-scope-id'));
    fireEvent.change(screen.getByTestId('role-add-permission-scope-id'), {
      target: { value: 'iss-internal-pki' },
    });
    fireEvent.click(screen.getByTestId('role-add-permission-submit'));

    await waitFor(() => expect(client.authAddRolePermission).toHaveBeenCalledTimes(1));
    expect(client.authAddRolePermission).toHaveBeenCalledWith('r-customrole', {
      permission: 'profile.edit',
      scope_type: 'issuer',
      scope_id: 'iss-internal-pki',
    });
  });

  it('Add button stays disabled when no permission is selected', async () => {
    vi.mocked(client.authGetRole).mockResolvedValue(roleDetail('r-customrole', 'Custom'));

    renderRoute(<RoleDetailPage />, '/auth/roles/r-customrole');
    await waitFor(() => screen.getByTestId('role-add-permission-submit'));

    const submit = screen.getByTestId('role-add-permission-submit') as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
  });
});

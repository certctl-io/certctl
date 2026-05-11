import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// Bundle 2 Phase 8 — OIDCProviderDetailPage tests. Pins:
//   - 403 ErrorState when caller lacks auth.oidc.list.
//   - "Edit"/"Refresh"/"Delete" buttons HIDDEN without their respective perms.
//   - "Edit"/"Refresh"/"Delete" buttons SHOWN when perms present.
//   - Refresh button calls refreshOIDCProvider.
//   - Delete confirmation flow + button enabled only when typed text matches.

vi.mock('../../api/client', () => ({
  listOIDCProviders: vi.fn(),
  updateOIDCProvider: vi.fn(),
  deleteOIDCProvider: vi.fn(),
  refreshOIDCProvider: vi.fn(),
  authMe: vi.fn(),
}));

import OIDCProviderDetailPage from './OIDCProviderDetailPage';
import * as client from '../../api/client';

function renderRoute(ui: ReactNode, path = '/auth/oidc/providers/op-okta') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/auth/oidc/providers/:id" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

const sampleProvider = {
  id: 'op-okta',
  tenant_id: 't-default',
  name: 'Okta',
  issuer_url: 'https://example.okta.com',
  client_id: 'certctl',
  redirect_uri: 'https://certctl.example.com/auth/oidc/callback',
  groups_claim_path: 'groups',
  groups_claim_format: 'string-array',
  fetch_userinfo: false,
  scopes: ['openid'],
  iat_window_seconds: 300,
  jwks_cache_ttl_seconds: 3600,
  created_at: '2026-05-10T00:00:00Z',
  updated_at: '2026-05-10T00:00:00Z',
};

describe('OIDCProviderDetailPage', () => {
  it('renders ErrorState when caller lacks auth.oidc.list', async () => {
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-x',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: [],
      effective_permissions: [],
    });
    renderRoute(<OIDCProviderDetailPage />);
    await waitFor(() => {
      expect(screen.queryByText(/auth\.oidc\.list/)).toBeTruthy();
    });
  });

  it('renders provider config and edit/delete/refresh buttons with full perms', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: [sampleProvider] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [
        { permission: 'auth.oidc.list', scope_type: 'global' },
        { permission: 'auth.oidc.edit', scope_type: 'global' },
        { permission: 'auth.oidc.delete', scope_type: 'global' },
      ],
    });
    renderRoute(<OIDCProviderDetailPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-provider-edit-button')).toBeTruthy();
    });
    expect(screen.getByTestId('oidc-provider-refresh-button')).toBeTruthy();
    expect(screen.getByTestId('oidc-provider-delete-button')).toBeTruthy();
    expect(screen.getByTestId('oidc-provider-mappings-link')).toBeTruthy();
    // The provider's issuer_url renders in the dl.
    expect(screen.getAllByText('https://example.okta.com').length).toBeGreaterThan(0);
  });

  it('hides edit/refresh/delete when caller has only auth.oidc.list', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: [sampleProvider] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-viewer',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-viewer'],
      effective_permissions: [{ permission: 'auth.oidc.list', scope_type: 'global' }],
    });
    renderRoute(<OIDCProviderDetailPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-provider-mappings-link')).toBeTruthy();
    });
    expect(screen.queryByTestId('oidc-provider-edit-button')).toBeNull();
    expect(screen.queryByTestId('oidc-provider-refresh-button')).toBeNull();
    expect(screen.queryByTestId('oidc-provider-delete-button')).toBeNull();
  });

  it('refresh button calls refreshOIDCProvider', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: [sampleProvider] });
    vi.mocked(client.refreshOIDCProvider).mockResolvedValue({ refreshed: true });
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
    renderRoute(<OIDCProviderDetailPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-provider-refresh-button')).toBeTruthy();
    });
    fireEvent.click(screen.getByTestId('oidc-provider-refresh-button'));
    await waitFor(() => {
      expect(client.refreshOIDCProvider).toHaveBeenCalledWith('op-okta');
    });
  });

  it('delete confirm button stays disabled until typed text matches provider name', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: [sampleProvider] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [
        { permission: 'auth.oidc.list', scope_type: 'global' },
        { permission: 'auth.oidc.delete', scope_type: 'global' },
      ],
    });
    renderRoute(<OIDCProviderDetailPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-provider-delete-button')).toBeTruthy();
    });
    fireEvent.click(screen.getByTestId('oidc-provider-delete-button'));
    await waitFor(() => {
      expect(screen.getByTestId('oidc-provider-delete-confirm')).toBeTruthy();
    });
    const confirmBtn = screen.getByTestId('oidc-provider-delete-confirm-button') as HTMLButtonElement;
    expect(confirmBtn.disabled).toBe(true);
    fireEvent.change(screen.getByTestId('oidc-provider-delete-confirm-input'), {
      target: { value: 'Wrong' },
    });
    expect(confirmBtn.disabled).toBe(true);
    fireEvent.change(screen.getByTestId('oidc-provider-delete-confirm-input'), {
      target: { value: 'Okta' },
    });
    expect(confirmBtn.disabled).toBe(false);
  });

  // =============================================================================
  // Audit 2026-05-11 A-7 — Advanced fields are editable (MED-4 closure).
  // =============================================================================

  async function openEditFormWithEditPerms() {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: [sampleProvider] });
    vi.mocked(client.updateOIDCProvider).mockResolvedValue(sampleProvider);
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
    renderRoute(<OIDCProviderDetailPage />);
    await waitFor(() => screen.getByTestId('oidc-provider-edit-button'));
    fireEvent.click(screen.getByTestId('oidc-provider-edit-button'));
    await waitFor(() => screen.getByTestId('oidc-provider-edit-advanced'));
  }

  it('A-7 Advanced details section is collapsed by default and visible in edit mode', async () => {
    await openEditFormWithEditPerms();
    const details = screen.getByTestId('oidc-provider-edit-advanced') as HTMLDetailsElement;
    expect(details).toBeTruthy();
    // <details> with no `open` attribute = collapsed.
    expect(details.open).toBe(false);
  });

  it('A-7 Advanced fields pre-populate from the live provider', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({
      providers: [{
        ...sampleProvider,
        scopes: ['openid', 'profile', 'email', 'groups'],
        groups_claim_path: 'realm_access.roles',
        groups_claim_format: 'json-path',
        iat_window_seconds: 120,
        jwks_cache_ttl_seconds: 600,
      }],
    });
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
    renderRoute(<OIDCProviderDetailPage />);
    await waitFor(() => screen.getByTestId('oidc-provider-edit-button'));
    fireEvent.click(screen.getByTestId('oidc-provider-edit-button'));
    await waitFor(() => screen.getByTestId('oidc-provider-edit-advanced'));

    expect((screen.getByTestId('oidc-provider-edit-scopes') as HTMLInputElement).value)
      .toBe('openid profile email groups');
    expect((screen.getByTestId('oidc-provider-edit-groups-claim-path') as HTMLInputElement).value)
      .toBe('realm_access.roles');
    expect((screen.getByTestId('oidc-provider-edit-groups-claim-format') as HTMLSelectElement).value)
      .toBe('json-path');
    expect((screen.getByTestId('oidc-provider-edit-iat-window-seconds') as HTMLInputElement).valueAsNumber)
      .toBe(120);
    expect((screen.getByTestId('oidc-provider-edit-jwks-cache-ttl-seconds') as HTMLInputElement).valueAsNumber)
      .toBe(600);
  });

  it('A-7 all five Advanced fields round-trip into the PUT body', async () => {
    await openEditFormWithEditPerms();

    fireEvent.change(screen.getByTestId('oidc-provider-edit-scopes'), {
      target: { value: '  openid   profile   email   groups  ' },
    });
    fireEvent.change(screen.getByTestId('oidc-provider-edit-groups-claim-path'), {
      target: { value: 'realm_access.roles' },
    });
    fireEvent.change(screen.getByTestId('oidc-provider-edit-groups-claim-format'), {
      target: { value: 'json-path' },
    });
    fireEvent.change(screen.getByTestId('oidc-provider-edit-iat-window-seconds'), {
      target: { value: '120' },
    });
    fireEvent.change(screen.getByTestId('oidc-provider-edit-jwks-cache-ttl-seconds'), {
      target: { value: '600' },
    });
    fireEvent.click(screen.getByTestId('oidc-provider-save-button'));

    await waitFor(() => expect(client.updateOIDCProvider).toHaveBeenCalledTimes(1));
    const [, body] = vi.mocked(client.updateOIDCProvider).mock.calls[0];
    // Whitespace normalization: collapsed runs, no empty strings.
    expect(body.scopes).toEqual(['openid', 'profile', 'email', 'groups']);
    expect(body.groups_claim_path).toBe('realm_access.roles');
    expect(body.groups_claim_format).toBe('json-path');
    expect(body.iat_window_seconds).toBe(120);
    expect(body.jwks_cache_ttl_seconds).toBe(600);
  });

  it('A-7 IAT window above 600 rejects with inline error and does NOT POST', async () => {
    await openEditFormWithEditPerms();
    fireEvent.change(screen.getByTestId('oidc-provider-edit-iat-window-seconds'), {
      target: { value: '601' },
    });
    fireEvent.click(screen.getByTestId('oidc-provider-save-button'));
    await waitFor(() => screen.getByTestId('oidc-provider-detail-error'));
    expect(screen.getByTestId('oidc-provider-detail-error').textContent).toContain('IAT window');
    expect(client.updateOIDCProvider).not.toHaveBeenCalled();
  });

  it('A-7 IAT window <= 0 rejects with inline error', async () => {
    await openEditFormWithEditPerms();
    fireEvent.change(screen.getByTestId('oidc-provider-edit-iat-window-seconds'), {
      target: { value: '0' },
    });
    fireEvent.click(screen.getByTestId('oidc-provider-save-button'));
    await waitFor(() => screen.getByTestId('oidc-provider-detail-error'));
    expect(client.updateOIDCProvider).not.toHaveBeenCalled();
  });

  it('A-7 JWKS cache TTL below 60 rejects with inline error', async () => {
    await openEditFormWithEditPerms();
    fireEvent.change(screen.getByTestId('oidc-provider-edit-jwks-cache-ttl-seconds'), {
      target: { value: '30' },
    });
    fireEvent.click(screen.getByTestId('oidc-provider-save-button'));
    await waitFor(() => screen.getByTestId('oidc-provider-detail-error'));
    expect(screen.getByTestId('oidc-provider-detail-error').textContent).toContain('JWKS');
    expect(client.updateOIDCProvider).not.toHaveBeenCalled();
  });

  it('A-7 empty scopes input rejects (operator can\'t accidentally wipe the array)', async () => {
    await openEditFormWithEditPerms();
    fireEvent.change(screen.getByTestId('oidc-provider-edit-scopes'), {
      target: { value: '   ' },
    });
    fireEvent.click(screen.getByTestId('oidc-provider-save-button'));
    await waitFor(() => screen.getByTestId('oidc-provider-detail-error'));
    expect(screen.getByTestId('oidc-provider-detail-error').textContent).toContain('Scopes');
    expect(client.updateOIDCProvider).not.toHaveBeenCalled();
  });

  it('A-7 empty groups-claim-path rejects', async () => {
    await openEditFormWithEditPerms();
    fireEvent.change(screen.getByTestId('oidc-provider-edit-groups-claim-path'), {
      target: { value: '   ' },
    });
    fireEvent.click(screen.getByTestId('oidc-provider-save-button'));
    await waitFor(() => screen.getByTestId('oidc-provider-detail-error'));
    expect(screen.getByTestId('oidc-provider-detail-error').textContent).toContain('Groups claim path');
    expect(client.updateOIDCProvider).not.toHaveBeenCalled();
  });

  it('A-7 unchanged Advanced fields still round-trip as the existing values (no lying field)', async () => {
    await openEditFormWithEditPerms();
    // Operator only changes Display name; advanced section is untouched.
    fireEvent.change(screen.getByTestId('oidc-provider-edit-name'), {
      target: { value: 'Okta Rename' },
    });
    fireEvent.click(screen.getByTestId('oidc-provider-save-button'));
    await waitFor(() => expect(client.updateOIDCProvider).toHaveBeenCalledTimes(1));
    const [, body] = vi.mocked(client.updateOIDCProvider).mock.calls[0];
    // Pre-A-7 these would have been the provider's pass-through; now
    // they come from state pre-populated by startEdit. Either way the
    // wire value should be the live provider's existing config.
    expect(body.scopes).toEqual(sampleProvider.scopes);
    expect(body.groups_claim_path).toBe(sampleProvider.groups_claim_path);
    expect(body.groups_claim_format).toBe(sampleProvider.groups_claim_format);
    expect(body.iat_window_seconds).toBe(sampleProvider.iat_window_seconds);
    expect(body.jwks_cache_ttl_seconds).toBe(sampleProvider.jwks_cache_ttl_seconds);
  });
});

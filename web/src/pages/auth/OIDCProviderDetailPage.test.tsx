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
});

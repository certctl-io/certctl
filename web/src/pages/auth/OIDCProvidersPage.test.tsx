import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// Bundle 2 Phase 8 — OIDCProvidersPage tests. Pins:
//   - Page 403's (renders ErrorState) when caller lacks auth.oidc.list.
//   - Empty state renders when no providers.
//   - List renders + name links to detail page.
//   - "Configure provider" button HIDDEN without auth.oidc.create.
//   - "Configure provider" button SHOWN with auth.oidc.create + submit
//     calls createOIDCProvider.

vi.mock('../../api/client', () => ({
  listOIDCProviders: vi.fn(),
  createOIDCProvider: vi.fn(),
  authMe: vi.fn(),
}));

import OIDCProvidersPage from './OIDCProvidersPage';
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

const sample = [
  {
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
  },
];

describe('OIDCProvidersPage', () => {
  it('renders ErrorState when caller lacks auth.oidc.list', async () => {
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-x',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: [],
      effective_permissions: [],
    });
    renderWithProviders(<OIDCProvidersPage />);
    await waitFor(() => {
      expect(screen.queryByText(/auth\.oidc\.list/)).toBeTruthy();
    });
  });

  it('renders empty state when no providers configured', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: [] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-x',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [{ permission: 'auth.oidc.list', scope_type: 'global' }],
    });
    renderWithProviders(<OIDCProvidersPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-providers-empty')).toBeTruthy();
    });
  });

  it('renders list + create button when caller has auth.oidc.create', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: sample });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [
        { permission: 'auth.oidc.list', scope_type: 'global' },
        { permission: 'auth.oidc.create', scope_type: 'global' },
      ],
    });
    renderWithProviders(<OIDCProvidersPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-provider-row-op-okta')).toBeTruthy();
    });
    expect(screen.getByTestId('oidc-providers-create-button')).toBeTruthy();
    expect(screen.getByText('Okta')).toBeTruthy();
  });

  it('hides create button without auth.oidc.create', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: sample });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-viewer',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-viewer'],
      effective_permissions: [{ permission: 'auth.oidc.list', scope_type: 'global' }],
    });
    renderWithProviders(<OIDCProvidersPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-provider-row-op-okta')).toBeTruthy();
    });
    expect(screen.queryByTestId('oidc-providers-create-button')).toBeNull();
  });

  it('submits the create modal via createOIDCProvider', async () => {
    vi.mocked(client.listOIDCProviders).mockResolvedValue({ providers: [] });
    vi.mocked(client.createOIDCProvider).mockResolvedValue(sample[0]);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [
        { permission: 'auth.oidc.list', scope_type: 'global' },
        { permission: 'auth.oidc.create', scope_type: 'global' },
      ],
    });
    renderWithProviders(<OIDCProvidersPage />);
    await waitFor(() => {
      expect(screen.getByTestId('oidc-providers-create-button')).toBeTruthy();
    });
    fireEvent.click(screen.getByTestId('oidc-providers-create-button'));
    await waitFor(() => {
      expect(screen.getByTestId('create-oidc-provider-modal')).toBeTruthy();
    });
    fireEvent.change(screen.getByTestId('oidc-provider-name-input'), { target: { value: 'Okta' } });
    fireEvent.change(screen.getByTestId('oidc-provider-issuer-url-input'), {
      target: { value: 'https://example.okta.com' },
    });
    fireEvent.change(screen.getByTestId('oidc-provider-client-id-input'), { target: { value: 'certctl' } });
    fireEvent.change(screen.getByTestId('oidc-provider-client-secret-input'), {
      target: { value: 'super-secret' },
    });
    fireEvent.change(screen.getByTestId('oidc-provider-redirect-uri-input'), {
      target: { value: 'https://certctl.example.com/auth/oidc/callback' },
    });
    fireEvent.click(screen.getByTestId('create-oidc-provider-submit'));
    await waitFor(() => {
      expect(client.createOIDCProvider).toHaveBeenCalledTimes(1);
    });
  });
});

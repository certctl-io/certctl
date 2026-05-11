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

  // =============================================================================
  // Audit 2026-05-11 A-3 — AllowedEmailDomains chip control.
  // =============================================================================

  async function openCreateModal() {
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
  }

  it('AllowedEmailDomains — Add persists a chip and is included in submit body', async () => {
    await openCreateModal();
    fireEvent.change(screen.getByTestId('oidc-create-allowed-email-domains-input'), {
      target: { value: 'acme.com' },
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domains-add'));
    await waitFor(() => {
      expect(screen.getByTestId('oidc-create-allowed-email-domain-chip-acme.com')).toBeTruthy();
    });
    // Fill remaining required fields and submit.
    fireEvent.change(screen.getByTestId('oidc-provider-name-input'), { target: { value: 'Okta' } });
    fireEvent.change(screen.getByTestId('oidc-provider-issuer-url-input'), {
      target: { value: 'https://example.okta.com' },
    });
    fireEvent.change(screen.getByTestId('oidc-provider-client-id-input'), { target: { value: 'certctl' } });
    fireEvent.change(screen.getByTestId('oidc-provider-client-secret-input'), { target: { value: 's' } });
    fireEvent.change(screen.getByTestId('oidc-provider-redirect-uri-input'), {
      target: { value: 'https://certctl.example.com/auth/oidc/callback' },
    });
    fireEvent.click(screen.getByTestId('create-oidc-provider-submit'));
    await waitFor(() => {
      expect(client.createOIDCProvider).toHaveBeenCalledTimes(1);
    });
    const body = vi.mocked(client.createOIDCProvider).mock.calls[0][0];
    expect(body.allowed_email_domains).toEqual(['acme.com']);
  });

  it('AllowedEmailDomains — rejects entries containing @', async () => {
    await openCreateModal();
    fireEvent.change(screen.getByTestId('oidc-create-allowed-email-domains-input'), {
      target: { value: 'user@acme.com' },
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domains-add'));
    await waitFor(() => {
      expect(screen.getByTestId('oidc-create-allowed-email-domains-error')).toBeTruthy();
    });
    // Chip must NOT have been added.
    expect(screen.queryByTestId('oidc-create-allowed-email-domain-chip-user@acme.com')).toBeNull();
  });

  it('AllowedEmailDomains — rejects wildcard entries', async () => {
    await openCreateModal();
    fireEvent.change(screen.getByTestId('oidc-create-allowed-email-domains-input'), {
      target: { value: '*.acme.com' },
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domains-add'));
    await waitFor(() => {
      expect(screen.getByTestId('oidc-create-allowed-email-domains-error')).toBeTruthy();
    });
  });

  it('AllowedEmailDomains — normalizes mixed-case input to lowercase', async () => {
    await openCreateModal();
    fireEvent.change(screen.getByTestId('oidc-create-allowed-email-domains-input'), {
      target: { value: 'ACME.COM' },
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domains-add'));
    await waitFor(() => {
      // The chip is keyed by the lowercased form.
      expect(screen.getByTestId('oidc-create-allowed-email-domain-chip-acme.com')).toBeTruthy();
    });
  });

  it('AllowedEmailDomains — Enter key adds the entry without clicking Add', async () => {
    await openCreateModal();
    const input = screen.getByTestId('oidc-create-allowed-email-domains-input');
    fireEvent.change(input, { target: { value: 'subsidiary.io' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    await waitFor(() => {
      expect(screen.getByTestId('oidc-create-allowed-email-domain-chip-subsidiary.io')).toBeTruthy();
    });
  });

  it('AllowedEmailDomains — chip × button removes the entry', async () => {
    await openCreateModal();
    fireEvent.change(screen.getByTestId('oidc-create-allowed-email-domains-input'), {
      target: { value: 'acme.com' },
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domains-add'));
    await waitFor(() => {
      expect(screen.getByTestId('oidc-create-allowed-email-domain-chip-acme.com')).toBeTruthy();
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domain-chip-remove-acme.com'));
    await waitFor(() => {
      expect(screen.queryByTestId('oidc-create-allowed-email-domain-chip-acme.com')).toBeNull();
    });
  });

  it('AllowedEmailDomains — duplicate entry is rejected', async () => {
    await openCreateModal();
    fireEvent.change(screen.getByTestId('oidc-create-allowed-email-domains-input'), {
      target: { value: 'acme.com' },
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domains-add'));
    await waitFor(() => {
      expect(screen.getByTestId('oidc-create-allowed-email-domain-chip-acme.com')).toBeTruthy();
    });
    fireEvent.change(screen.getByTestId('oidc-create-allowed-email-domains-input'), {
      target: { value: 'acme.com' },
    });
    fireEvent.click(screen.getByTestId('oidc-create-allowed-email-domains-add'));
    await waitFor(() => {
      expect(screen.getByTestId('oidc-create-allowed-email-domains-error')).toBeTruthy();
    });
    // Still exactly one chip.
    const chips = screen.getAllByTestId(/^oidc-create-allowed-email-domain-chip-(?!remove-)/);
    expect(chips).toHaveLength(1);
  });
});

// =============================================================================
// Pure unit tests for validateEmailDomain (Audit 2026-05-11 A-3).
// Backend-parity rules: no @ / no whitespace / no wildcards / lowercase
// only / must be FQDN.
// =============================================================================

describe('validateEmailDomain', () => {
  it('accepts a plain lowercase FQDN', async () => {
    const { validateEmailDomain } = await import('./OIDCProvidersPage');
    expect(validateEmailDomain('acme.com')).toBe('');
    expect(validateEmailDomain('subsidiary.io')).toBe('');
    expect(validateEmailDomain('hyphen-domain.co.uk')).toBe('');
  });

  it('rejects entries containing @', async () => {
    const { validateEmailDomain } = await import('./OIDCProvidersPage');
    expect(validateEmailDomain('user@acme.com')).not.toBe('');
    expect(validateEmailDomain('@acme.com')).not.toBe('');
  });

  it('rejects entries with whitespace', async () => {
    const { validateEmailDomain } = await import('./OIDCProvidersPage');
    expect(validateEmailDomain('acme com')).not.toBe('');
    expect(validateEmailDomain('acme\tcom')).not.toBe('');
  });

  it('rejects wildcards', async () => {
    const { validateEmailDomain } = await import('./OIDCProvidersPage');
    expect(validateEmailDomain('*.acme.com')).not.toBe('');
    expect(validateEmailDomain('acme.*')).not.toBe('');
  });

  it('rejects mixed-case', async () => {
    const { validateEmailDomain } = await import('./OIDCProvidersPage');
    expect(validateEmailDomain('Acme.com')).not.toBe('');
    expect(validateEmailDomain('ACME.COM')).not.toBe('');
  });

  it('rejects bare hostnames (no dot)', async () => {
    const { validateEmailDomain } = await import('./OIDCProvidersPage');
    expect(validateEmailDomain('localhost')).not.toBe('');
  });

  it('rejects empty strings', async () => {
    const { validateEmailDomain } = await import('./OIDCProvidersPage');
    expect(validateEmailDomain('')).not.toBe('');
  });
});

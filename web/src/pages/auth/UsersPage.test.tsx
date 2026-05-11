import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

// =============================================================================
// Audit 2026-05-11 Fix 12 — UsersPage regression coverage.
//
// The MED-11 closure shipped UsersPage but no test file. This file pins:
//   - Active rows render with the operator-readable status pill.
//   - Deactivated rows render dimmed + show the deactivation timestamp.
//   - Deactivate button fires the API call after confirm() returns true.
//   - Deactivate is silent when confirm() returns false (no API call).
//   - Reactivate button is rendered for deactivated rows + fires the API.
//   - Provider filter narrows the underlying authListUsers call.
//   - Empty-state placeholder renders when the response is empty.
// =============================================================================

vi.mock('../../api/client', () => ({
  authListUsers: vi.fn(),
  authDeactivateUser: vi.fn(),
  authReactivateUser: vi.fn(),
}));

import UsersPage from './UsersPage';
import * as client from '../../api/client';

function renderWithProviders(ui: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

const baseUser = {
  id: 'u-1',
  tenant_id: 't-default',
  email: 'alice@example.com',
  display_name: 'Alice',
  oidc_subject: 'sub-alice',
  oidc_provider_id: 'op-okta',
  last_login_at: '2026-05-10T00:00:00Z',
  created_at: '2026-05-01T00:00:00Z',
};

describe('UsersPage', () => {
  it('renders active user rows with the Active status pill', async () => {
    vi.mocked(client.authListUsers).mockResolvedValue([baseUser]);
    renderWithProviders(<UsersPage />);

    await waitFor(() => screen.getByText('alice@example.com'));
    expect(screen.getByText('Alice')).toBeInTheDocument();
    expect(screen.getByText('op-okta')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    // Active row carries a Deactivate button.
    expect(screen.getByRole('button', { name: /Deactivate$/i })).toBeInTheDocument();
  });

  it('deactivated row renders the Deactivated <timestamp> status + Reactivate button', async () => {
    vi.mocked(client.authListUsers).mockResolvedValue([{
      ...baseUser,
      id: 'u-2',
      email: 'bob@example.com',
      display_name: 'Bob',
      deactivated_at: '2026-05-10T12:34:56Z',
    }]);
    renderWithProviders(<UsersPage />);

    await waitFor(() => screen.getByText('bob@example.com'));
    // Status cell carries the timestamp so the operator can correlate
    // with the audit log without leaving the page.
    expect(screen.getByText(/Deactivated 2026-05-10T12:34:56Z/)).toBeInTheDocument();
    // The deactivated row swaps Deactivate → Reactivate.
    expect(screen.getByRole('button', { name: /Reactivate$/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Deactivate$/i })).toBeNull();
  });

  it('Deactivate button calls authDeactivateUser after confirm() returns true', async () => {
    vi.mocked(client.authListUsers).mockResolvedValue([baseUser]);
    vi.mocked(client.authDeactivateUser).mockResolvedValue(undefined as unknown as void);
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);

    renderWithProviders(<UsersPage />);
    await waitFor(() => screen.getByText('alice@example.com'));

    fireEvent.click(screen.getByRole('button', { name: /Deactivate$/i }));
    await waitFor(() => expect(client.authDeactivateUser).toHaveBeenCalledTimes(1));
    expect(client.authDeactivateUser).toHaveBeenCalledWith('u-1');
    expect(confirmSpy).toHaveBeenCalled();
  });

  it('Deactivate is no-op when confirm() returns false', async () => {
    vi.mocked(client.authListUsers).mockResolvedValue([baseUser]);
    vi.spyOn(window, 'confirm').mockReturnValue(false);

    renderWithProviders(<UsersPage />);
    await waitFor(() => screen.getByText('alice@example.com'));

    fireEvent.click(screen.getByRole('button', { name: /Deactivate$/i }));
    // Allow any microtask flush before asserting nothing happened.
    await new Promise((r) => setTimeout(r, 10));
    expect(client.authDeactivateUser).not.toHaveBeenCalled();
  });

  it('Reactivate button calls authReactivateUser after confirm() returns true', async () => {
    vi.mocked(client.authListUsers).mockResolvedValue([{
      ...baseUser,
      id: 'u-3',
      deactivated_at: '2026-05-10T12:00:00Z',
    }]);
    vi.mocked(client.authReactivateUser).mockResolvedValue(undefined as unknown as void);
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    renderWithProviders(<UsersPage />);
    await waitFor(() => screen.getByRole('button', { name: /Reactivate$/i }));

    fireEvent.click(screen.getByRole('button', { name: /Reactivate$/i }));
    await waitFor(() => expect(client.authReactivateUser).toHaveBeenCalledTimes(1));
    expect(client.authReactivateUser).toHaveBeenCalledWith('u-3');
  });

  it('provider filter input narrows the authListUsers call', async () => {
    vi.mocked(client.authListUsers).mockResolvedValue([]);
    renderWithProviders(<UsersPage />);

    // First mount call — empty filter passes undefined (NOT the empty string)
    // because authListUsers(undefined) hits the backend without ?provider=.
    await waitFor(() => expect(client.authListUsers).toHaveBeenCalledWith(undefined));

    const input = screen.getByPlaceholderText(/op-keycloak/);
    fireEvent.change(input, { target: { value: 'op-okta' } });

    // The TanStack-Query queryKey includes providerFilter so the filtered
    // value triggers a re-fetch with the narrow argument.
    await waitFor(() => expect(client.authListUsers).toHaveBeenLastCalledWith('op-okta'));
  });

  it('empty list renders the "No users matching filter." placeholder', async () => {
    vi.mocked(client.authListUsers).mockResolvedValue([]);
    renderWithProviders(<UsersPage />);

    await waitFor(() => screen.getByText(/No users matching filter\./));
  });

  it('loading state renders the "Loading users…" text', async () => {
    // Never-resolving promise so we can observe the loading branch.
    vi.mocked(client.authListUsers).mockReturnValue(new Promise(() => {}));
    renderWithProviders(<UsersPage />);

    expect(screen.getByText(/Loading users…/)).toBeInTheDocument();
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// Bundle 2 Phase 8 — SessionsPage tests. Pins:
//   - 403 ErrorState when caller lacks auth.session.list.
//   - "Self" view renders the caller's sessions + self-pill on own row.
//   - "All actors (admin)" toggle HIDDEN without auth.session.list.all.
//   - "All actors (admin)" toggle SHOWN with auth.session.list.all.
//   - Revoke button SHOWN for own session even without auth.session.revoke.
//   - Revoke click calls revokeSession (after window.confirm).

vi.mock('../../api/client', () => ({
  listSessions: vi.fn(),
  revokeSession: vi.fn(),
  authMe: vi.fn(),
}));

import SessionsPage from './SessionsPage';
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

const ownSession = {
  id: 'sess-own',
  actor_id: 'u-alice',
  actor_type: 'User',
  ip_address: '10.0.0.1',
  user_agent: 'curl/8',
  created_at: '2026-05-10T00:00:00Z',
  last_seen_at: '2026-05-10T01:00:00Z',
  idle_expires_at: '2026-05-10T02:00:00Z',
  absolute_expires_at: '2026-05-11T00:00:00Z',
  revoked: false,
};

const otherSession = {
  id: 'sess-other',
  actor_id: 'u-bob',
  actor_type: 'User',
  ip_address: '10.0.0.2',
  user_agent: 'firefox',
  created_at: '2026-05-10T00:00:00Z',
  last_seen_at: '2026-05-10T01:00:00Z',
  idle_expires_at: '2026-05-10T02:00:00Z',
  absolute_expires_at: '2026-05-11T00:00:00Z',
  revoked: false,
};

describe('SessionsPage', () => {
  it('renders ErrorState when caller lacks auth.session.list', async () => {
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-x',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: [],
      effective_permissions: [],
    });
    renderWithProviders(<SessionsPage />);
    await waitFor(() => {
      expect(screen.queryByText(/auth\.session\.list/)).toBeTruthy();
    });
  });

  it('renders own sessions with self-pill on caller row', async () => {
    vi.mocked(client.listSessions).mockResolvedValue({ sessions: [ownSession] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-alice',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-viewer'],
      effective_permissions: [{ permission: 'auth.session.list', scope_type: 'global' }],
    });
    renderWithProviders(<SessionsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('session-row-sess-own')).toBeTruthy();
    });
    expect(screen.getByTestId('session-self-pill-sess-own')).toBeTruthy();
    // own session always shows revoke (own-bypass) regardless of auth.session.revoke.
    expect(screen.getByTestId('session-revoke-sess-own')).toBeTruthy();
  });

  it('hides "All actors" toggle when caller lacks auth.session.list.all', async () => {
    vi.mocked(client.listSessions).mockResolvedValue({ sessions: [ownSession] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-alice',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-viewer'],
      effective_permissions: [{ permission: 'auth.session.list', scope_type: 'global' }],
    });
    renderWithProviders(<SessionsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('session-row-sess-own')).toBeTruthy();
    });
    expect(screen.getByTestId('sessions-view-self')).toBeTruthy();
    expect(screen.queryByTestId('sessions-view-all')).toBeNull();
  });

  it('shows "All actors" toggle when caller has auth.session.list.all', async () => {
    vi.mocked(client.listSessions).mockResolvedValue({ sessions: [ownSession] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-admin',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: true,
      roles: ['r-admin'],
      effective_permissions: [
        { permission: 'auth.session.list', scope_type: 'global' },
        { permission: 'auth.session.list.all', scope_type: 'global' },
      ],
    });
    renderWithProviders(<SessionsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('sessions-view-all')).toBeTruthy();
    });
  });

  it('hides revoke button on other-actor sessions without auth.session.revoke', async () => {
    vi.mocked(client.listSessions).mockResolvedValue({ sessions: [ownSession, otherSession] });
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-alice',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-viewer'],
      effective_permissions: [{ permission: 'auth.session.list', scope_type: 'global' }],
    });
    renderWithProviders(<SessionsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('session-row-sess-other')).toBeTruthy();
    });
    expect(screen.getByTestId('session-revoke-sess-own')).toBeTruthy();
    expect(screen.queryByTestId('session-revoke-sess-other')).toBeNull();
  });

  it('clicking revoke calls revokeSession after window.confirm', async () => {
    vi.mocked(client.listSessions).mockResolvedValue({ sessions: [ownSession] });
    vi.mocked(client.revokeSession).mockResolvedValue(undefined);
    vi.mocked(client.authMe).mockResolvedValue({
      actor_id: 'u-alice',
      actor_type: 'User',
      tenant_id: 't-default',
      admin: false,
      roles: ['r-viewer'],
      effective_permissions: [{ permission: 'auth.session.list', scope_type: 'global' }],
    });
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderWithProviders(<SessionsPage />);
    await waitFor(() => {
      expect(screen.getByTestId('session-revoke-sess-own')).toBeTruthy();
    });
    fireEvent.click(screen.getByTestId('session-revoke-sess-own'));
    await waitFor(() => {
      expect(client.revokeSession).toHaveBeenCalledWith('sess-own');
    });
    confirmSpy.mockRestore();
  });
});

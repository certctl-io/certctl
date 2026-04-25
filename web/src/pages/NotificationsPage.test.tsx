import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// I-005: NotificationsPage Phase 1 Red — Dead Letter tab + Requeue action
//
// This file pins the frontend contract Phase 2 Green must implement:
//
//   1. A "Dead letter" tab renders alongside the existing status filter, and
//      selecting it causes the underlying query to fetch with { status: 'dead' }.
//      The tab does not exist at HEAD — the tab-locator assertions are the Red.
//
//   2. Notifications in status='dead' render a "Requeue" action button. HEAD
//      only renders "Mark read" for Pending rows and no action for anything
//      else — the button-locator assertion is the Red.
//
//   3. Clicking "Requeue" invokes requeueNotification(id) from the API client
//      and invalidates the notifications query. `requeueNotification` does not
//      yet exist as an export from ../api/client — tsc --noEmit will fail with
//      "Property 'requeueNotification' does not exist" when Phase 2 Green runs
//      its verification gates, which is the compile-time Red halt. This file is
//      structured so Phase 2 Green's single fix (add the client export + page
//      wiring) flips the entire suite Green at once.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getNotifications: vi.fn(),
  getNotification: vi.fn(),
  markNotificationRead: vi.fn(),
  requeueNotification: vi.fn(),
}));

// Imported after vi.mock so the mock replaces the real module.
import NotificationsPage from './NotificationsPage';
import * as client from '../api/client';

function renderWithQuery(ui: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
    },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

// D-2 (master): pre-D-2 these mocks set `subject:` — the field was a TS
// phantom the Go-side struct never emitted. Post-D-2 the phantom is
// removed from the Notification interface; the mocks no longer set it.
const pendingNotif = {
  id: 'notif-001',
  type: 'ExpirationWarning',
  channel: 'Email',
  recipient: 'admin@example.com',
  message: 'Certificate expiring in 7 days',
  status: 'Pending',
  certificate_id: 'mc-prod-001',
  created_at: new Date().toISOString(),
};

const deadNotif = {
  id: 'notif-dead-001',
  type: 'ExpirationWarning',
  channel: 'Email',
  recipient: 'admin@example.com',
  message: 'Certificate expiring in 7 days',
  status: 'dead',
  certificate_id: 'mc-prod-001',
  created_at: new Date().toISOString(),
  retry_count: 5,
  last_error: 'SMTP connection refused',
};

describe('NotificationsPage — I-005 Dead Letter + Requeue (Phase 1 Red)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
  });

  it('renders a Dead letter tab in the filter toolbar', async () => {
    vi.mocked(client.getNotifications).mockResolvedValue({
      data: [pendingNotif],
      total: 1,
      page: 1,
      per_page: 100,
    });

    renderWithQuery(<NotificationsPage />);

    await waitFor(() => {
      expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
    });

    // Red: no Dead letter tab exists at HEAD. Phase 2 Green adds a button/tab
    // labeled "Dead letter" (matches docs/testing-guide UI label).
    expect(screen.getByRole('button', { name: /Dead letter/i })).toBeInTheDocument();
  });

  it('clicking Dead letter tab fetches notifications with status=dead', async () => {
    vi.mocked(client.getNotifications).mockResolvedValue({
      data: [],
      total: 0,
      page: 1,
      per_page: 100,
    });

    renderWithQuery(<NotificationsPage />);

    await waitFor(() => {
      expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
    });

    const tab = screen.getByRole('button', { name: /Dead letter/i });
    fireEvent.click(tab);

    // Red: Phase 2 Green must route the Dead letter tab's query through
    // getNotifications({ status: 'dead', per_page: '100' }). HEAD only ever
    // calls getNotifications({ per_page: '100' }) — no status param is ever
    // passed through.
    await waitFor(() => {
      const calls = vi.mocked(client.getNotifications).mock.calls;
      const deadCall = calls.find(([params]) => (params as Record<string, string>)?.status === 'dead');
      expect(deadCall, 'expected getNotifications to be called with status=dead').toBeTruthy();
    });
  });

  it('renders a Requeue button on dead notifications', async () => {
    vi.mocked(client.getNotifications).mockResolvedValue({
      data: [deadNotif],
      total: 1,
      page: 1,
      per_page: 100,
    });

    renderWithQuery(<NotificationsPage />);

    await waitFor(() => {
      expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
    });

    // Switch to Dead letter tab so the mocked dead notification becomes visible.
    const tab = screen.getByRole('button', { name: /Dead letter/i });
    fireEvent.click(tab);

    await waitFor(() => {
      // Red: HEAD renders no action for status='dead'. Phase 2 Green adds a
      // "Requeue" button next to each dead row.
      expect(screen.getByRole('button', { name: /Requeue/i })).toBeInTheDocument();
    });
  });

  it('clicking Requeue invokes requeueNotification(id) from the API client', async () => {
    vi.mocked(client.getNotifications).mockResolvedValue({
      data: [deadNotif],
      total: 1,
      page: 1,
      per_page: 100,
    });
    vi.mocked(client.requeueNotification).mockResolvedValue({ status: 'requeued' });

    renderWithQuery(<NotificationsPage />);

    await waitFor(() => {
      expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Dead letter/i }));

    const requeueBtn = await screen.findByRole('button', { name: /Requeue/i });
    fireEvent.click(requeueBtn);

    // Red: client.requeueNotification is not an exported function at HEAD, and
    // the page does not call it. Both the mock and the page wiring are added
    // in Phase 2 Green.
    await waitFor(() => {
      expect(client.requeueNotification).toHaveBeenCalledWith('notif-dead-001');
    });
  });

  it('dead notifications surface retry_count and last_error metadata', async () => {
    vi.mocked(client.getNotifications).mockResolvedValue({
      data: [deadNotif],
      total: 1,
      page: 1,
      per_page: 100,
    });

    renderWithQuery(<NotificationsPage />);

    await waitFor(() => {
      expect(screen.queryByText(/Loading/i)).not.toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Dead letter/i }));

    await waitFor(() => {
      // Red: HEAD does not display retry_count or last_error. Phase 2 Green
      // must surface these so operators can see *why* a notification died.
      expect(screen.getByText(/SMTP connection refused/i)).toBeInTheDocument();
      expect(screen.getByText(/5/)).toBeInTheDocument();
    });
  });
});

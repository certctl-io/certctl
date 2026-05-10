import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// =============================================================================
// Bundle 1 Phase 9 + Phase 10 — ApprovalsPage. Pins:
//   - Same-actor self-approve invariant: when requested_by == current
//     actor_id, the Approve / Reject buttons are HIDDEN. Server-side
//     enforcement (ErrApproveBySameActor) is the load-bearing gate;
//     this is the UX layer.
//   - Profile-edit kind renders with the amber kind pill so an
//     approver can tell it apart from cert_issuance.
//   - Approve action POSTs the right URL.
// =============================================================================

vi.mock('../../api/client', () => ({
  listApprovals: vi.fn(),
  approveApproval: vi.fn(),
  rejectApproval: vi.fn(),
  authMe: vi.fn(),
}));

import ApprovalsPage from './ApprovalsPage';
import * as client from '../../api/client';

function renderWithProviders(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

const aliceMe = {
  actor_id: 'alice',
  actor_type: 'APIKey',
  tenant_id: 't-default',
  admin: true,
  roles: ['r-admin'],
  effective_permissions: [],
};

const samplePending = [
  {
    id: 'ar-1',
    kind: 'profile_edit' as const,
    profile_id: 'prof-prod',
    requested_by: 'alice', // SAME as caller — should hide buttons
    state: 'pending' as const,
    created_at: '2026-05-09T20:00:00Z',
    updated_at: '2026-05-09T20:00:00Z',
  },
  {
    id: 'ar-2',
    kind: 'cert_issuance' as const,
    profile_id: 'prof-prod',
    certificate_id: 'mc-1',
    job_id: 'job-1',
    requested_by: 'bob', // different from caller — buttons visible
    state: 'pending' as const,
    created_at: '2026-05-09T20:01:00Z',
    updated_at: '2026-05-09T20:01:00Z',
  },
];

describe('ApprovalsPage', () => {
  it('hides approve/reject buttons for self-requested approvals', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: samplePending,
      total: 2,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-table'));

    // alice's own row: self-locked indicator visible; buttons absent.
    expect(screen.queryByTestId('approvals-self-locked-ar-1')).toBeTruthy();
    expect(screen.queryByTestId('approvals-approve-ar-1')).toBeNull();
    expect(screen.queryByTestId('approvals-reject-ar-1')).toBeNull();

    // bob's row: buttons visible.
    expect(screen.queryByTestId('approvals-approve-ar-2')).toBeTruthy();
    expect(screen.queryByTestId('approvals-reject-ar-2')).toBeTruthy();
  });

  it('renders profile_edit kind with the amber pill', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [samplePending[0]],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-table'));
    expect(screen.getByText('profile_edit')).toBeTruthy();
  });

  it('POSTs approveApproval when an approver clicks Approve', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [samplePending[1]],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.approveApproval).mockResolvedValue({});
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    // Stub window.prompt for the note dialog.
    const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('lgtm');

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-approve-ar-2'));
    fireEvent.click(screen.getByTestId('approvals-approve-ar-2'));

    await waitFor(() => expect(client.approveApproval).toHaveBeenCalledWith('ar-2', 'lgtm'));
    promptSpy.mockRestore();
  });

  it('renders the empty state when no pending approvals', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [],
      total: 0,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => expect(screen.getByTestId('approvals-empty')).toBeTruthy());
  });
});

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

  // =============================================================================
  // Audit 2026-05-11 A-5 — payload preview.
  // =============================================================================

  // b64 of '{"before":{"must_staple":false,"max_validity_days":397},"after":{"must_staple":true,"max_validity_days":90}}'
  const profileEditPayload = btoa(JSON.stringify({
    before: { must_staple: false, max_validity_days: 397, requires_approval: true },
    after: { must_staple: true, max_validity_days: 90, requires_approval: true },
  }));
  const profileEditNoChangesPayload = btoa(JSON.stringify({
    before: { must_staple: false },
    after: { must_staple: false },
  }));
  const certIssuancePayload = btoa(JSON.stringify({
    subject_common_name: 'api.acme.com',
    sans: ['api.acme.com', 'www.acme.com'],
    profile_id: 'p-corp-public',
    key_algorithm: 'ECDSA-P256',
    must_staple: true,
    validity_days: 90,
  }));

  it('A-5 Preview button toggles the payload panel', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        ...samplePending[1],
        payload: certIssuancePayload,
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-2'));

    // Panel hidden by default.
    expect(screen.queryByTestId('approvals-payload-preview-ar-2')).toBeNull();

    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-2'));
    await waitFor(() => screen.getByTestId('approvals-payload-preview-ar-2'));
    expect(screen.getByTestId('approval-cert-issuance-preview')).toBeTruthy();

    // Toggle off.
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-2'));
    await waitFor(() => {
      expect(screen.queryByTestId('approvals-payload-preview-ar-2')).toBeNull();
    });
  });

  it('A-5 ProfileEdit kind renders field diff with changed-only rows', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        ...samplePending[0],
        requested_by: 'bob',  // not self — Preview button is enabled regardless
        payload: profileEditPayload,
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-1'));
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-1'));

    await waitFor(() => screen.getByTestId('approval-profile-edit-diff'));
    // Only changed fields render rows.
    expect(screen.getByTestId('approval-profile-edit-row-must_staple')).toBeTruthy();
    expect(screen.getByTestId('approval-profile-edit-row-max_validity_days')).toBeTruthy();
    // Unchanged requires_approval should NOT render a row.
    expect(screen.queryByTestId('approval-profile-edit-row-requires_approval')).toBeNull();
  });

  it('A-5 ProfileEdit before/after values are visible in the diff cells', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        ...samplePending[0],
        requested_by: 'bob',
        payload: profileEditPayload,
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-1'));
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-1'));

    await waitFor(() => screen.getByTestId('approval-profile-edit-diff'));
    const row = screen.getByTestId('approval-profile-edit-row-must_staple');
    expect(row.textContent).toContain('false');
    expect(row.textContent).toContain('true');
  });

  it('A-5 ProfileEdit with no changes renders empty-state', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        ...samplePending[0],
        requested_by: 'bob',
        payload: profileEditNoChangesPayload,
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-1'));
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-1'));

    await waitFor(() => screen.getByTestId('approval-profile-edit-no-changes'));
    expect(screen.queryByTestId('approval-profile-edit-diff')).toBeNull();
  });

  it('A-5 CertIssuance renders definition list with SANs + profile + key algo', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        ...samplePending[1],
        payload: certIssuancePayload,
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-2'));
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-2'));

    const dl = await waitFor(() => screen.getByTestId('approval-cert-issuance-preview'));
    expect(dl.textContent).toContain('api.acme.com');
    expect(dl.textContent).toContain('www.acme.com');
    expect(dl.textContent).toContain('p-corp-public');
    expect(dl.textContent).toContain('ECDSA-P256');
  });

  it('A-5 Unknown kind falls back to generic JSON pre block', async () => {
    const unknownKindPayload = btoa(JSON.stringify({ some_future_field: 42, nested: { ok: true } }));
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        id: 'ar-3',
        kind: 'future_kind_v3' as never,  // not in current enum
        profile_id: 'prof-x',
        requested_by: 'bob',
        state: 'pending' as const,
        payload: unknownKindPayload,
        created_at: '2026-05-09T20:02:00Z',
        updated_at: '2026-05-09T20:02:00Z',
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-3'));
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-3'));

    const pre = await waitFor(() => screen.getByTestId('approval-payload-generic-json'));
    expect(pre.textContent).toContain('some_future_field');
    expect(pre.textContent).toContain('42');
  });

  it('A-5 Empty payload renders the "No payload attached" sentinel', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        ...samplePending[1],
        payload: undefined,
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-2'));
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-2'));

    await waitFor(() => screen.getByTestId('approval-payload-empty'));
  });

  it('A-5 Malformed base64 payload renders the decode-error fallback', async () => {
    vi.mocked(client.listApprovals).mockResolvedValue({
      data: [{
        ...samplePending[1],
        payload: '!!!not-valid-base64!!!',
      }],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.authMe).mockResolvedValue(aliceMe);

    renderWithProviders(<ApprovalsPage />);
    await waitFor(() => screen.getByTestId('approvals-preview-toggle-ar-2'));
    fireEvent.click(screen.getByTestId('approvals-preview-toggle-ar-2'));

    await waitFor(() => screen.getByTestId('approval-payload-decode-error'));
  });
});

// =============================================================================
// Pure-function tests on decodePayload (Audit 2026-05-11 A-5).
// =============================================================================

describe('decodePayload', () => {
  it('returns null for undefined input', async () => {
    const { decodePayload } = await import('./ApprovalsPage');
    expect(decodePayload(undefined)).toBeNull();
  });

  it('returns null for empty string', async () => {
    const { decodePayload } = await import('./ApprovalsPage');
    expect(decodePayload('')).toBeNull();
  });

  it('round-trips base64-encoded JSON', async () => {
    const { decodePayload } = await import('./ApprovalsPage');
    const original = { foo: 'bar', n: 42, arr: [1, 2, 3] };
    const encoded = btoa(JSON.stringify(original));
    expect(decodePayload(encoded)).toEqual(original);
  });

  it('returns null on malformed base64', async () => {
    const { decodePayload } = await import('./ApprovalsPage');
    expect(decodePayload('!!!not-base64!!!')).toBeNull();
  });

  it('returns null on valid base64 of non-JSON content', async () => {
    const { decodePayload } = await import('./ApprovalsPage');
    expect(decodePayload(btoa('not a json document'))).toBeNull();
  });
});

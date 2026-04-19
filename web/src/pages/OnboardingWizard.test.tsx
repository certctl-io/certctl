import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

// -----------------------------------------------------------------------------
// UX-001 Phase 3 — CertificateStep inline team + owner creation contract
//
// The wizard has to satisfy C-001's six required certificate fields (name,
// common_name, issuer_id, owner_id, team_id, renewal_policy_id). Before Phase
// 3, a fresh install had no teams + no owners, so the two required `<select>`s
// were empty and the only way forward was to leave the wizard (losing state)
// and visit /owners + /teams. The inline modals close that dead end by letting
// users create a team or owner without leaving CertificateStep.
//
// These tests pin the contract on the inline modals specifically:
//
//   1. Skip-skip navigation reaches CertificateStep with the "+ New team" and
//      "+ New owner" buttons present.
//   2. "+ New team" opens the inline modal; submit calls `createTeam`, the
//      React Query cache invalidates, and the parent team `<select>` auto-
//      selects the new team's id.
//   3. "+ New owner" does the same for owners.
//   4. Cancel closes the modal without firing the mutation — pins the
//      "nothing leaks on abort" guarantee.
//
// DashboardPage's outer wizard entry/exit contract is covered in
// DashboardPage.test.tsx. Layout's sidebar re-entry button is covered in
// Layout.test.tsx.
// -----------------------------------------------------------------------------

// Mock the entire API client. vi.mock factories are hoisted above the imports
// that follow, so these stubs are in effect when OnboardingWizard's module
// graph resolves.
vi.mock('../api/client', () => ({
  getApiKey: vi.fn(() => 'test-api-key'),
  getIssuers: vi.fn(),
  getAgents: vi.fn(),
  getProfiles: vi.fn(),
  getOwners: vi.fn(),
  getTeams: vi.fn(),
  getPolicies: vi.fn(),
  createIssuer: vi.fn(),
  testIssuerConnection: vi.fn(),
  createCertificate: vi.fn(),
  triggerRenewal: vi.fn(),
  createTeam: vi.fn(),
  createOwner: vi.fn(),
}));

import OnboardingWizard from './OnboardingWizard';
import * as client from '../api/client';

function renderWizard() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
    },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/']}>
        <OnboardingWizard onDismiss={vi.fn()} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// Canonical "empty but well-formed" stubs for every query the wizard calls.
// Returning data (rather than leaving queries pending) lets CertificateStep's
// dropdowns render their placeholder options immediately.
function stubAllQueriesEmpty() {
  vi.mocked(client.getIssuers).mockResolvedValue({
    data: [], total: 0, page: 1, per_page: 100,
  } as never);
  vi.mocked(client.getAgents).mockResolvedValue({
    data: [], total: 0, page: 1, per_page: 100,
  } as never);
  vi.mocked(client.getProfiles).mockResolvedValue({
    data: [], total: 0, page: 1, per_page: 100,
  } as never);
  vi.mocked(client.getOwners).mockResolvedValue({
    data: [], total: 0, page: 1, per_page: 500,
  } as never);
  vi.mocked(client.getTeams).mockResolvedValue({
    data: [], total: 0, page: 1, per_page: 500,
  } as never);
  vi.mocked(client.getPolicies).mockResolvedValue({
    data: [], total: 0, page: 1, per_page: 500,
  } as never);
}

// Drive through Skip to reach CertificateStep. Each step renders its own
// "Skip this step" button in the WizardFooter; clicking it advances via the
// parent goTo() state machine. "Skip setup" in the header (top-right) is a
// different button tied to onDismiss and is intentionally not clicked here.
async function advanceToCertificateStep() {
  // IssuerStep renders first. Wait for its heading before clicking skip so
  // we don't race ahead of the initial render.
  await waitFor(() => {
    expect(
      screen.getByRole('heading', { name: /Connect a Certificate Authority/i }),
    ).toBeInTheDocument();
  });
  fireEvent.click(screen.getByRole('button', { name: /Skip this step/i }));

  // AgentStep — wait for its heading, then skip.
  await waitFor(() => {
    expect(
      screen.getByRole('heading', { name: /Deploy a certctl Agent/i }),
    ).toBeInTheDocument();
  });
  fireEvent.click(screen.getByRole('button', { name: /Skip this step/i }));

  // CertificateStep — wait for its heading. Caller can now exercise the
  // inline modals.
  await waitFor(() => {
    expect(
      screen.getByRole('heading', { name: /Add a Certificate/i }),
    ).toBeInTheDocument();
  });
}

describe('OnboardingWizard — UX-001 inline team + owner creation in CertificateStep', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    stubAllQueriesEmpty();
  });

  it('skip-skip reaches CertificateStep with "+ New team" and "+ New owner" buttons', async () => {
    renderWizard();
    await advanceToCertificateStep();

    // The contract buttons are the whole point of UX-001 Phase 3 — if they
    // disappear, the dead-end is back.
    expect(screen.getByRole('button', { name: /\+ New team/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /\+ New owner/i })).toBeInTheDocument();
  });

  it('+ New team opens the inline modal, calls createTeam, invalidates the cache, and auto-selects the new team', async () => {
    // Drive getTeams from a closure variable so React Query's post-mutation
    // refetch observes the newly-created team. Without this, the parent
    // <select> would auto-select 't-platform' but the DOM would have no
    // matching <option> and the browser normalizes select.value back to ''.
    let teamsData: Array<{
      id: string; name: string; description: string; created_at: string; updated_at: string;
    }> = [];
    vi.mocked(client.getTeams).mockImplementation(() =>
      Promise.resolve({
        data: teamsData,
        total: teamsData.length,
        page: 1,
        per_page: 500,
      } as never),
    );

    vi.mocked(client.createTeam).mockImplementation(async (data) => {
      const team = {
        id: 't-platform',
        name: data?.name ?? 'unnamed',
        description: data?.description ?? '',
        created_at: '2026-04-19T00:00:00Z',
        updated_at: '2026-04-19T00:00:00Z',
      };
      // Mutate the closure so the subsequent invalidation-triggered refetch
      // of ['teams'] returns the new row. Per
      // OnboardingWizard.tsx:411-419 the success branch invalidates
      // queryKey ['teams'] before firing onCreated(team.id) + onClose().
      teamsData = [team];
      return team as never;
    });

    renderWizard();
    await advanceToCertificateStep();

    // Open the inline team modal.
    fireEvent.click(screen.getByRole('button', { name: /\+ New team/i }));

    // Modal is open — "Create Team" heading + the autofocused Name input
    // are both present.
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Create Team/i })).toBeInTheDocument();
    });
    const nameInput = screen.getByPlaceholderText(/Platform Engineering/i);
    fireEvent.change(nameInput, { target: { value: 'Platform Eng' } });

    // Submit — anchored regex so we don't accidentally match "+ New team"
    // or any "Create Team" banner elsewhere on the page.
    fireEvent.click(screen.getByRole('button', { name: /^Create Team$/ }));

    // Mutation fires with trimmed name + empty description — mirrors the
    // contract in OnboardingWizard.tsx:411.
    await waitFor(() => {
      expect(vi.mocked(client.createTeam)).toHaveBeenCalledWith({
        name: 'Platform Eng',
        description: '',
      });
    });

    // Modal tears down on success (onClose() in the mutation's onSuccess).
    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: /Create Team/i })).not.toBeInTheDocument();
    });

    // Parent <select> auto-selected the new team. Locate the select by
    // finding the new team's <option> (which only exists on the parent
    // form's team dropdown after the refetch populates it), then assert
    // the select's current value is the new id. This avoids relying on
    // label-for-select association, which the current markup doesn't
    // provide (label is a sibling, not htmlFor-linked).
    const newTeamOption = await screen.findByRole('option', { name: /Platform Eng/i });
    const teamSelect = newTeamOption.closest('select') as HTMLSelectElement;
    expect(teamSelect).not.toBeNull();
    await waitFor(() => {
      expect(teamSelect.value).toBe('t-platform');
    });
  });

  it('+ New owner opens the inline modal, calls createOwner, invalidates the cache, and auto-selects the new owner', async () => {
    let ownersData: Array<{
      id: string; name: string; email: string; team_id: string;
      created_at: string; updated_at: string;
    }> = [];
    vi.mocked(client.getOwners).mockImplementation(() =>
      Promise.resolve({
        data: ownersData,
        total: ownersData.length,
        page: 1,
        per_page: 500,
      } as never),
    );

    vi.mocked(client.createOwner).mockImplementation(async (data) => {
      const owner = {
        id: 'o-alice',
        name: data?.name ?? 'unnamed',
        email: data?.email ?? '',
        team_id: data?.team_id ?? '',
        created_at: '2026-04-19T00:00:00Z',
        updated_at: '2026-04-19T00:00:00Z',
      };
      ownersData = [owner];
      return owner as never;
    });

    renderWizard();
    await advanceToCertificateStep();

    fireEvent.click(screen.getByRole('button', { name: /\+ New owner/i }));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Create Owner/i })).toBeInTheDocument();
    });

    fireEvent.change(screen.getByPlaceholderText(/Alice Chen/i), {
      target: { value: 'Alice Chen' },
    });
    fireEvent.change(screen.getByPlaceholderText(/alice@example\.com/i), {
      target: { value: 'alice@example.com' },
    });

    fireEvent.click(screen.getByRole('button', { name: /^Create Owner$/ }));

    // Per OnboardingWizard.tsx:485-489, team_id is coerced to `undefined`
    // when the optional Team select is left at its default empty value —
    // otherwise the server would see `team_id: ""` and 400 on an invalid
    // FK. This assertion pins that coercion.
    await waitFor(() => {
      expect(vi.mocked(client.createOwner)).toHaveBeenCalledWith({
        name: 'Alice Chen',
        email: 'alice@example.com',
        team_id: undefined,
      });
    });

    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: /Create Owner/i })).not.toBeInTheDocument();
    });

    // Parent Owner <select> auto-selects the new owner. Option text format
    // from OnboardingWizard.tsx:754-756 is `{name}{email ? ` (${email})` : ''}`
    // — "Alice Chen (alice@example.com)".
    const newOwnerOption = await screen.findByRole('option', { name: /Alice Chen/i });
    const ownerSelect = newOwnerOption.closest('select') as HTMLSelectElement;
    expect(ownerSelect).not.toBeNull();
    await waitFor(() => {
      expect(ownerSelect.value).toBe('o-alice');
    });
  });

  it('cancel on the team modal closes it without firing createTeam', async () => {
    renderWizard();
    await advanceToCertificateStep();

    fireEvent.click(screen.getByRole('button', { name: /\+ New team/i }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Create Team/i })).toBeInTheDocument();
    });

    // Cancel button is the modal's second footer button — anchored regex to
    // avoid matching any stray "Cancel" on the page.
    fireEvent.click(screen.getByRole('button', { name: /^Cancel$/ }));

    // Modal tears down and the mutation never fires — abort is clean.
    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: /Create Team/i })).not.toBeInTheDocument();
    });
    expect(vi.mocked(client.createTeam)).not.toHaveBeenCalled();
  });
});

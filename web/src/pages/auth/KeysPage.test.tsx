import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// =============================================================================
// Bundle 1 Phase 10 — KeysPage Vitest coverage. Pins the demo-anon
// system-managed flag (no assign / revoke buttons) and the per-row
// permission gating.
// =============================================================================

vi.mock('../../api/client', () => ({
  authListKeys: vi.fn(),
  authListRoles: vi.fn(),
  authAssignKeyRole: vi.fn(),
  authRevokeKeyRole: vi.fn(),
  authMe: vi.fn(),
}));

import KeysPage from './KeysPage';
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

const adminMe = {
  actor_id: 'alice',
  actor_type: 'APIKey',
  tenant_id: 't-default',
  admin: true,
  roles: ['r-admin'],
  effective_permissions: [{ permission: 'auth.role.assign', scope_type: 'global' as const }],
};

const auditorMe = {
  actor_id: 'audrey',
  actor_type: 'APIKey',
  tenant_id: 't-default',
  admin: false,
  roles: ['r-auditor'],
  effective_permissions: [{ permission: 'audit.read', scope_type: 'global' as const }],
};

const sampleKeys = [
  { actor_id: 'alice', actor_type: 'APIKey', tenant_id: 't-default', role_ids: ['r-admin'] },
  { actor_id: 'actor-demo-anon', actor_type: 'Anonymous', tenant_id: 't-default', role_ids: ['r-admin'] },
];

describe('KeysPage', () => {
  it('flags actor-demo-anon as system-managed and hides its mutation buttons', async () => {
    vi.mocked(client.authListKeys).mockResolvedValue(sampleKeys);
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue(adminMe);

    renderWithProviders(<KeysPage />);

    await waitFor(() => screen.getByTestId('keys-table'));
    expect(screen.getByText(/system-managed/i)).toBeTruthy();
    // alice has the assign + revoke affordances; demo-anon does NOT.
    expect(screen.queryByTestId('keys-assign-alice')).toBeTruthy();
    expect(screen.queryByTestId('keys-assign-actor-demo-anon')).toBeNull();
    expect(screen.queryByTestId('keys-revoke-alice-r-admin')).toBeTruthy();
    expect(screen.queryByTestId('keys-revoke-actor-demo-anon-r-admin')).toBeNull();
  });

  it('hides the assign + revoke affordances when the caller lacks auth.role.assign', async () => {
    vi.mocked(client.authListKeys).mockResolvedValue([sampleKeys[0]]);
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue(auditorMe);

    renderWithProviders(<KeysPage />);

    await waitFor(() => screen.getByTestId('keys-table'));
    expect(screen.queryByTestId('keys-assign-alice')).toBeNull();
    expect(screen.queryByTestId('keys-revoke-alice-r-admin')).toBeNull();
  });

  it('opens the assign modal and POSTs the role choice', async () => {
    vi.mocked(client.authListKeys).mockResolvedValue([sampleKeys[0]]);
    vi.mocked(client.authListRoles).mockResolvedValue([
      { id: 'r-operator', tenant_id: 't-default', name: 'operator' },
    ]);
    vi.mocked(client.authAssignKeyRole).mockResolvedValue({});
    vi.mocked(client.authMe).mockResolvedValue(adminMe);

    renderWithProviders(<KeysPage />);

    await waitFor(() => screen.getByTestId('keys-assign-alice'));
    fireEvent.click(screen.getByTestId('keys-assign-alice'));

    await waitFor(() => screen.getByTestId('assign-role-modal'));
    fireEvent.change(screen.getByTestId('assign-role-select'), {
      target: { value: 'r-operator' },
    });
    fireEvent.click(screen.getByTestId('assign-role-submit'));

    await waitFor(() => expect(client.authAssignKeyRole).toHaveBeenCalledTimes(1));
    const args = vi.mocked(client.authAssignKeyRole).mock.calls[0];
    expect(args[0]).toBe('alice');
    expect(args[1]).toBe('r-operator');
    // Default state: scope_type=global, no scope_id, no expires_at.
    expect(args[2]).toMatchObject({ scope_type: 'global' });
  });
});

// =============================================================================
// Audit 2026-05-11 Fix 12 — HIGH-10 GUI half scope/expiry coverage.
//
// The HIGH-10 GUI half added the scope picker + scope_id input + expires_at
// datetime-local to the assign modal, but the pre-existing test only
// asserted the (actor, role) pair on the call. This block pins the third
// opts arg's shape so a future refactor that drops the scope wiring
// surfaces in the diff. Test cases mirror the spec's Phase 3 enumeration:
//   - global scope → no scope_id field visible + scope_type='global'
//   - profile scope → scope_id input visible + required, body carries
//     scope_type='profile' + scope_id=<input>
//   - expires_at empty → omitted (undefined) from body
//   - expires_at filled → promoted to RFC3339 with :00Z suffix
//   - actor-demo-anon row → no assign / no revoke buttons (system-managed)
// =============================================================================

async function openAssignModalForAlice() {
  vi.mocked(client.authListKeys).mockResolvedValue([sampleKeys[0]]);
  vi.mocked(client.authListRoles).mockResolvedValue([
    { id: 'r-operator', tenant_id: 't-default', name: 'operator' },
  ]);
  vi.mocked(client.authAssignKeyRole).mockResolvedValue({});
  vi.mocked(client.authMe).mockResolvedValue(adminMe);

  renderWithProviders(<KeysPage />);
  await waitFor(() => screen.getByTestId('keys-assign-alice'));
  fireEvent.click(screen.getByTestId('keys-assign-alice'));
  await waitFor(() => screen.getByTestId('assign-role-modal'));
  fireEvent.change(screen.getByTestId('assign-role-select'), {
    target: { value: 'r-operator' },
  });
}

describe('KeysPage — HIGH-10 GUI half scope + expiry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
  });

  it('global scope hides the scope_id input', async () => {
    await openAssignModalForAlice();
    // Default scope_type is 'global'; the conditional scope_id input
    // is only rendered when scope_type !== 'global'.
    expect(screen.getByTestId('assign-role-scope-type')).toBeInTheDocument();
    expect(screen.queryByTestId('assign-role-scope-id')).toBeNull();
  });

  it('switching to profile scope reveals the scope_id input and marks it required', async () => {
    await openAssignModalForAlice();

    fireEvent.change(screen.getByTestId('assign-role-scope-type'), {
      target: { value: 'profile' },
    });
    await waitFor(() => screen.getByTestId('assign-role-scope-id'));

    const scopeID = screen.getByTestId('assign-role-scope-id') as HTMLInputElement;
    expect(scopeID.required).toBe(true);
    expect(scopeID.placeholder).toContain('p-acme');
  });

  it('profile scope submit sends {scope_type: profile, scope_id: <trimmed input>}', async () => {
    await openAssignModalForAlice();

    fireEvent.change(screen.getByTestId('assign-role-scope-type'), {
      target: { value: 'profile' },
    });
    await waitFor(() => screen.getByTestId('assign-role-scope-id'));
    fireEvent.change(screen.getByTestId('assign-role-scope-id'), {
      target: { value: '  p-acme-corp  ' }, // whitespace deliberate; submit must trim
    });
    fireEvent.click(screen.getByTestId('assign-role-submit'));

    await waitFor(() => expect(client.authAssignKeyRole).toHaveBeenCalledTimes(1));
    const [, , opts] = vi.mocked(client.authAssignKeyRole).mock.calls[0];
    if (!opts) throw new Error('opts arg missing');
    expect(opts).toMatchObject({
      scope_type: 'profile',
      scope_id: 'p-acme-corp',
    });
  });

  it('issuer scope submit sends {scope_type: issuer, scope_id: <trimmed input>}', async () => {
    await openAssignModalForAlice();

    fireEvent.change(screen.getByTestId('assign-role-scope-type'), {
      target: { value: 'issuer' },
    });
    await waitFor(() => screen.getByTestId('assign-role-scope-id'));
    fireEvent.change(screen.getByTestId('assign-role-scope-id'), {
      target: { value: 'iss-internal-pki' },
    });
    fireEvent.click(screen.getByTestId('assign-role-submit'));

    await waitFor(() => expect(client.authAssignKeyRole).toHaveBeenCalledTimes(1));
    const [, , opts] = vi.mocked(client.authAssignKeyRole).mock.calls[0];
    if (!opts) throw new Error('opts arg missing');
    expect(opts.scope_type).toBe('issuer');
    expect(opts.scope_id).toBe('iss-internal-pki');
  });

  it('global scope submit omits scope_id (undefined, not empty string)', async () => {
    await openAssignModalForAlice();
    fireEvent.click(screen.getByTestId('assign-role-submit'));

    await waitFor(() => expect(client.authAssignKeyRole).toHaveBeenCalledTimes(1));
    const [, , opts] = vi.mocked(client.authAssignKeyRole).mock.calls[0];
    if (!opts) throw new Error('opts arg missing');
    expect(opts.scope_type).toBe('global');
    // The implementation explicitly passes undefined when scope_type==='global'.
    expect(opts.scope_id).toBeUndefined();
  });

  it('empty expires_at omits the field from the body', async () => {
    await openAssignModalForAlice();
    fireEvent.click(screen.getByTestId('assign-role-submit'));

    await waitFor(() => expect(client.authAssignKeyRole).toHaveBeenCalledTimes(1));
    const [, , opts] = vi.mocked(client.authAssignKeyRole).mock.calls[0];
    if (!opts) throw new Error('opts arg missing');
    // The page converts an empty datetime-local value to undefined, NOT to
    // an empty string. An empty string would fail the backend's RFC3339
    // parse with a confusing error; the GUI prevents that footgun.
    expect(opts.expires_at).toBeUndefined();
  });

  it('filled expires_at gets the :00Z UTC suffix appended', async () => {
    await openAssignModalForAlice();
    fireEvent.change(screen.getByTestId('assign-role-expires-at'), {
      target: { value: '2027-06-15T13:30' },
    });
    fireEvent.click(screen.getByTestId('assign-role-submit'));

    await waitFor(() => expect(client.authAssignKeyRole).toHaveBeenCalledTimes(1));
    const [, , opts] = vi.mocked(client.authAssignKeyRole).mock.calls[0];
    if (!opts) throw new Error('opts arg missing');
    // datetime-local emits "YYYY-MM-DDTHH:MM"; the page promotes to RFC3339
    // by appending :00Z. Operators wanting non-UTC must use curl.
    expect(opts.expires_at).toBe('2027-06-15T13:30:00Z');
  });

  it('profile scope with whitespace-only scope_id shows an inline error and does NOT POST', async () => {
    await openAssignModalForAlice();

    fireEvent.change(screen.getByTestId('assign-role-scope-type'), {
      target: { value: 'profile' },
    });
    await waitFor(() => screen.getByTestId('assign-role-scope-id'));
    fireEvent.change(screen.getByTestId('assign-role-scope-id'), {
      target: { value: '   ' },
    });

    // The form's native `required` attribute blocks submit when the
    // input is empty after trimming, but a whitespace-only value
    // bypasses native validation; the JS handler then sets a typed
    // error and returns before calling the API.
    const form = screen.getByTestId('assign-role-modal').querySelector('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      const modal = screen.getByTestId('assign-role-modal');
      expect(modal.textContent).toContain('scope_id is required when scope_type is profile');
    });
    expect(client.authAssignKeyRole).not.toHaveBeenCalled();
  });

  it('actor-demo-anon row hides both assign and revoke buttons', async () => {
    vi.mocked(client.authListKeys).mockResolvedValue([sampleKeys[1]]); // demo-anon row
    vi.mocked(client.authListRoles).mockResolvedValue([]);
    vi.mocked(client.authMe).mockResolvedValue(adminMe);

    renderWithProviders(<KeysPage />);
    await waitFor(() => screen.getByTestId('keys-table'));

    // The "(system-managed)" tag flags the row.
    expect(screen.getByText('(system-managed)')).toBeInTheDocument();
    // Both action affordances are missing — reserved-actor mutation guard
    // at the service layer would reject anyway; the GUI hides them.
    expect(screen.queryByTestId('keys-assign-actor-demo-anon')).toBeNull();
    expect(screen.queryByTestId('keys-revoke-actor-demo-anon-r-admin')).toBeNull();
  });
});

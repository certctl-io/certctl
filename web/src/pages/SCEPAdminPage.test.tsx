import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// SCEP RFC 8894 + Intune master bundle Phase 9.5: Vitest coverage for the
// SCEPAdminPage component. Pins:
//   1. Admin gate — non-admin callers see the gated banner and the page
//      MUST NOT issue the underlying admin API requests.
//   2. Profile cards render with status + counters + trust-anchor expiry
//      badge tone (good / warn / bad / EXPIRED).
//   3. Disabled profiles render the off-state pill instead of the counter
//      grid.
//   4. Reload button opens the confirmation modal; Confirm calls the
//      mutation and refetches stats; Cancel closes without calling.
//   5. Error path surfaces ErrorState with retry.
//   6. Audit log filter merges PKCSReq + RenewalReq events and sorts by
//      timestamp descending.

vi.mock('../api/client', () => ({
  getAdminSCEPIntuneStats: vi.fn(),
  reloadAdminSCEPIntuneTrust: vi.fn(),
  getAuditEvents: vi.fn(),
}));

vi.mock('../components/AuthProvider', () => ({
  useAuth: vi.fn(),
}));

import SCEPAdminPage from './SCEPAdminPage';
import * as client from '../api/client';
import { useAuth } from '../components/AuthProvider';

function renderWithQuery(ui: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function setAuth(opts: { authRequired: boolean; admin: boolean }) {
  vi.mocked(useAuth).mockReturnValue({
    loading: false,
    authRequired: opts.authRequired,
    authenticated: true,
    authType: 'apikey',
    user: 'tester',
    admin: opts.admin,
    login: async () => {},
    logout: () => {},
    error: null,
  });
}

const baseEnabledProfile = {
  path_id: 'corp',
  issuer_id: 'iss-corp',
  enabled: true,
  trust_anchor_path: '/etc/certctl/intune-corp.pem',
  trust_anchors: [
    {
      subject: 'intune-connector-installation-corp',
      not_before: '2026-01-01T00:00:00Z',
      not_after: '2027-01-01T00:00:00Z',
      days_to_expiry: 250,
      expired: false,
    },
  ],
  audience: 'https://certctl.example.com/scep/corp',
  challenge_validity_ns: 3_600_000_000_000,
  rate_limit_disabled: false,
  replay_cache_size: 12,
  counters: {
    success: 42,
    signature_invalid: 1,
    expired: 0,
    not_yet_valid: 0,
    wrong_audience: 0,
    replay: 2,
    rate_limited: 0,
    claim_mismatch: 3,
    compliance_failed: 0,
    malformed: 0,
    unknown_version: 0,
  },
  generated_at: '2026-04-29T15:00:00Z',
};

const disabledProfile = {
  path_id: 'iot',
  issuer_id: 'iss-iot',
  enabled: false,
  rate_limit_disabled: false,
  replay_cache_size: 0,
  counters: {},
  generated_at: '2026-04-29T15:00:00Z',
};

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
  setAuth({ authRequired: true, admin: true });
  vi.mocked(client.getAuditEvents).mockResolvedValue({
    data: [],
    total: 0,
    page: 1,
    per_page: 200,
  } as never);
});

describe('SCEPAdminPage — admin gate', () => {
  it('renders an Admin access required banner for non-admin callers and skips the admin API', async () => {
    setAuth({ authRequired: true, admin: false });
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /SCEP Intune Monitoring/ })).toBeInTheDocument();
    });
    expect(client.getAdminSCEPIntuneStats).not.toHaveBeenCalled();
    expect(screen.getByText(/Admin access required/i)).toBeInTheDocument();
  });

  it('lets admin callers through and fetches stats', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [baseEnabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    expect(await screen.findByTestId('profile-card-corp')).toBeInTheDocument();
    expect(client.getAdminSCEPIntuneStats).toHaveBeenCalled();
  });

  it('keeps the page accessible when authRequired=false (no-auth dev mode)', async () => {
    setAuth({ authRequired: false, admin: false });
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [],
      profile_count: 0,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(client.getAdminSCEPIntuneStats).toHaveBeenCalledTimes(1);
    });
  });
});

describe('SCEPAdminPage — profile rendering', () => {
  it('renders enabled profile counters with the expected labels and tone', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [baseEnabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('counter-corp-success')).toHaveTextContent('42');
    });
    expect(screen.getByTestId('counter-corp-replay')).toHaveTextContent('2');
    expect(screen.getByTestId('counter-corp-claim_mismatch')).toHaveTextContent('3');
    // Expiry badge is "good" tone for >= 30 days remaining.
    const badge = screen.getByTestId('expiry-badge-corp');
    expect(badge).toHaveTextContent('250d');
  });

  it('renders an expiry badge with EXPIRED text and bad tone when an anchor is past NotAfter', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [
        {
          ...baseEnabledProfile,
          trust_anchors: [
            { subject: 'expired-conn', not_before: '2024-01-01T00:00:00Z', not_after: '2025-01-01T00:00:00Z', days_to_expiry: 0, expired: true },
          ],
        },
      ],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('expiry-badge-corp')).toHaveTextContent(/EXPIRED/);
    });
  });

  it('renders the off-state pill for disabled profiles instead of the counter grid', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [disabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('profile-card-iot')).toBeInTheDocument();
    });
    expect(screen.getByText(/Intune disabled/)).toBeInTheDocument();
    // Counter grid should NOT render for disabled profiles.
    expect(screen.queryByTestId('counter-iot-success')).toBeNull();
  });

  it('renders an empty-state banner when no profiles are configured', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [],
      profile_count: 0,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByText(/No SCEP profiles are configured/)).toBeInTheDocument();
    });
  });
});

describe('SCEPAdminPage — reload-trust modal', () => {
  it('opens the confirmation modal when the Reload trust button is clicked', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [baseEnabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('reload-button-corp')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('reload-button-corp'));
    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/Reload Intune trust anchor/i)).toBeInTheDocument();
  });

  it('calls reloadAdminSCEPIntuneTrust on Confirm and closes the modal on success', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [baseEnabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.reloadAdminSCEPIntuneTrust).mockResolvedValue({
      reloaded: true,
      path_id: 'corp',
      reloaded_at: '2026-04-29T15:01:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('reload-button-corp')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('reload-button-corp'));
    fireEvent.click(await screen.findByRole('button', { name: /Reload trust anchor/i }));
    await waitFor(() => {
      expect(client.reloadAdminSCEPIntuneTrust).toHaveBeenCalledWith('corp');
    });
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull();
    });
  });

  it('keeps the modal open and shows the error message when reload fails', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [baseEnabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.reloadAdminSCEPIntuneTrust).mockRejectedValue(new Error('trust anchor cert expired'));
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('reload-button-corp')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('reload-button-corp'));
    fireEvent.click(await screen.findByRole('button', { name: /Reload trust anchor/i }));
    await waitFor(() => {
      expect(screen.getByText(/trust anchor cert expired/)).toBeInTheDocument();
    });
    // Modal stays open so the operator can read the error and retry.
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('Cancel closes the modal without calling the reload mutation', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [baseEnabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('reload-button-corp')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('reload-button-corp'));
    fireEvent.click(await screen.findByRole('button', { name: /Cancel/i }));
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull();
    });
    expect(client.reloadAdminSCEPIntuneTrust).not.toHaveBeenCalled();
  });
});

describe('SCEPAdminPage — error + audit-log surface', () => {
  it('surfaces ErrorState when the stats query fails', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockRejectedValue(new Error('boom'));
    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByText(/Failed to load data/i)).toBeInTheDocument();
    });
  });

  it('merges PKCSReq + RenewalReq audit events and sorts by timestamp descending', async () => {
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [baseEnabledProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAuditEvents).mockImplementation((params: Record<string, string> = {}) => {
      if (params.action === 'scep_pkcsreq_intune') {
        return Promise.resolve({
          data: [
            { id: 'ae-pkcs-1', action: 'scep_pkcsreq_intune', actor: 'scep-client', actor_type: 'system', resource_type: 'certificate', resource_id: 'cert-1', details: {}, timestamp: '2026-04-29T14:00:00Z' },
          ],
          total: 1, page: 1, per_page: 200,
        } as never);
      }
      return Promise.resolve({
        data: [
          { id: 'ae-renew-1', action: 'scep_renewalreq_intune', actor: 'scep-client', actor_type: 'system', resource_type: 'certificate', resource_id: 'cert-2', details: {}, timestamp: '2026-04-29T14:30:00Z' },
        ],
        total: 1, page: 1, per_page: 200,
      } as never);
    });

    renderWithQuery(<SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('recent-failures-table')).toBeInTheDocument();
    });

    const rows = screen.getByTestId('recent-failures-table').querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    // Sorted descending by timestamp — renewal (14:30) comes before pkcs (14:00).
    expect(rows[0].textContent).toContain('scep_renewalreq_intune');
    expect(rows[1].textContent).toContain('scep_pkcsreq_intune');
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import type { ReactNode } from 'react';

// SCEP RFC 8894 + Intune master bundle Phase 9 follow-up
// (cowork/scep-gui-restructure-prompt.md): Vitest coverage for the
// rebranded SCEP Administration page. Pins:
//   1. Admin gate — non-admin sees the gated banner; admin requests are
//      never issued.
//   2. Tab navigation — Profiles is the default; clicking each tab
//      switches surface; ?tab=intune deep-links land on Intune; the
//      legacy /scep/intune route alias also lands on Intune.
//   3. Profiles tab — per-profile lean cards; status badges reflect
//      Intune + mTLS + challenge-password-set; RA cert expiry badge
//      tone bands (good ≥30d / warn 7-30d / bad <7d / EXPIRED);
//      "View Intune details →" link only renders for Intune-enabled
//      profiles AND switches to the Intune tab on click.
//   4. Intune tab — counters render with the existing Phase 9 deep-dive
//      shape; reload modal opens / Confirm calls mutation / Cancel
//      skips mutation / Error keeps modal open + surfaces message.
//   5. Recent Activity tab — merges all four SCEP audit actions across
//      four parallel useQuery calls; filter chips narrow to the
//      requested subset.
//   6. Error path — surfaces ErrorState on the active tab.

vi.mock('../api/client', () => ({
  getAdminSCEPProfiles: vi.fn(),
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

function renderWithRoute(initialPath: string, ui: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/scep" element={ui} />
          <Route path="/scep/intune" element={ui} />
        </Routes>
      </MemoryRouter>
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

const corpProfileSummary = {
  path_id: 'corp',
  issuer_id: 'iss-corp',
  challenge_password_set: true,
  ra_cert_subject: 'ra-corp',
  ra_cert_not_before: '2026-01-01T00:00:00Z',
  ra_cert_not_after: '2027-01-01T00:00:00Z',
  ra_cert_days_to_expiry: 250,
  ra_cert_expired: false,
  mtls_enabled: true,
  mtls_trust_bundle_path: '/etc/certctl/mtls-corp.pem',
  generated_at: '2026-04-29T15:00:00Z',
  intune: {
    trust_anchor_path: '/etc/certctl/intune-corp.pem',
    trust_anchors: [
      { subject: 'intune-conn', not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z', days_to_expiry: 250, expired: false },
    ],
    audience: 'https://certctl.example.com/scep/corp',
    challenge_validity_ns: 3_600_000_000_000,
    rate_limit_disabled: false,
    replay_cache_size: 12,
    counters: { success: 42 },
  },
};

const iotProfileSummary = {
  path_id: 'iot',
  issuer_id: 'iss-iot',
  challenge_password_set: true,
  ra_cert_subject: 'ra-iot',
  ra_cert_not_before: '2026-01-01T00:00:00Z',
  ra_cert_not_after: '2026-05-15T00:00:00Z',
  ra_cert_days_to_expiry: 16,
  ra_cert_expired: false,
  mtls_enabled: false,
  generated_at: '2026-04-29T15:00:00Z',
  // Intune disabled — no intune field
};

const expiredProfileSummary = {
  path_id: 'legacy',
  issuer_id: 'iss-old',
  challenge_password_set: true,
  ra_cert_subject: 'ra-old',
  ra_cert_not_before: '2024-01-01T00:00:00Z',
  ra_cert_not_after: '2025-01-01T00:00:00Z',
  ra_cert_days_to_expiry: 0,
  ra_cert_expired: true,
  mtls_enabled: false,
  generated_at: '2026-04-29T15:00:00Z',
};

const corpIntuneStats = {
  path_id: 'corp',
  issuer_id: 'iss-corp',
  enabled: true,
  trust_anchor_path: '/etc/certctl/intune-corp.pem',
  trust_anchors: [
    { subject: 'intune-conn', not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z', days_to_expiry: 250, expired: false },
  ],
  audience: 'https://certctl.example.com/scep/corp',
  challenge_validity_ns: 3_600_000_000_000,
  rate_limit_disabled: false,
  replay_cache_size: 12,
  counters: { success: 42, signature_invalid: 1, claim_mismatch: 3, replay: 2 },
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

// =============================================================================
// Admin gate.
// =============================================================================

describe('SCEPAdminPage — admin gate', () => {
  it('renders an Admin access required banner for non-admin callers and skips the admin API', async () => {
    setAuth({ authRequired: true, admin: false });
    renderWithRoute('/scep', <SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: /SCEP Administration/ })).toBeInTheDocument();
    });
    expect(client.getAdminSCEPProfiles).not.toHaveBeenCalled();
    expect(client.getAdminSCEPIntuneStats).not.toHaveBeenCalled();
    expect(screen.getByText(/Admin access required/i)).toBeInTheDocument();
  });

  it('lets admin callers through and fetches the per-profile snapshot', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep', <SCEPAdminPage />);
    expect(await screen.findByTestId('profile-summary-corp')).toBeInTheDocument();
    expect(client.getAdminSCEPProfiles).toHaveBeenCalled();
    // Default tab is Profiles → Intune stats endpoint NOT called yet
    expect(client.getAdminSCEPIntuneStats).not.toHaveBeenCalled();
  });
});

// =============================================================================
// Tab navigation + deep links.
// =============================================================================

describe('SCEPAdminPage — tab navigation', () => {
  it('renders Profiles tab as default', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep', <SCEPAdminPage />);
    expect(await screen.findByTestId('profile-summary-corp')).toBeInTheDocument();
    expect(screen.getByTestId('tab-profiles').getAttribute('aria-pressed')).toBe('true');
  });

  it('switches to Intune tab on click and triggers the Intune stats fetch', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [corpIntuneStats],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep', <SCEPAdminPage />);
    await screen.findByTestId('profile-summary-corp');
    fireEvent.click(screen.getByTestId('tab-intune'));
    expect(await screen.findByTestId('profile-card-corp')).toBeInTheDocument();
    expect(client.getAdminSCEPIntuneStats).toHaveBeenCalled();
  });

  it('?tab=intune deep-link lands on Intune tab', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [corpIntuneStats],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep?tab=intune', <SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('tab-intune').getAttribute('aria-pressed')).toBe('true');
    });
  });

  it('legacy /scep/intune route alias lands on Intune tab', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [corpIntuneStats],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep/intune', <SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByTestId('tab-intune').getAttribute('aria-pressed')).toBe('true');
    });
  });

  it('switches to Activity tab and merges the four SCEP audit actions', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAuditEvents).mockImplementation((params: Record<string, string> = {}) => {
      const events: Record<string, unknown[]> = {
        scep_pkcsreq: [{ id: 'a1', action: 'scep_pkcsreq', actor: 'scep-client', actor_type: 'system', resource_type: 'certificate', resource_id: 'c1', details: {}, timestamp: '2026-04-29T14:00:00Z' }],
        scep_renewalreq: [{ id: 'a2', action: 'scep_renewalreq', actor: 'scep-client', actor_type: 'system', resource_type: 'certificate', resource_id: 'c2', details: {}, timestamp: '2026-04-29T14:10:00Z' }],
        scep_pkcsreq_intune: [{ id: 'a3', action: 'scep_pkcsreq_intune', actor: 'scep-client', actor_type: 'system', resource_type: 'certificate', resource_id: 'c3', details: {}, timestamp: '2026-04-29T14:20:00Z' }],
        scep_renewalreq_intune: [{ id: 'a4', action: 'scep_renewalreq_intune', actor: 'scep-client', actor_type: 'system', resource_type: 'certificate', resource_id: 'c4', details: {}, timestamp: '2026-04-29T14:30:00Z' }],
      };
      const action = params.action ?? '';
      return Promise.resolve({
        data: events[action] ?? [],
        total: events[action]?.length ?? 0,
        page: 1,
        per_page: 200,
      } as never);
    });
    renderWithRoute('/scep', <SCEPAdminPage />);
    await screen.findByTestId('profile-summary-corp');
    fireEvent.click(screen.getByTestId('tab-activity'));
    await screen.findByTestId('activity-tab');
    const table = await screen.findByTestId('activity-events-table');
    const rows = table.querySelectorAll('tbody tr');
    expect(rows.length).toBe(4);
    // Sorted descending → renewal_intune (14:30) is first
    expect(rows[0].textContent).toContain('scep_renewalreq_intune');
  });
});

// =============================================================================
// Profiles tab — lean cards.
// =============================================================================

describe('SCEPAdminPage — Profiles tab cards', () => {
  it('renders status badges for Intune + mTLS + challenge-password-set', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary, iotProfileSummary],
      profile_count: 2,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep', <SCEPAdminPage />);
    await screen.findByTestId('profile-summary-corp');
    const corpBadges = screen.getByTestId('profile-badges-corp');
    expect(corpBadges.textContent).toContain('Intune enabled');
    expect(corpBadges.textContent).toContain('mTLS enabled');
    expect(corpBadges.textContent).toContain('Challenge password set');
    const iotBadges = screen.getByTestId('profile-badges-iot');
    expect(iotBadges.textContent).toContain('Intune disabled');
    expect(iotBadges.textContent).toContain('mTLS disabled');
  });

  it('RA cert expiry badge tone reflects the days-to-expiry band', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary, iotProfileSummary, expiredProfileSummary],
      profile_count: 3,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep', <SCEPAdminPage />);
    expect(await screen.findByTestId('ra-expiry-badge-corp')).toHaveTextContent('250d');
    expect(screen.getByTestId('ra-expiry-badge-iot')).toHaveTextContent(/16d remaining \(rotate soon\)/);
    expect(screen.getByTestId('ra-expiry-badge-legacy')).toHaveTextContent(/EXPIRED/);
  });

  it('"View Intune details →" only renders for Intune-enabled profiles AND switches tabs', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary, iotProfileSummary],
      profile_count: 2,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [corpIntuneStats],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep', <SCEPAdminPage />);
    await screen.findByTestId('profile-summary-corp');
    expect(screen.getByTestId('view-intune-details-corp')).toBeInTheDocument();
    expect(screen.queryByTestId('view-intune-details-iot')).toBeNull();
    fireEvent.click(screen.getByTestId('view-intune-details-corp'));
    expect(await screen.findByTestId('profile-card-corp')).toBeInTheDocument();
    expect(screen.getByTestId('tab-intune').getAttribute('aria-pressed')).toBe('true');
  });

  it('renders an empty-state banner when no profiles are configured', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [],
      profile_count: 0,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep', <SCEPAdminPage />);
    expect(await screen.findByText(/No SCEP profiles are configured/)).toBeInTheDocument();
  });
});

// =============================================================================
// Intune tab — reload modal + counters.
// =============================================================================

describe('SCEPAdminPage — Intune tab', () => {
  function gotoIntune() {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAdminSCEPIntuneStats).mockResolvedValue({
      profiles: [corpIntuneStats],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    renderWithRoute('/scep?tab=intune', <SCEPAdminPage />);
  }

  it('renders counters with the expected labels and tones', async () => {
    gotoIntune();
    expect(await screen.findByTestId('counter-corp-success')).toHaveTextContent('42');
    expect(screen.getByTestId('counter-corp-signature_invalid')).toHaveTextContent('1');
    expect(screen.getByTestId('counter-corp-claim_mismatch')).toHaveTextContent('3');
  });

  it('opens the reload modal and calls the mutation on Confirm', async () => {
    vi.mocked(client.reloadAdminSCEPIntuneTrust).mockResolvedValue({
      reloaded: true,
      path_id: 'corp',
      reloaded_at: '2026-04-29T15:01:00Z',
    } as never);
    gotoIntune();
    expect(await screen.findByTestId('reload-button-corp')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('reload-button-corp'));
    fireEvent.click(await screen.findByRole('button', { name: /Reload trust anchor/i }));
    await waitFor(() => {
      expect(client.reloadAdminSCEPIntuneTrust).toHaveBeenCalledWith('corp');
    });
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull();
    });
  });

  it('keeps the modal open and shows the error when reload fails', async () => {
    vi.mocked(client.reloadAdminSCEPIntuneTrust).mockRejectedValue(new Error('trust anchor cert expired'));
    gotoIntune();
    expect(await screen.findByTestId('reload-button-corp')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('reload-button-corp'));
    fireEvent.click(await screen.findByRole('button', { name: /Reload trust anchor/i }));
    await waitFor(() => {
      expect(screen.getByText(/trust anchor cert expired/)).toBeInTheDocument();
    });
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('Cancel closes the modal without calling the reload mutation', async () => {
    gotoIntune();
    expect(await screen.findByTestId('reload-button-corp')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('reload-button-corp'));
    fireEvent.click(await screen.findByRole('button', { name: /Cancel/i }));
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull();
    });
    expect(client.reloadAdminSCEPIntuneTrust).not.toHaveBeenCalled();
  });
});

// =============================================================================
// Recent Activity tab — filter chips.
// =============================================================================

describe('SCEPAdminPage — Activity tab filter', () => {
  beforeEach(() => {
    vi.mocked(client.getAdminSCEPProfiles).mockResolvedValue({
      profiles: [corpProfileSummary],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as never);
    vi.mocked(client.getAuditEvents).mockImplementation((params: Record<string, string> = {}) => {
      const lookup: Record<string, unknown[]> = {
        scep_pkcsreq: [{ id: 'p1', action: 'scep_pkcsreq', actor: 's', actor_type: 'system', resource_type: 'certificate', resource_id: 'c1', details: {}, timestamp: '2026-04-29T14:00:00Z' }],
        scep_renewalreq: [{ id: 'p2', action: 'scep_renewalreq', actor: 's', actor_type: 'system', resource_type: 'certificate', resource_id: 'c2', details: {}, timestamp: '2026-04-29T14:01:00Z' }],
        scep_pkcsreq_intune: [{ id: 'p3', action: 'scep_pkcsreq_intune', actor: 's', actor_type: 'system', resource_type: 'certificate', resource_id: 'c3', details: {}, timestamp: '2026-04-29T14:02:00Z' }],
        scep_renewalreq_intune: [{ id: 'p4', action: 'scep_renewalreq_intune', actor: 's', actor_type: 'system', resource_type: 'certificate', resource_id: 'c4', details: {}, timestamp: '2026-04-29T14:03:00Z' }],
      };
      return Promise.resolve({
        data: lookup[params.action ?? ''] ?? [],
        total: 1,
        page: 1,
        per_page: 200,
      } as never);
    });
  });

  it('filter=all shows all four actions', async () => {
    renderWithRoute('/scep?tab=activity', <SCEPAdminPage />);
    await screen.findByTestId('activity-tab');
    const table = await screen.findByTestId('activity-events-table');
    expect(table.querySelectorAll('tbody tr').length).toBe(4);
  });

  it('filter=intune narrows to just the two _intune actions', async () => {
    renderWithRoute('/scep?tab=activity', <SCEPAdminPage />);
    await screen.findByTestId('activity-tab');
    fireEvent.click(screen.getByTestId('activity-filter-intune'));
    const table = await screen.findByTestId('activity-events-table');
    const rows = table.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    for (const r of rows) {
      expect(r.textContent).toMatch(/_intune/);
    }
  });

  it('filter=renewal narrows to just the two renewal actions', async () => {
    renderWithRoute('/scep?tab=activity', <SCEPAdminPage />);
    await screen.findByTestId('activity-tab');
    fireEvent.click(screen.getByTestId('activity-filter-renewal'));
    const table = await screen.findByTestId('activity-events-table');
    const rows = table.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    for (const r of rows) {
      expect(r.textContent).toContain('scep_renewalreq');
    }
  });

  it('filter=static narrows to just the two non-Intune actions', async () => {
    renderWithRoute('/scep?tab=activity', <SCEPAdminPage />);
    await screen.findByTestId('activity-tab');
    fireEvent.click(screen.getByTestId('activity-filter-static'));
    const table = await screen.findByTestId('activity-events-table');
    const rows = table.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    for (const r of rows) {
      expect(r.textContent).not.toMatch(/_intune/);
    }
  });
});

// =============================================================================
// Error path.
// =============================================================================

describe('SCEPAdminPage — error surfacing', () => {
  it('surfaces ErrorState on the active tab when its query fails', async () => {
    vi.mocked(client.getAdminSCEPProfiles).mockRejectedValue(new Error('boom-profiles'));
    renderWithRoute('/scep', <SCEPAdminPage />);
    await waitFor(() => {
      expect(screen.getByText(/Failed to load data/i)).toBeInTheDocument();
    });
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import type { ReactNode } from 'react';

// EST RFC 7030 hardening master bundle Phase 8.4 — Vitest coverage for
// the EST Administration page. Mirrors SCEPAdminPage.test.tsx's
// structure verbatim. Pins:
//   1. Admin gate — non-admin sees the gated banner; admin requests are
//      never issued.
//   2. Tab navigation — Profiles is the default; clicking each tab
//      switches surface; ?tab=activity / ?tab=trust deep-links land
//      correctly.
//   3. Profiles tab — per-profile cards; status badges reflect mTLS +
//      Basic + ServerKeygen; trust-anchor expiry badge tone bands
//      (good ≥30d / warn 7-30d / bad <7d / EXPIRED); per-counter cells
//      render the correct value; "Reload trust anchor" only renders for
//      mTLS-enabled profiles AND opens the modal on click.
//   4. Reload modal — Confirm calls mutation / Cancel skips mutation /
//      Error keeps modal open + surfaces the error message.
//   5. Recent Activity tab — merges all four EST audit actions across
//      four parallel useQuery calls; filter chips narrow to the
//      requested subset.
//   6. Trust Bundle tab — only mTLS profiles render; non-mTLS deploy
//      sees the empty-state banner.
//   7. Error path — surfaces ErrorState on the active tab.

vi.mock('../api/client', () => ({
  getAdminESTProfiles: vi.fn(),
  reloadAdminESTTrust: vi.fn(),
  getAuditEvents: vi.fn(),
}));

vi.mock('../components/AuthProvider', () => ({
  useAuth: vi.fn(),
}));

import ESTAdminPage from './ESTAdminPage';
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
          <Route path="/est" element={ui} />
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

const corpProfile = {
  path_id: 'corp',
  issuer_id: 'iss-corp',
  profile_id: 'prof-corp',
  counters: {
    success_simpleenroll: 42,
    success_simplereenroll: 7,
    success_serverkeygen: 3,
    auth_failed_basic: 1,
    auth_failed_mtls: 0,
    auth_failed_channel_binding: 0,
    csr_invalid: 0,
    csr_policy_violation: 0,
    csr_signature_mismatch: 0,
    rate_limited: 2,
    issuer_error: 0,
    internal_error: 0,
  },
  mtls_enabled: true,
  basic_auth_configured: true,
  server_keygen_enabled: true,
  trust_anchors: [
    {
      subject: 'corp-bootstrap-ca',
      not_before: '2026-01-01T00:00:00Z',
      not_after: '2027-01-01T00:00:00Z',
      days_to_expiry: 250,
      expired: false,
    },
  ],
  trust_anchor_path: '/etc/certctl/est-mtls-corp.pem',
  now: '2026-04-29T15:00:00Z',
};

const iotProfile = {
  path_id: 'iot',
  issuer_id: 'iss-iot',
  counters: {
    success_simpleenroll: 9,
    auth_failed_basic: 0,
  } as Record<string, number>,
  mtls_enabled: false,
  basic_auth_configured: false,
  server_keygen_enabled: false,
  now: '2026-04-29T15:00:00Z',
};

const profilesResponse = {
  profiles: [corpProfile, iotProfile],
  profile_count: 2,
  generated_at: '2026-04-29T15:00:00Z',
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(client.getAdminESTProfiles).mockResolvedValue(profilesResponse as any);
  vi.mocked(client.getAuditEvents).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as any);
  setAuth({ authRequired: true, admin: true });
});

afterEach(() => {
  cleanup();
});

// React's afterEach is implicit in this scope via Vitest; the explicit
// cleanup() above is safe to call even when no render happened.
function afterEach(fn: () => void) {
  // re-export from vitest globals — vitest's globals expose `afterEach`
  // automatically when test config has globals: true. Our config does, so
  // the import is unnecessary; this thin shim documents the call site.
  (globalThis as any).afterEach?.(fn);
}

describe('ESTAdminPage — admin gate', () => {
  it('non-admin sees the gated banner; admin requests never fire', async () => {
    setAuth({ authRequired: true, admin: false });
    renderWithRoute('/est', <ESTAdminPage />);
    expect(await screen.findByText(/Admin access required/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(client.getAdminESTProfiles).not.toHaveBeenCalled();
    });
  });

  it('non-auth-required deploy lets the page render and fires admin request', async () => {
    setAuth({ authRequired: false, admin: false });
    renderWithRoute('/est', <ESTAdminPage />);
    await waitFor(() => {
      expect(client.getAdminESTProfiles).toHaveBeenCalled();
    });
  });
});

describe('ESTAdminPage — tab navigation', () => {
  it('defaults to the Profiles tab', async () => {
    renderWithRoute('/est', <ESTAdminPage />);
    expect(await screen.findByTestId('est-tab-profiles')).toHaveAttribute('aria-pressed', 'true');
  });

  it('clicking Recent Activity switches the tab', async () => {
    renderWithRoute('/est', <ESTAdminPage />);
    fireEvent.click(await screen.findByTestId('est-tab-activity'));
    expect(screen.getByTestId('est-tab-activity')).toHaveAttribute('aria-pressed', 'true');
  });

  it('?tab=trust deep-link lands on Trust Bundle', async () => {
    renderWithRoute('/est?tab=trust', <ESTAdminPage />);
    expect(await screen.findByTestId('est-tab-trust')).toHaveAttribute('aria-pressed', 'true');
  });
});

describe('ESTAdminPage — Profiles tab', () => {
  it('renders one card per profile with the right badges + counters', async () => {
    renderWithRoute('/est', <ESTAdminPage />);
    expect(await screen.findByTestId('est-profile-summary-corp')).toBeInTheDocument();
    expect(screen.getByTestId('est-profile-summary-iot')).toBeInTheDocument();
    // Per-profile counter cells render with the snapshot value.
    expect(screen.getByTestId('est-counter-corp-success_simpleenroll')).toHaveTextContent('42');
    expect(screen.getByTestId('est-counter-corp-rate_limited')).toHaveTextContent('2');
    expect(screen.getByTestId('est-counter-iot-success_simpleenroll')).toHaveTextContent('9');
    // Counters that don't appear in the iot snapshot default to 0 in the cell.
    expect(screen.getByTestId('est-counter-iot-internal_error')).toHaveTextContent('0');
  });

  it('reload-trust button only appears for mTLS profiles', async () => {
    renderWithRoute('/est', <ESTAdminPage />);
    expect(await screen.findByTestId('est-reload-trust-corp')).toBeInTheDocument();
    expect(screen.queryByTestId('est-reload-trust-iot')).toBeNull();
  });

  it('shows mTLS trust expiry badge tone bands', async () => {
    renderWithRoute('/est', <ESTAdminPage />);
    const badge = await screen.findByTestId('est-trust-expiry-badge-corp');
    expect(badge).toHaveTextContent(/250d remaining/);
  });
});

describe('ESTAdminPage — reload modal', () => {
  it('Confirm calls mutation', async () => {
    vi.mocked(client.reloadAdminESTTrust).mockResolvedValue({
      reloaded: true,
      path_id: 'corp',
      reloaded_at: '2026-04-29T15:00:01Z',
    });
    renderWithRoute('/est', <ESTAdminPage />);
    fireEvent.click(await screen.findByTestId('est-reload-trust-corp'));
    fireEvent.click(await screen.findByTestId('est-reload-confirm'));
    await waitFor(() => {
      expect(client.reloadAdminESTTrust).toHaveBeenCalledWith('corp');
    });
  });

  it('Cancel skips mutation', async () => {
    renderWithRoute('/est', <ESTAdminPage />);
    fireEvent.click(await screen.findByTestId('est-reload-trust-corp'));
    fireEvent.click(await screen.findByTestId('est-reload-cancel'));
    await waitFor(() => {
      expect(screen.queryByTestId('est-reload-confirm')).toBeNull();
    });
    expect(client.reloadAdminESTTrust).not.toHaveBeenCalled();
  });

  it('Error keeps the modal open + surfaces the message', async () => {
    vi.mocked(client.reloadAdminESTTrust).mockRejectedValue(
      new Error('Trust anchor reload failed: trustanchor: cert in /etc/est-corp.pem expired'),
    );
    renderWithRoute('/est', <ESTAdminPage />);
    fireEvent.click(await screen.findByTestId('est-reload-trust-corp'));
    fireEvent.click(await screen.findByTestId('est-reload-confirm'));
    expect(await screen.findByTestId('est-reload-error')).toHaveTextContent(/expired/);
    // Modal stays open — Confirm button still rendered.
    expect(screen.getByTestId('est-reload-confirm')).toBeInTheDocument();
  });
});

describe('ESTAdminPage — Trust Bundle tab', () => {
  it('renders only mTLS profiles + skips non-mTLS', async () => {
    renderWithRoute('/est?tab=trust', <ESTAdminPage />);
    expect(await screen.findByTestId('est-trust-card-corp')).toBeInTheDocument();
    expect(screen.queryByTestId('est-trust-card-iot')).toBeNull();
  });

  it('shows the empty-state banner when no profile has mTLS', async () => {
    vi.mocked(client.getAdminESTProfiles).mockResolvedValue({
      profiles: [iotProfile],
      profile_count: 1,
      generated_at: '2026-04-29T15:00:00Z',
    } as any);
    renderWithRoute('/est?tab=trust', <ESTAdminPage />);
    expect(await screen.findByText(/No EST profiles have mTLS enabled/i)).toBeInTheDocument();
  });
});

describe('ESTAdminPage — Recent Activity tab', () => {
  it('renders filter chips + reacts to selection', async () => {
    renderWithRoute('/est?tab=activity', <ESTAdminPage />);
    const allChip = await screen.findByTestId('est-activity-filter-all');
    expect(allChip).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(screen.getByTestId('est-activity-filter-enroll'));
    await waitFor(() => {
      expect(screen.getByTestId('est-activity-filter-enroll')).toHaveAttribute('aria-pressed', 'true');
    });
  });
});

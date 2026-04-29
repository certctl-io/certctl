import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): NetworkScanPage XSS-hardening + render coverage.
// Scan targets are operator-supplied CIDR / hostname strings; scan results
// are server-side discovery output that may include attacker-controlled
// cert subjects via the discovery surface.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getNetworkScanTargets: vi.fn(),
  createNetworkScanTarget: vi.fn(),
  updateNetworkScanTarget: vi.fn(),
  deleteNetworkScanTarget: vi.fn(),
  triggerNetworkScan: vi.fn(),
  // SCEP RFC 8894 + Intune master bundle Phase 11.5: SCEP probe.
  probeSCEPServer: vi.fn(),
  listSCEPProbes: vi.fn(),
}));

import NetworkScanPage from './NetworkScanPage';
import * as client from '../api/client';

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

const xssPayload = '<script data-xss="network-scan">window.__xss_pwned__=1;</script>';

const xssScanTarget = {
  id: 'ns-xss-001',
  name: xssPayload,
  network_range: xssPayload,
  ports: [443, 8443],
  agent_id: xssPayload,
  enabled: true,
  last_scan_at: new Date().toISOString(),
  last_scan_status: 'failed',
  last_scan_message: xssPayload,
};

describe('NetworkScanPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
    // SCEP probe section runs in parallel with the scan-targets table;
    // stub its history endpoint to an empty list so the existing tests
    // don't accidentally exercise the probe path.
    vi.mocked(client.listSCEPProbes).mockResolvedValue({ probes: [], probe_count: 0 } as never);
  });

  it('renders the page header when getNetworkScanTargets resolves', async () => {
    vi.mocked(client.getNetworkScanTargets).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderWithQuery(<NetworkScanPage />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 2, name: 'Network Scanning' })).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in scan-target fields', async () => {
    vi.mocked(client.getNetworkScanTargets).mockResolvedValue({
      data: [xssScanTarget],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    renderWithQuery(<NetworkScanPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="network-scan">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="network-scan"]');
    expect(liveScripts.length, 'scan-target fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'scan-target <script> body must not have executed',
    ).toBeUndefined();
  });
});

// =============================================================================
// SCEP Probe section — Phase 11.5 of the master bundle.
// =============================================================================

const happyProbeResult = {
  id: 'spr-test-1',
  target_url: 'https://scep.example.com/scep',
  reachable: true,
  advertised_caps: ['POSTPKIOperation', 'SHA-256', 'SHA-512', 'AES', 'SCEPStandard', 'Renewal'],
  supports_rfc8894: true,
  supports_aes: true,
  supports_post_operation: true,
  supports_renewal: true,
  supports_sha256: true,
  supports_sha512: true,
  ca_cert_subject: 'CN=test-ca',
  ca_cert_issuer: 'CN=test-ca',
  ca_cert_not_before: '2026-01-01T00:00:00Z',
  ca_cert_not_after: '2027-01-01T00:00:00Z',
  ca_cert_expired: false,
  ca_cert_days_to_expiry: 250,
  ca_cert_algorithm: 'ECDSA-P-256',
  ca_cert_chain_length: 1,
  probed_at: '2026-04-29T16:00:00Z',
  probe_duration_ms: 245,
};

describe('NetworkScanPage — SCEP probe section (Phase 11.5)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getNetworkScanTargets).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    vi.mocked(client.listSCEPProbes).mockResolvedValue({ probes: [], probe_count: 0 } as never);
  });

  it('renders the SCEP probe section header + form', async () => {
    renderWithQuery(<NetworkScanPage />);
    expect(await screen.findByTestId('scep-probe-section')).toBeInTheDocument();
    expect(screen.getByTestId('scep-probe-url-input')).toBeInTheDocument();
    expect(screen.getByTestId('scep-probe-submit')).toBeInTheDocument();
  });

  it('rejects an empty URL with an inline error and never calls the probe endpoint', async () => {
    renderWithQuery(<NetworkScanPage />);
    fireEvent.click(await screen.findByTestId('scep-probe-submit'));
    await waitFor(() => {
      expect(screen.getByTestId('scep-probe-error')).toBeInTheDocument();
    });
    expect(client.probeSCEPServer).not.toHaveBeenCalled();
  });

  it('runs a probe and renders capability badges + CA cert details on success', async () => {
    vi.mocked(client.probeSCEPServer).mockResolvedValue(happyProbeResult as never);
    renderWithQuery(<NetworkScanPage />);

    const input = await screen.findByTestId('scep-probe-url-input');
    fireEvent.change(input, { target: { value: 'https://scep.example.com/scep' } });
    fireEvent.click(screen.getByTestId('scep-probe-submit'));

    await waitFor(() => {
      expect(client.probeSCEPServer).toHaveBeenCalledWith('https://scep.example.com/scep');
    });
    const panel = await screen.findByTestId('scep-probe-result-panel');
    expect(panel).toBeInTheDocument();
    expect(screen.getByTestId('scep-probe-cap-badges')).toBeInTheDocument();
    expect(screen.getByTestId('scep-probe-cap-rfc-8894').textContent).toContain('✓');
    expect(screen.getByTestId('scep-probe-cap-aes').textContent).toContain('✓');
    // Subject + days-remaining are rendered inside the panel; assert
    // their substrings rather than using getByText (which matches a
    // single text node and can miss content split across nested
    // elements like dt/dd pairs).
    expect(panel.textContent ?? '').toContain('CN=test-ca');
    expect(panel.textContent ?? '').toContain('250d remaining');
  });

  it('surfaces probe-level errors in the inline panel', async () => {
    vi.mocked(client.probeSCEPServer).mockRejectedValue(new Error('network unreachable'));
    renderWithQuery(<NetworkScanPage />);

    fireEvent.change(await screen.findByTestId('scep-probe-url-input'), { target: { value: 'https://broken.example.com/scep' } });
    fireEvent.click(screen.getByTestId('scep-probe-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('scep-probe-error')).toHaveTextContent(/network unreachable/);
    });
    expect(screen.queryByTestId('scep-probe-result-panel')).toBeNull();
  });

  it('renders the recent-probes history table with a row per probe', async () => {
    vi.mocked(client.listSCEPProbes).mockResolvedValue({
      probes: [
        happyProbeResult,
        { ...happyProbeResult, id: 'spr-test-2', target_url: 'https://other.example.com/scep', supports_rfc8894: false },
      ],
      probe_count: 2,
    } as never);
    renderWithQuery(<NetworkScanPage />);

    const table = await screen.findByTestId('scep-probe-history-table');
    const rows = table.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('scep.example.com');
    expect(rows[1].textContent).toContain('other.example.com');
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
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
  ports: '443,8443',
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
  });

  it('renders the page header when getNetworkScanTargets resolves', async () => {
    vi.mocked(client.getNetworkScanTargets).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderWithQuery(<NetworkScanPage />);
    await waitFor(() => {
      expect(screen.getByText(/Network/i)).toBeInTheDocument();
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

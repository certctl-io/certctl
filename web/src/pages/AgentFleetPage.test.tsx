import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// M-029 Pass 3 (Audit M-026): AgentFleetPage XSS-hardening + render coverage.
// Agent name / hostname / OS / arch / IP are agent-self-reported (M-003 in
// the MCP fence path); the GUI rendering must also be XSS-safe.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getAgents: vi.fn(),
}));

import AgentFleetPage from './AgentFleetPage';
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

const xssPayload = '<script data-xss="agent-fleet">window.__xss_pwned__=1;</script>';

const xssAgent = {
  id: 'a-xss-001',
  name: xssPayload,
  hostname: xssPayload,
  os: xssPayload,
  architecture: xssPayload,
  ip_address: xssPayload,
  version: xssPayload,
  status: 'online',
  last_heartbeat_at: new Date().toISOString(),
  agent_group_id: 'ag-xss',
};

describe('AgentFleetPage — render + XSS hardening (M-026 / M-029 Pass 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    delete (window as unknown as { __xss_pwned__?: number }).__xss_pwned__;
  });

  it('renders the page header when getAgents resolves', async () => {
    vi.mocked(client.getAgents).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 } as never);
    renderWithQuery(<AgentFleetPage />);
    await waitFor(() => {
      expect(screen.getByText(/Agent/i)).toBeInTheDocument();
    });
  });

  it('does NOT execute <script> payloads in agent name / hostname / OS / arch / ip', async () => {
    vi.mocked(client.getAgents).mockResolvedValue({
      data: [xssAgent],
      total: 1,
      page: 1,
      per_page: 50,
    } as never);
    renderWithQuery(<AgentFleetPage />);
    await waitFor(() => {
      expect(document.body.textContent ?? '').toContain('<script data-xss="agent-fleet">');
    });

    const liveScripts = document.querySelectorAll('script[data-xss="agent-fleet"]');
    expect(liveScripts.length, 'agent fields must not inject a live <script>').toBe(0);
    expect(
      (window as unknown as { __xss_pwned__?: number }).__xss_pwned__,
      'agent <script> body must not have executed',
    ).toBeUndefined();
  });
});

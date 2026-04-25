import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): AgentsPage Vitest coverage.
//
// Pins:
//   1. Active agents render when getAgents resolves.
//   2. heartbeatStatus()-derived health badge handles undefined
//      last_heartbeat_at gracefully (Offline) — D-2 phantom-trim contract.
//   3. The page calls listRetiredAgents only when the retired tab is active
//      (lazy query enablement).
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getAgents: vi.fn(),
  listRetiredAgents: vi.fn(),
  retireAgent: vi.fn(),
  BlockedByDependenciesError: class BlockedByDependenciesError extends Error {
    counts: unknown;
    constructor(counts: unknown) { super('blocked'); this.counts = counts; }
  },
}));

import AgentsPage from './AgentsPage';
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

const onlineAgent = {
  id: 'agent-iis01',
  name: 'IIS-01',
  hostname: 'iis01.prod.example.com',
  status: 'Online',
  last_heartbeat_at: new Date().toISOString(),
  registered_at: new Date(Date.now() - 86400000).toISOString(),
};

const noHeartbeatAgent = {
  id: 'agent-fresh',
  name: 'Fresh-Agent',
  hostname: 'fresh.example.com',
  // No status, no last_heartbeat_at — exercises the heartbeatStatus
  // undefined-fallback path (returns 'Offline').
  registered_at: new Date().toISOString(),
};

describe('AgentsPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getAgents).mockResolvedValue({
      data: [onlineAgent, noHeartbeatAgent],
      total: 2,
      page: 1,
      per_page: 50,
    } as never);
    vi.mocked(client.listRetiredAgents).mockResolvedValue({
      data: [],
      total: 0,
      page: 1,
      per_page: 50,
    } as never);
  });

  it('renders the active agents list when getAgents resolves', async () => {
    renderWithQuery(<AgentsPage />);
    await waitFor(() => {
      expect(screen.getByText('IIS-01')).toBeInTheDocument();
    });
    expect(screen.getByText('Fresh-Agent')).toBeInTheDocument();
  });

  it('uses heartbeatStatus to derive Offline for agents without last_heartbeat_at', async () => {
    renderWithQuery(<AgentsPage />);
    await waitFor(() => {
      expect(screen.getByText('Fresh-Agent')).toBeInTheDocument();
    });
    // The Fresh-Agent row has no status and no last_heartbeat_at;
    // heartbeatStatus() falls through to 'Offline'.
    expect(screen.getAllByText(/Offline/).length).toBeGreaterThan(0);
  });

  it('lazy-fetches the retired agents only when the retired tab is active', async () => {
    renderWithQuery(<AgentsPage />);
    await waitFor(() => expect(client.getAgents).toHaveBeenCalled());
    // Active tab is default — listRetiredAgents must NOT be called.
    expect(client.listRetiredAgents).not.toHaveBeenCalled();
  });
});

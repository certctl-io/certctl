import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): AgentDetailPage Vitest coverage.
//
// Pins the D-2 phantom-trim contract on the detail page:
//   1. Page fetches the agent via getAgent(id) when the URL :id param is set.
//   2. The Registered row reads agent.registered_at — pre-D-2 it read
//      agent.created_at which was a TS phantom never emitted by the Go
//      Agent struct.
//   3. The page does NOT render Capabilities / Tags sections — both were
//      D-2-trimmed phantoms.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getAgent: vi.fn(),
  getJobs: vi.fn(),
}));

import AgentDetailPage from './AgentDetailPage';
import * as client from '../api/client';

function renderAt(path: string, ui: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/agents/:id" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('AgentDetailPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getAgent).mockResolvedValue({
      id: 'agent-iis01',
      name: 'IIS-01',
      hostname: 'iis01.prod.example.com',
      ip_address: '10.0.0.5',
      version: '0.5.4',
      status: 'Online',
      os: 'windows',
      architecture: 'amd64',
      last_heartbeat_at: new Date().toISOString(),
      registered_at: '2026-04-01T00:00:00Z',
    });
    vi.mocked(client.getJobs).mockResolvedValue({
      data: [],
      total: 0,
      page: 1,
      per_page: 10,
    });
  });

  it('fetches the agent by URL id param', async () => {
    renderAt('/agents/agent-iis01', <AgentDetailPage />);
    await waitFor(() => {
      expect(client.getAgent).toHaveBeenCalledWith('agent-iis01');
    });
  });

  it('renders the Registered row from registered_at (D-2 phantom-trim)', async () => {
    renderAt('/agents/agent-iis01', <AgentDetailPage />);
    await waitFor(() => {
      expect(screen.getByText('Registered')).toBeInTheDocument();
    });
  });

  it('does NOT render Capabilities / Tags sections (D-2 trimmed both phantoms)', async () => {
    renderAt('/agents/agent-iis01', <AgentDetailPage />);
    await waitFor(() => {
      expect(screen.getByText('IIS-01')).toBeInTheDocument();
    });
    // These two labels existed pre-D-2 backed by phantom fields the Go
    // Agent struct never emitted; both sections must be absent post-D-2.
    expect(screen.queryByText('Capabilities')).not.toBeInTheDocument();
    expect(screen.queryByText('Tags')).not.toBeInTheDocument();
  });
});

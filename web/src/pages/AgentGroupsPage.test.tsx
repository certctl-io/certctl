import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): AgentGroupsPage Vitest coverage.
//
// Pins the B-1 closure: Edit button opens EditAgentGroupModal which calls
// updateAgentGroup(id, payload). Mirrors the OwnersPage / TeamsPage pattern.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getAgentGroups: vi.fn(),
  createAgentGroup: vi.fn(),
  updateAgentGroup: vi.fn(),
  deleteAgentGroup: vi.fn(),
  getAgentGroupMembers: vi.fn(),
}));

import AgentGroupsPage from './AgentGroupsPage';
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

const group = {
  id: 'ag-linux-prod',
  name: 'Linux Prod Fleet',
  description: 'Linux amd64 in prod CIDR',
  match_os: 'linux',
  match_architecture: 'amd64',
  match_ip_cidr: '10.0.0.0/24',
  match_version: '',
  enabled: true,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('AgentGroupsPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getAgentGroups).mockResolvedValue({
      data: [group],
      total: 1,
      page: 1,
      per_page: 50,
    });
    vi.mocked(client.updateAgentGroup).mockResolvedValue(group);
  });

  it('renders the agent groups list when getAgentGroups resolves', async () => {
    renderWithQuery(<AgentGroupsPage />);
    await waitFor(() => {
      expect(screen.getByText('Linux Prod Fleet')).toBeInTheDocument();
    });
  });

  it('Edit + Save calls updateAgentGroup with the right payload (B-1 closure)', async () => {
    renderWithQuery(<AgentGroupsPage />);
    await waitFor(() => {
      expect(screen.getByText('Linux Prod Fleet')).toBeInTheDocument();
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await waitFor(() => {
      expect(screen.getByText('Edit Agent Group')).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole('button', { name: /Save Changes/ }));
    await waitFor(() => {
      expect(client.updateAgentGroup).toHaveBeenCalled();
    });
    const [id, payload] = vi.mocked(client.updateAgentGroup).mock.calls[0]!;
    expect(id).toBe('ag-linux-prod');
    expect(payload).toMatchObject({ name: 'Linux Prod Fleet', match_os: 'linux' });
  });
});

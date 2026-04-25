import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): TeamsPage Vitest coverage.
//
// Pins the B-1 closure: Edit button opens EditTeamModal which calls
// updateTeam(id, payload). Mirrors the OwnersPage pattern.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getTeams: vi.fn(),
  createTeam: vi.fn(),
  updateTeam: vi.fn(),
  deleteTeam: vi.fn(),
}));

import TeamsPage from './TeamsPage';
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

const team = {
  id: 't-platform',
  name: 'Platform',
  description: 'Core infra team',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('TeamsPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getTeams).mockResolvedValue({
      data: [team],
      total: 1,
      page: 1,
      per_page: 50,
    });
    vi.mocked(client.updateTeam).mockResolvedValue(team);
  });

  it('renders the teams list when getTeams resolves', async () => {
    renderWithQuery(<TeamsPage />);
    await waitFor(() => {
      expect(screen.getByText('Platform')).toBeInTheDocument();
    });
  });

  it('Edit + Save calls updateTeam with the right payload (B-1 closure)', async () => {
    renderWithQuery(<TeamsPage />);
    await waitFor(() => {
      expect(screen.getByText('Platform')).toBeInTheDocument();
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await waitFor(() => {
      expect(screen.getByText('Edit Team')).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole('button', { name: /Save Changes/ }));
    await waitFor(() => {
      expect(client.updateTeam).toHaveBeenCalled();
    });
    const [id, payload] = vi.mocked(client.updateTeam).mock.calls[0]!;
    expect(id).toBe('t-platform');
    expect(payload).toMatchObject({ name: 'Platform' });
  });
});

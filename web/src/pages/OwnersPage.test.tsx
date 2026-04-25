import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): OwnersPage Vitest coverage.
//
// Pins the B-1 master closure: the Edit button opens an EditOwnerModal that
// calls updateOwner(id, payload) — pre-B-1 the only rename path was
// delete-and-recreate which destroyed audit history and broke every cert
// referencing the old owner_id.
//
//   1. Owner list renders when getOwners resolves.
//   2. Edit button opens the EditOwnerModal (B-1 closure).
//   3. Submitting the edit calls updateOwner with the right payload.
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getOwners: vi.fn(),
  getTeams: vi.fn(),
  createOwner: vi.fn(),
  updateOwner: vi.fn(),
  deleteOwner: vi.fn(),
}));

import OwnersPage from './OwnersPage';
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

const owner = {
  id: 'o-platform',
  name: 'Platform Team Lead',
  email: 'platform@example.com',
  team_id: 't-platform',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const team = { id: 't-platform', name: 'Platform', description: '' };

describe('OwnersPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getOwners).mockResolvedValue({ data: [owner], total: 1, page: 1, per_page: 50 } as never);
    vi.mocked(client.getTeams).mockResolvedValue({ data: [team], total: 1, page: 1, per_page: 50 } as never);
    vi.mocked(client.updateOwner).mockResolvedValue(owner as never);
  });

  it('renders the owners list when getOwners resolves', async () => {
    renderWithQuery(<OwnersPage />);
    await waitFor(() => {
      expect(screen.getByText('Platform Team Lead')).toBeInTheDocument();
    });
    expect(screen.getByText('platform@example.com')).toBeInTheDocument();
  });

  it('Edit button opens the EditOwnerModal (B-1 closure)', async () => {
    renderWithQuery(<OwnersPage />);
    await waitFor(() => {
      expect(screen.getByText('Platform Team Lead')).toBeInTheDocument();
    });
    const editBtn = await screen.findByRole('button', { name: 'Edit' });
    fireEvent.click(editBtn);
    await waitFor(() => {
      expect(screen.getByText('Edit Owner')).toBeInTheDocument();
    });
  });

  it('submitting the edit form calls updateOwner with the new payload', async () => {
    renderWithQuery(<OwnersPage />);
    await waitFor(() => {
      expect(screen.getByText('Platform Team Lead')).toBeInTheDocument();
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await waitFor(() => {
      expect(screen.getByText('Edit Owner')).toBeInTheDocument();
    });

    const saveBtn = await screen.findByRole('button', { name: /Save Changes/ });
    fireEvent.click(saveBtn);
    await waitFor(() => {
      expect(client.updateOwner).toHaveBeenCalled();
    });
    const [id, payload] = vi.mocked(client.updateOwner).mock.calls[0]!;
    expect(id).toBe('o-platform');
    expect(payload).toMatchObject({ name: 'Platform Team Lead', email: 'platform@example.com' });
  });
});

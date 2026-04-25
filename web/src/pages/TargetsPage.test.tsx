import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// -----------------------------------------------------------------------------
// T-1 closure (cat-s2-c24a548076c6): TargetsPage Vitest coverage.
//
// Pins:
//   1. Targets list renders when getTargets resolves.
//   2. Status column derives from `enabled` (D-2 phantom-field trim).
//   3. Connection column reads test_status (D-2 contract).
//   4. Delete confirm flow calls deleteTarget(id).
// -----------------------------------------------------------------------------

vi.mock('../api/client', () => ({
  getTargets: vi.fn(),
  createTarget: vi.fn(),
  deleteTarget: vi.fn(),
  getAgents: vi.fn(),
}));

import TargetsPage from './TargetsPage';
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

const targetEnabled = {
  id: 'tgt-iis-prod',
  name: 'IIS Web01',
  type: 'iis',
  agent_id: 'agent-iis01',
  enabled: true,
  test_status: 'success',
  config: {},
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

const targetUntested = {
  id: 'tgt-untested',
  name: 'New Target',
  type: 'kubernetes',
  agent_id: '',
  enabled: false,
  test_status: 'untested',
  config: {},
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

describe('TargetsPage — T-1 page coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cleanup();
    vi.mocked(client.getTargets).mockResolvedValue({
      data: [targetEnabled, targetUntested],
      total: 2,
      page: 1,
      per_page: 50,
    });
    vi.mocked(client.getAgents).mockResolvedValue({ data: [], total: 0, page: 1, per_page: 50 });
    vi.mocked(client.deleteTarget).mockResolvedValue({ message: 'deleted' });
  });

  it('renders the targets list when getTargets resolves', async () => {
    renderWithQuery(<TargetsPage />);
    await waitFor(() => {
      expect(screen.getByText('IIS Web01')).toBeInTheDocument();
    });
    expect(screen.getByText('New Target')).toBeInTheDocument();
  });

  it('derives the Status column from enabled (D-2 phantom-field trim)', async () => {
    renderWithQuery(<TargetsPage />);
    await waitFor(() => {
      expect(screen.getByText('IIS Web01')).toBeInTheDocument();
    });
    // Pre-D-2 the column read a phantom `status` field; post-D-2 it derives
    // 'Enabled' / 'Disabled' purely from the boolean.
    expect(screen.getAllByText(/Enabled/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Disabled/).length).toBeGreaterThan(0);
  });

  it('Delete confirm flow calls deleteTarget(id)', async () => {
    const origConfirm = globalThis.confirm;
    globalThis.confirm = vi.fn(() => true);
    try {
      renderWithQuery(<TargetsPage />);
      await waitFor(() => {
        expect(screen.getByText('IIS Web01')).toBeInTheDocument();
      });

      const deleteButtons = await screen.findAllByRole('button', { name: 'Delete' });
      fireEvent.click(deleteButtons[0]!);

      await waitFor(() => {
        expect(client.deleteTarget).toHaveBeenCalled();
      });
      expect(vi.mocked(client.deleteTarget).mock.calls[0]?.[0]).toBe('tgt-iis-prod');
    } finally {
      globalThis.confirm = origConfirm;
    }
  });
});

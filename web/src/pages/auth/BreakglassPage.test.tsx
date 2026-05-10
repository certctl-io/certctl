import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactNode } from 'react';

// Audit 2026-05-10 CRIT-4 closure — BreakglassPage tests. Pins:
//   - Forbidden page when caller lacks auth.breakglass.admin.
//   - Renders credential rows from the API when caller has permission.
//   - Set-password form rejects mismatched passwords.
//   - Set-password form rejects below-threshold length.
//   - Unlock button disabled when actor is not locked.
//   - Remove modal requires actor-id type-confirmation.

vi.mock('../../api/client', () => ({
  breakglassListCredentials: vi.fn(),
  breakglassSetPassword: vi.fn(),
  breakglassUnlock: vi.fn(),
  breakglassRemove: vi.fn(),
}));

vi.mock('../../hooks/useAuthMe', () => ({
  useAuthMe: vi.fn(),
}));

import BreakglassPage from './BreakglassPage';
import * as client from '../../api/client';
import { useAuthMe } from '../../hooks/useAuthMe';

function renderWithProviders(ui: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  cleanup();
});

function mockMe(opts: { hasPerm: boolean }) {
  (useAuthMe as ReturnType<typeof vi.fn>).mockReturnValue({
    isLoading: false,
    data: { actor_id: 'admin', permissions: opts.hasPerm ? ['auth.breakglass.admin'] : [] },
    hasPerm: (p: string) => opts.hasPerm && p === 'auth.breakglass.admin',
  });
}

describe('BreakglassPage permission gating', () => {
  it('renders the forbidden state when caller lacks auth.breakglass.admin', () => {
    mockMe({ hasPerm: false });
    renderWithProviders(<BreakglassPage />);
    expect(screen.getByText(/Forbidden/i)).toBeInTheDocument();
    expect(screen.queryByTestId('breakglass-new-form')).not.toBeInTheDocument();
  });

  it('shows the admin surface when caller has auth.breakglass.admin', async () => {
    mockMe({ hasPerm: true });
    (client.breakglassListCredentials as ReturnType<typeof vi.fn>).mockResolvedValue([
      {
        actor_id: 'admin',
        created_at: '2026-05-10T00:00:00Z',
        last_password_change_at: '2026-05-10T00:00:00Z',
        failure_count: 0,
      },
    ]);
    renderWithProviders(<BreakglassPage />);
    await waitFor(() => {
      expect(screen.getByTestId('breakglass-row-admin')).toBeInTheDocument();
    });
    expect(screen.getByTestId('breakglass-new-form')).toBeInTheDocument();
  });
});

describe('BreakglassPage set-password validation', () => {
  beforeEach(() => {
    mockMe({ hasPerm: true });
    (client.breakglassListCredentials as ReturnType<typeof vi.fn>).mockResolvedValue([]);
  });

  it('rejects mismatched passwords', async () => {
    renderWithProviders(<BreakglassPage />);
    fireEvent.change(screen.getByTestId('breakglass-new-actor-id'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByTestId('breakglass-new-password'), {
      target: { value: 'pass-long-enough-12' },
    });
    fireEvent.change(screen.getByTestId('breakglass-new-password-confirm'), {
      target: { value: 'pass-different-yo-12' },
    });
    fireEvent.click(screen.getByTestId('breakglass-new-submit'));
    await waitFor(() => {
      expect(screen.getByTestId('breakglass-new-error')).toHaveTextContent(/match/i);
    });
    expect(client.breakglassSetPassword).not.toHaveBeenCalled();
  });

  it('rejects below-threshold password length', async () => {
    renderWithProviders(<BreakglassPage />);
    fireEvent.change(screen.getByTestId('breakglass-new-actor-id'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByTestId('breakglass-new-password'), { target: { value: 'short' } });
    fireEvent.change(screen.getByTestId('breakglass-new-password-confirm'), {
      target: { value: 'short' },
    });
    fireEvent.click(screen.getByTestId('breakglass-new-submit'));
    await waitFor(() => {
      expect(screen.getByTestId('breakglass-new-error')).toHaveTextContent(/12 characters/i);
    });
    expect(client.breakglassSetPassword).not.toHaveBeenCalled();
  });
});

describe('BreakglassPage credential actions', () => {
  beforeEach(() => {
    mockMe({ hasPerm: true });
  });

  it('disables unlock button when actor is not locked', async () => {
    (client.breakglassListCredentials as ReturnType<typeof vi.fn>).mockResolvedValue([
      {
        actor_id: 'alice',
        created_at: '2026-05-10T00:00:00Z',
        last_password_change_at: '2026-05-10T00:00:00Z',
        failure_count: 0,
      },
    ]);
    renderWithProviders(<BreakglassPage />);
    await waitFor(() => {
      expect(screen.getByTestId('breakglass-row-alice')).toBeInTheDocument();
    });
    const unlockBtn = screen.getByTestId('breakglass-unlock-alice');
    expect(unlockBtn).toBeDisabled();
  });

  it('remove modal requires actor-id type-confirmation', async () => {
    (client.breakglassListCredentials as ReturnType<typeof vi.fn>).mockResolvedValue([
      {
        actor_id: 'alice',
        created_at: '2026-05-10T00:00:00Z',
        last_password_change_at: '2026-05-10T00:00:00Z',
        failure_count: 0,
      },
    ]);
    renderWithProviders(<BreakglassPage />);
    await waitFor(() => {
      expect(screen.getByTestId('breakglass-row-alice')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('breakglass-remove-alice'));
    const removeBtn = screen.getByTestId('breakglass-remove-confirm-submit');
    expect(removeBtn).toBeDisabled();

    // Typing the wrong actor-id keeps it disabled.
    fireEvent.change(screen.getByTestId('breakglass-remove-confirm-input'), {
      target: { value: 'bob' },
    });
    expect(removeBtn).toBeDisabled();

    // Typing the correct actor-id enables it.
    fireEvent.change(screen.getByTestId('breakglass-remove-confirm-input'), {
      target: { value: 'alice' },
    });
    expect(removeBtn).not.toBeDisabled();

    fireEvent.click(removeBtn);
    await waitFor(() => {
      expect(client.breakglassRemove).toHaveBeenCalledWith('alice');
    });
  });
});

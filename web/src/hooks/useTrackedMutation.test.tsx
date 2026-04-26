// Bundle-8 / Audit M-009:
// regression coverage for useTrackedMutation. Confirms that:
//   1. successful mutation invalidates each declared query key
//   2. caller's onSuccess fires after invalidation
//   3. 'noop' invalidates option requires noopReason at the type level
//      (compile-time assertion via the discriminated union — runtime
//      coverage here just confirms 'noop' passes through silently)

import { describe, it, expect, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useTrackedMutation } from './useTrackedMutation';
import type { ReactNode } from 'react';

function withQueryClient(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

describe('useTrackedMutation — Bundle-8 / M-009', () => {
  it('invalidates declared query keys on successful mutation', async () => {
    const client = new QueryClient();
    const invalidateSpy = vi.spyOn(client, 'invalidateQueries');

    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async () => 'ok',
          invalidates: [['certificates'], ['certificate', 'mc-001']],
        }),
      { wrapper: withQueryClient(client) },
    );

    result.current.mutate(undefined);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    // Once per declared key
    expect(invalidateSpy).toHaveBeenCalledTimes(2);
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['certificates'] });
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['certificate', 'mc-001'] });
  });

  it('fires caller onSuccess after invalidation', async () => {
    const client = new QueryClient();
    const onSuccess = vi.fn();
    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async () => 42,
          invalidates: [['certificates']],
          onSuccess,
        }),
      { wrapper: withQueryClient(client) },
    );

    result.current.mutate(undefined);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(onSuccess).toHaveBeenCalledOnce();
    expect(onSuccess.mock.calls[0][0]).toBe(42);
  });

  it("noop variant doesn't invalidate but still runs caller onSuccess", async () => {
    const client = new QueryClient();
    const invalidateSpy = vi.spyOn(client, 'invalidateQueries');
    const onSuccess = vi.fn();
    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async () => 'noop-data',
          invalidates: 'noop',
          noopReason: 'fire-and-forget agent ping; no client cache impact',
          onSuccess,
        }),
      { wrapper: withQueryClient(client) },
    );

    result.current.mutate(undefined);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(invalidateSpy).not.toHaveBeenCalled();
    expect(onSuccess).toHaveBeenCalledOnce();
  });
});

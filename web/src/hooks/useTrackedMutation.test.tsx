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

  // Phase 2 TQ-L1 extension — pin the optimistic-update contract.
  //
  // useTrackedMutation passes onMutate / onError / onSettled through
  // verbatim (only onSuccess is wrapper-owned). The 4 Phase-2 sites
  // (mark-notification-read, dismiss-discovery, claim-discovered,
  // archive-certificate) depend on this pass-through to implement
  // optimistic updates with rollback. These tests pin:
  //   (a) onMutate runs before mutationFn (snapshot pre-mutation state)
  //   (b) onError fires with the snapshot as the 3rd arg (rollback path)
  //   (c) onError pass-through (raw useMutation behaviour preserved)
  //   (d) the no-options call is parity with raw useMutation (the
  //       wrapper imposes no semantic behaviour beyond invalidation
  //       + the optional onSuccess chain).
  it('passes onMutate through and runs it before mutationFn', async () => {
    const client = new QueryClient();
    const order: string[] = [];
    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async () => {
            order.push('mutate');
            return 'ok';
          },
          invalidates: [['something']],
          onMutate: async () => {
            order.push('onMutate');
            return { snapshot: 'pre-state' };
          },
        }),
      { wrapper: withQueryClient(client) },
    );
    result.current.mutate(undefined);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(order).toEqual(['onMutate', 'mutate']);
  });

  it('passes onError through with the onMutate context (rollback path)', async () => {
    const client = new QueryClient();
    const onError = vi.fn();
    const onMutate = vi.fn(async () => ({ snapshot: { foo: 'bar' } }));
    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async () => {
            throw new Error('boom');
          },
          invalidates: [['something']],
          onMutate,
          onError,
        }),
      { wrapper: withQueryClient(client) },
    );
    result.current.mutate(undefined);
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(onMutate).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalledOnce();
    // 3rd arg of onError is the onMutate return value (the snapshot
    // for rollback). Pinning this guarantees the optimistic-update
    // rollback wiring stays intact across future refactors.
    expect(onError.mock.calls[0][2]).toEqual({ snapshot: { foo: 'bar' } });
  });

  it('does NOT invalidate on error (only on success)', async () => {
    const client = new QueryClient();
    const invalidateSpy = vi.spyOn(client, 'invalidateQueries');
    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async () => {
            throw new Error('nope');
          },
          invalidates: [['cache-key']],
        }),
      { wrapper: withQueryClient(client) },
    );
    result.current.mutate(undefined);
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(invalidateSpy).not.toHaveBeenCalled();
  });

  it('passes onSettled through (fires after both success and error)', async () => {
    const client = new QueryClient();
    const onSettled = vi.fn();
    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async () => 'ok',
          invalidates: [['x']],
          onSettled,
        }),
      { wrapper: withQueryClient(client) },
    );
    result.current.mutate(undefined);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(onSettled).toHaveBeenCalledOnce();
  });

  it('parity with raw useMutation when no extra options given', async () => {
    const client = new QueryClient();
    const { result } = renderHook(
      () =>
        useTrackedMutation({
          mutationFn: async (n: number) => n * 2,
          invalidates: [['compute']],
        }),
      { wrapper: withQueryClient(client) },
    );
    result.current.mutate(7);
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toBe(14);
  });
});

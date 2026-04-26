// Bundle-8 / Audit M-009:
//
// Thin wrapper around `useMutation` that REQUIRES the caller to declare
// what the mutation invalidates. Pre-Bundle-8, mutation invalidation
// was per-mutation discretion: a careless `useMutation` could leave
// stale data on screen for users who mutated and then queried.
//
// At Bundle-8 time the codebase has 56 useMutation sites and 70
// invalidateQueries calls — most mutations DO invalidate, but the
// pairing isn't enforced anywhere. This wrapper lets new mutations
// opt into the contract incrementally; the CI grep guard at
// `.github/workflows/ci.yml` ("Bundle-8 / M-009 mutation invalidation
// contract guard") flags new bare `useMutation` calls without a
// nearby invalidation marker.
//
// Usage:
//
//   const renew = useTrackedMutation({
//     mutationFn: () => renewCertificate(certId),
//     invalidates: [['certificates'], ['certificate', certId]],
//   });
//
//   // Or, document why no invalidation is needed:
//   const ping = useTrackedMutation({
//     mutationFn: () => pingAgent(agentId),
//     invalidates: 'noop',  // server-side write that doesn't change cached data
//     noopReason: 'agent ping records timestamp only — no client-side cache impact',
//   });

import {
  useMutation,
  useQueryClient,
  type QueryKey,
  type UseMutationOptions,
} from '@tanstack/react-query';

interface TrackedMutationBase<TData, TError, TVariables, TContext>
  extends Omit<UseMutationOptions<TData, TError, TVariables, TContext>, 'onSuccess'> {
  /** Caller's onSuccess. The wrapper invalidates BEFORE invoking this. */
  onSuccess?: UseMutationOptions<TData, TError, TVariables, TContext>['onSuccess'];
}

interface TrackedMutationWithInvalidates<TData, TError, TVariables, TContext>
  extends TrackedMutationBase<TData, TError, TVariables, TContext> {
  /** QueryKeys that should be invalidated on successful mutation. */
  invalidates: QueryKey[];
  noopReason?: never;
}

interface TrackedMutationNoop<TData, TError, TVariables, TContext>
  extends TrackedMutationBase<TData, TError, TVariables, TContext> {
  /** Explicitly opt out of invalidation. Requires a documented reason. */
  invalidates: 'noop';
  noopReason: string;
}

export type TrackedMutationOptions<TData, TError, TVariables, TContext> =
  | TrackedMutationWithInvalidates<TData, TError, TVariables, TContext>
  | TrackedMutationNoop<TData, TError, TVariables, TContext>;

/**
 * Bundle-8 / M-009 — `useMutation` wrapper that enforces the
 * invalidation contract. See file header for usage.
 */
export function useTrackedMutation<
  TData = unknown,
  TError = Error,
  TVariables = void,
  TContext = unknown,
>(options: TrackedMutationOptions<TData, TError, TVariables, TContext>) {
  const queryClient = useQueryClient();
  const { invalidates, onSuccess, ...rest } = options;

  return useMutation<TData, TError, TVariables, TContext>({
    ...rest,
    onSuccess: (data, variables, onMutateResult, context) => {
      if (Array.isArray(invalidates)) {
        for (const key of invalidates) {
          // void-ignore: invalidateQueries returns a Promise but the
          // wrapper deliberately fires-and-forgets — react-query will
          // refetch in the background while React renders the next state.
          void queryClient.invalidateQueries({ queryKey: key });
        }
      }
      if (onSuccess) {
        return onSuccess(data, variables, onMutateResult, context);
      }
    },
  });
}

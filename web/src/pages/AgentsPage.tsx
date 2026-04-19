import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getAgents,
  listRetiredAgents,
  retireAgent,
  BlockedByDependenciesError,
} from '../api/client';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import type { Column } from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ErrorState from '../components/ErrorState';
import { timeAgo } from '../api/utils';
import type { Agent, AgentDependencyCounts } from '../api/types';

function heartbeatStatus(lastHeartbeat: string): string {
  if (!lastHeartbeat) return 'Offline';
  const ago = Date.now() - new Date(lastHeartbeat).getTime();
  if (ago < 5 * 60 * 1000) return 'Online';
  if (ago < 15 * 60 * 1000) return 'Stale';
  return 'Offline';
}

type TabKey = 'active' | 'retired';

// I-004: retire-modal state machine.
//   confirm  — operator clicked Retire, shown plain confirm + optional reason.
//   blocked  — soft retire returned 409; switch to a force-retire dialog that
//              shows the dependency counts and requires a reason before the
//              operator can opt into ?force=true.
//   error    — any other failure (network, 500, unexpected 4xx). Reused by both
//              the initial attempt and the force retry.
type ModalMode =
  | { kind: 'closed' }
  | { kind: 'confirm'; agent: Agent; reason: string }
  | { kind: 'blocked'; agent: Agent; reason: string; counts: AgentDependencyCounts }
  | { kind: 'error'; agent: Agent; message: string };

export default function AgentsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [tab, setTab] = useState<TabKey>('active');
  const [modal, setModal] = useState<ModalMode>({ kind: 'closed' });

  const active = useQuery({
    queryKey: ['agents'],
    queryFn: () => getAgents(),
    refetchInterval: 15000,
    enabled: tab === 'active',
  });

  const retired = useQuery({
    queryKey: ['agents', 'retired'],
    queryFn: () => listRetiredAgents(),
    refetchInterval: 30000,
    enabled: tab === 'retired',
  });

  // retireAgent mutation wrapping both paths. The caller supplies force/reason,
  // and we invalidate both queries on success so the retired tab refreshes and
  // the active tab drops the row. 409s are converted into modal.mode=blocked so
  // the operator can escalate to force; everything else becomes modal.mode=error.
  const mutation = useMutation({
    mutationFn: (input: { agent: Agent; force?: boolean; reason?: string }) =>
      retireAgent(input.agent.id, { force: input.force, reason: input.reason }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents'] });
      qc.invalidateQueries({ queryKey: ['agents', 'retired'] });
      setModal({ kind: 'closed' });
    },
  });

  // Shared submit handler: when we know the current modal.agent + modal.reason,
  // decide whether this is a soft retire or force retire based on modal.kind.
  const submitRetire = (force: boolean) => {
    if (modal.kind !== 'confirm' && modal.kind !== 'blocked') return;
    const { agent, reason } = modal;
    mutation.mutate(
      { agent, force, reason: reason || undefined },
      {
        onError: (err) => {
          if (err instanceof BlockedByDependenciesError) {
            setModal({
              kind: 'blocked',
              agent,
              reason,
              counts: err.counts ?? { active_targets: 0, active_certificates: 0, pending_jobs: 0 },
            });
            return;
          }
          setModal({
            kind: 'error',
            agent,
            message: err instanceof Error ? err.message : String(err),
          });
        },
      },
    );
  };

  const activeColumns: Column<Agent>[] = [
    {
      key: 'name',
      label: 'Agent',
      render: (a) => (
        <div>
          <div className="font-medium text-ink">{a.name}</div>
          <div className="text-xs text-ink-faint">{a.id}</div>
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Health',
      render: (a) => <StatusBadge status={a.status || heartbeatStatus(a.last_heartbeat_at)} />,
    },
    {
      key: 'hostname',
      label: 'Hostname',
      render: (a) => <span className="text-ink-muted font-mono text-xs">{a.hostname || '—'}</span>,
    },
    {
      key: 'os',
      label: 'OS / Arch',
      render: (a) => (
        <span className="text-ink-muted text-xs">
          {a.os && a.architecture ? `${a.os}/${a.architecture}` : a.os || '—'}
        </span>
      ),
    },
    {
      key: 'ip',
      label: 'IP Address',
      render: (a) => <span className="text-ink-muted font-mono text-xs">{a.ip_address || '—'}</span>,
    },
    {
      key: 'version',
      label: 'Version',
      render: (a) => <span className="text-ink-muted text-xs">{a.version || '—'}</span>,
    },
    {
      key: 'heartbeat',
      label: 'Last Heartbeat',
      render: (a) => <span className="text-ink-muted text-xs">{timeAgo(a.last_heartbeat_at)}</span>,
    },
    {
      key: 'actions',
      label: '',
      render: (a) => (
        <button
          type="button"
          onClick={(e) => {
            // Table rows are navigable via onRowClick. The retire button must
            // not trigger the row-click handler or the modal will race the
            // navigation and unmount mid-render.
            e.stopPropagation();
            setModal({ kind: 'confirm', agent: a, reason: '' });
          }}
          className="px-3 py-1 text-xs font-medium text-danger border border-danger/30 rounded hover:bg-danger/10"
        >
          Retire
        </button>
      ),
    },
  ];

  const retiredColumns: Column<Agent>[] = [
    {
      key: 'name',
      label: 'Agent',
      render: (a) => (
        <div>
          <div className="font-medium text-ink">{a.name}</div>
          <div className="text-xs text-ink-faint">{a.id}</div>
        </div>
      ),
    },
    {
      key: 'hostname',
      label: 'Hostname',
      render: (a) => <span className="text-ink-muted font-mono text-xs">{a.hostname || '—'}</span>,
    },
    {
      key: 'os',
      label: 'OS / Arch',
      render: (a) => (
        <span className="text-ink-muted text-xs">
          {a.os && a.architecture ? `${a.os}/${a.architecture}` : a.os || '—'}
        </span>
      ),
    },
    {
      key: 'retired_at',
      label: 'Retired',
      render: (a) => <span className="text-ink-muted text-xs">{timeAgo(a.retired_at || '')}</span>,
    },
    {
      key: 'retired_reason',
      label: 'Reason',
      render: (a) => (
        <span className="text-ink-muted text-xs">{a.retired_reason || <em>—</em>}</span>
      ),
    },
  ];

  const currentQuery = tab === 'active' ? active : retired;
  const currentColumns = tab === 'active' ? activeColumns : retiredColumns;
  const emptyMessage = tab === 'active' ? 'No agents registered' : 'No retired agents';

  return (
    <>
      <PageHeader
        title="Agents"
        subtitle={
          tab === 'active' && active.data
            ? `${active.data.total} active`
            : tab === 'retired' && retired.data
              ? `${retired.data.total} retired`
              : undefined
        }
      />

      <div className="px-6 pt-2">
        <div className="flex gap-2 border-b border-border">
          <TabButton active={tab === 'active'} onClick={() => setTab('active')}>
            Active
          </TabButton>
          <TabButton active={tab === 'retired'} onClick={() => setTab('retired')}>
            Retired
          </TabButton>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {currentQuery.error ? (
          <ErrorState error={currentQuery.error as Error} onRetry={() => currentQuery.refetch()} />
        ) : (
          <DataTable
            columns={currentColumns}
            data={currentQuery.data?.data || []}
            isLoading={currentQuery.isLoading}
            emptyMessage={emptyMessage}
            onRowClick={(a) => navigate(`/agents/${a.id}`)}
          />
        )}
      </div>

      {modal.kind !== 'closed' && (
        <RetireModal
          mode={modal}
          pending={mutation.isPending}
          onClose={() => setModal({ kind: 'closed' })}
          onReasonChange={(reason) => {
            if (modal.kind === 'confirm') setModal({ ...modal, reason });
            if (modal.kind === 'blocked') setModal({ ...modal, reason });
          }}
          onSoftRetire={() => submitRetire(false)}
          onForceRetire={() => submitRetire(true)}
        />
      )}
    </>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        active
          ? 'px-4 py-2 text-sm font-medium text-ink border-b-2 border-accent -mb-px'
          : 'px-4 py-2 text-sm text-ink-muted hover:text-ink'
      }
    >
      {children}
    </button>
  );
}

function RetireModal({
  mode,
  pending,
  onClose,
  onReasonChange,
  onSoftRetire,
  onForceRetire,
}: {
  mode: ModalMode;
  pending: boolean;
  onClose: () => void;
  onReasonChange: (reason: string) => void;
  onSoftRetire: () => void;
  onForceRetire: () => void;
}) {
  if (mode.kind === 'closed') return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/40"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-lg bg-surface p-6 shadow-lg border border-border"
        onClick={(e) => e.stopPropagation()}
      >
        {mode.kind === 'confirm' && (
          <>
            <h2 className="text-lg font-semibold text-ink">Retire agent</h2>
            <p className="mt-2 text-sm text-ink-muted">
              <span className="font-mono">{mode.agent.name}</span> ({mode.agent.id}) will be
              soft-retired. The agent will stop receiving heartbeats and be removed from active
              listings. This is reversible only by direct database intervention.
            </p>
            <label className="mt-4 block text-xs font-medium text-ink-muted">
              Reason (optional)
              <input
                type="text"
                value={mode.reason}
                onChange={(e) => onReasonChange(e.target.value)}
                placeholder="e.g. decommissioning rack 7"
                className="mt-1 w-full rounded border border-border bg-surface-alt px-2 py-1 text-sm"
              />
            </label>
            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-sm text-ink-muted hover:text-ink"
                disabled={pending}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={onSoftRetire}
                disabled={pending}
                className="px-4 py-2 text-sm font-medium text-white bg-danger rounded hover:bg-danger/90 disabled:opacity-50"
              >
                {pending ? 'Retiring…' : 'Retire'}
              </button>
            </div>
          </>
        )}

        {mode.kind === 'blocked' && (
          <>
            <h2 className="text-lg font-semibold text-ink">Cannot retire — active dependencies</h2>
            <p className="mt-2 text-sm text-ink-muted">
              The agent <span className="font-mono">{mode.agent.name}</span> still has downstream
              work tied to it. Force-retiring will cascade-retire all active targets and fail any
              pending jobs.
            </p>
            <dl className="mt-4 grid grid-cols-3 gap-3 text-center">
              <div className="rounded border border-border bg-surface-alt p-3">
                <dt className="text-xs text-ink-muted">Active targets</dt>
                <dd className="mt-1 text-xl font-semibold text-ink">{mode.counts.active_targets}</dd>
              </div>
              <div className="rounded border border-border bg-surface-alt p-3">
                <dt className="text-xs text-ink-muted">Active certs</dt>
                <dd className="mt-1 text-xl font-semibold text-ink">
                  {mode.counts.active_certificates}
                </dd>
              </div>
              <div className="rounded border border-border bg-surface-alt p-3">
                <dt className="text-xs text-ink-muted">Pending jobs</dt>
                <dd className="mt-1 text-xl font-semibold text-ink">{mode.counts.pending_jobs}</dd>
              </div>
            </dl>
            <label className="mt-4 block text-xs font-medium text-ink-muted">
              Reason <span className="text-danger">(required for force retire)</span>
              <input
                type="text"
                value={mode.reason}
                onChange={(e) => onReasonChange(e.target.value)}
                placeholder="e.g. rack 7 decommission, cascade retire"
                className="mt-1 w-full rounded border border-border bg-surface-alt px-2 py-1 text-sm"
              />
            </label>
            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-sm text-ink-muted hover:text-ink"
                disabled={pending}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={onForceRetire}
                // Backend enforces reason on force; keep the GUI in lockstep
                // rather than letting a 400 bounce back.
                disabled={pending || !mode.reason.trim()}
                className="px-4 py-2 text-sm font-medium text-white bg-danger rounded hover:bg-danger/90 disabled:opacity-50"
              >
                {pending ? 'Force-retiring…' : 'Force retire'}
              </button>
            </div>
          </>
        )}

        {mode.kind === 'error' && (
          <>
            <h2 className="text-lg font-semibold text-ink">Retire failed</h2>
            <p className="mt-2 text-sm text-danger">{mode.message}</p>
            <div className="mt-6 flex justify-end">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-sm text-ink-muted hover:text-ink"
              >
                Close
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

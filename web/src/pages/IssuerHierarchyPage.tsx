import { useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useTrackedMutation } from '../hooks/useTrackedMutation';
import { listIntermediateCAs, retireIntermediateCA, type IntermediateCA } from '../api/client';
import PageHeader from '../components/PageHeader';
import ErrorState from '../components/ErrorState';
import { formatDateTime } from '../api/utils';

// IssuerHierarchyPage renders the operator-managed CA hierarchy for a
// single issuer. Rank 8 of the 2026-05-03 deep-research deliverable.
//
// The recursive tree is built client-side from the flat list returned
// by GET /api/v1/issuers/{id}/intermediates — each row's parent_ca_id
// (nil = root) drives the nesting. We render with native HTML <ul>
// elements rather than pulling D3 to keep the dep graph thin; the
// dendrogram view is parking-lot work tracked in WORKSPACE-ROADMAP.
//
// Admin gate: the backend handlers enforce admin role at the API
// layer (M-008 pattern). The page itself is reachable from the issuer
// detail nav; non-admin callers see a 403 from the API and the page
// renders the error.
export default function IssuerHierarchyPage() {
  const { id: issuerID = '' } = useParams<{ id: string }>();
  const [retireConfirmFor, setRetireConfirmFor] = useState<string | null>(null);

  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ['issuer-hierarchy', issuerID],
    queryFn: () => listIntermediateCAs(issuerID),
    enabled: issuerID !== '',
  });

  const retireMu = useTrackedMutation({
    mutationKey: ['retire-intermediate-ca'],
    mutationFn: (vars: { id: string; note: string; confirm: boolean }) =>
      retireIntermediateCA(vars.id, vars.note, vars.confirm),
    onSuccess: () => {
      setRetireConfirmFor(null);
      refetch();
    },
    invalidates: [['issuer-hierarchy', issuerID]],
  });

  const tree = useMemo(() => buildHierarchyTree(data?.data ?? []), [data?.data]);

  if (issuerID === '') {
    return <ErrorState error={new Error('No issuer id in URL.')} />;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Certificate authority hierarchy"
        subtitle="Multi-level CA hierarchy backed by the intermediate_cas table. Each row is one CA cert (root, policy, issuing). The recursive nesting is driven by parent_ca_id."
      />

      {isLoading && <p className="text-sm text-slate-500">Loading hierarchy…</p>}
      {error && (
        <ErrorState
          error={error instanceof Error ? error : new Error(String(error))}
          onRetry={() => refetch()}
        />
      )}

      {tree.length === 0 && !isLoading && !error && (
        <div className="rounded-md border border-slate-200 bg-slate-50 p-6 text-sm text-slate-600">
          <p className="font-medium">No CA hierarchy registered yet for this issuer.</p>
          <p className="mt-2">
            Operators register a root via <code>POST /api/v1/issuers/{issuerID}/intermediates</code> with
            <code> root_cert_pem</code> + <code>key_driver_id</code> set, then chain
            <code> POST </code> calls with <code>parent_ca_id</code> to build out the tree. See
            <code> docs/intermediate-ca-hierarchy.md</code> for the operator runbook.
          </p>
        </div>
      )}

      {tree.length > 0 && (
        <ul className="space-y-2 text-sm">
          {tree.map(node => (
            <HierarchyNode
              key={node.ca.id}
              node={node}
              depth={0}
              retireConfirmFor={retireConfirmFor}
              setRetireConfirmFor={setRetireConfirmFor}
              onRetire={(id, note, confirm) => retireMu.mutate({ id, note, confirm })}
              retireDisabled={retireMu.isPending}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

interface HierarchyTreeNode {
  ca: IntermediateCA;
  children: HierarchyTreeNode[];
}

// buildHierarchyTree turns the flat list into a parent-child forest by
// grouping rows on parent_ca_id. Roots (parent_ca_id null/empty) are
// the forest's top level; everything else nests under its parent.
function buildHierarchyTree(rows: IntermediateCA[]): HierarchyTreeNode[] {
  const byID = new Map<string, HierarchyTreeNode>();
  rows.forEach(row => byID.set(row.id, { ca: row, children: [] }));
  const roots: HierarchyTreeNode[] = [];
  rows.forEach(row => {
    const node = byID.get(row.id)!;
    if (!row.parent_ca_id) {
      roots.push(node);
      return;
    }
    const parent = byID.get(row.parent_ca_id);
    if (parent) {
      parent.children.push(node);
    } else {
      // Orphan (parent retired+pruned) — still surface at the top.
      roots.push(node);
    }
  });
  return roots;
}

interface HierarchyNodeProps {
  node: HierarchyTreeNode;
  depth: number;
  retireConfirmFor: string | null;
  setRetireConfirmFor: (id: string | null) => void;
  onRetire: (id: string, note: string, confirm: boolean) => void;
  retireDisabled: boolean;
}

function HierarchyNode({
  node,
  depth,
  retireConfirmFor,
  setRetireConfirmFor,
  onRetire,
  retireDisabled,
}: HierarchyNodeProps) {
  const { ca, children } = node;
  const isRetiring = ca.state === 'retiring';
  const isRetired = ca.state === 'retired';
  const stateBadge =
    ca.state === 'active'
      ? 'bg-emerald-100 text-emerald-700'
      : ca.state === 'retiring'
      ? 'bg-amber-100 text-amber-700'
      : 'bg-slate-100 text-slate-600';

  return (
    <li
      className="rounded-md border border-slate-200 bg-white p-3"
      style={{ marginLeft: depth * 24 }}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-slate-500">{ca.id}</span>
            <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${stateBadge}`}>
              {ca.state}
            </span>
            {ca.path_len_constraint !== undefined && ca.path_len_constraint !== null && (
              <span className="text-xs text-slate-500">path_len={ca.path_len_constraint}</span>
            )}
          </div>
          <div className="mt-1 font-medium">{ca.name}</div>
          <div className="mt-1 text-xs text-slate-600">{ca.subject}</div>
          <div className="mt-1 text-xs text-slate-500">
            valid {formatDateTime(ca.not_before)} → {formatDateTime(ca.not_after)}
          </div>
          {ca.name_constraints && ca.name_constraints.length > 0 && (
            <div className="mt-1 text-xs text-slate-500">
              constraints: {ca.name_constraints.flatMap(nc => nc.permitted ?? []).join(', ') || '—'}
            </div>
          )}
        </div>
        {!isRetired && (
          <div className="flex flex-col gap-1">
            {retireConfirmFor === ca.id ? (
              <>
                <button
                  type="button"
                  className="rounded bg-red-600 px-3 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
                  disabled={retireDisabled}
                  onClick={() => onRetire(ca.id, isRetiring ? 'terminalize' : 'drain', isRetiring)}
                >
                  {isRetiring ? 'Confirm retire (terminal)' : 'Retire (begin drain)'}
                </button>
                <button
                  type="button"
                  className="rounded border border-slate-300 px-3 py-1 text-xs"
                  onClick={() => setRetireConfirmFor(null)}
                >
                  Cancel
                </button>
              </>
            ) : (
              <button
                type="button"
                className="rounded border border-slate-300 px-3 py-1 text-xs hover:bg-slate-100"
                onClick={() => setRetireConfirmFor(ca.id)}
              >
                {isRetiring ? 'Terminalize…' : 'Retire…'}
              </button>
            )}
          </div>
        )}
      </div>
      {children.length > 0 && (
        <ul className="mt-3 space-y-2">
          {children.map(child => (
            <HierarchyNode
              key={child.ca.id}
              node={child}
              depth={depth + 1}
              retireConfirmFor={retireConfirmFor}
              setRetireConfirmFor={setRetireConfirmFor}
              onRetire={onRetire}
              retireDisabled={retireDisabled}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

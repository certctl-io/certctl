import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import Skeleton from './Skeleton';

// Phase 9 closure (UX-M8): row-density toggle. Three tiers map to the
// vertical padding on tbody td elements. Compact wins at 5K-row dense
// data review; Spacious wins for low-attention scanning; Comfortable
// is the existing pre-Phase-9 default. Choice persists per-table via
// the `tableId` prop — keyed at certctl.density.<id> so two tables on
// one page don't fight each other.
export type Density = 'compact' | 'comfortable' | 'spacious';

const DENSITY_CELL_CLASS: Record<Density, string> = {
  compact:     'px-4 py-1.5',
  comfortable: 'px-4 py-3',
  spacious:    'px-4 py-4',
};

const DENSITY_HEADER_CLASS: Record<Density, string> = {
  compact:     'px-4 py-2',
  comfortable: 'px-4 py-3',
  spacious:    'px-4 py-3.5',
};

function readDensityPref(tableId: string | undefined): Density {
  if (!tableId || typeof localStorage === 'undefined') return 'comfortable';
  try {
    const v = localStorage.getItem(`certctl.density.${tableId}`);
    if (v === 'compact' || v === 'comfortable' || v === 'spacious') return v;
  } catch { /* noop */ }
  return 'comfortable';
}

function writeDensityPref(tableId: string | undefined, d: Density): void {
  if (!tableId || typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(`certctl.density.${tableId}`, d);
  } catch { /* noop */ }
}

interface Column<T> {
  key: string;
  label: string;
  render: (item: T) => React.ReactNode;
  className?: string;
}

// F-1 closure (cat-k-e85d1099b2d7): DataTable was a render-only
// component pre-F-1 — every consumer page handed it the first 50
// rows from a paginated endpoint and there was no way for the
// operator to advance. The backend has always returned `{data,
// total, page, per_page}` but the frontend never surfaced page
// 2+. The pagination prop below opt-ins reusable controls in the
// table footer; CertificatesPage is the first consumer (and the
// audit's flagged page), but TargetsPage / IssuersPage / others
// can adopt by passing the same prop.
interface PaginationProps {
  page: number;
  perPage: number;
  total: number;
  onPageChange: (page: number) => void;
  onPerPageChange?: (perPage: number) => void;
  perPageOptions?: number[];
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (item: T) => void;
  emptyMessage?: string;
  /**
   * UX-M3 / Phase 1: rich empty-state slot. Pass an <EmptyState />
   * component (or any ReactNode) here when the page wants a CTA-driven
   * first-run experience instead of the bare emptyMessage string. The
   * existing `emptyMessage` prop is preserved for backward compat with
   * the ~18 list-page call sites that pass a simple string.
   */
  emptyState?: ReactNode;
  isLoading?: boolean;
  keyField?: string;
  selectable?: boolean;
  selectedKeys?: Set<string>;
  onSelectionChange?: (keys: Set<string>) => void;
  pagination?: PaginationProps;
  /**
   * Phase 9 (UX-M8): per-table identifier for the density preference.
   * Use a stable string like `'certificates-list'` — choice persists
   * to localStorage at `certctl.density.<tableId>`. When unset, the
   * density toggle is hidden (the table renders at the default
   * 'comfortable' density) — opt-in per-page rollout.
   */
  tableId?: string;
  /**
   * Initial density. Overridden by the persisted preference when
   * tableId is set. Defaults to 'comfortable' (matches pre-Phase-9
   * vertical padding exactly so existing pages render identically
   * until an operator flips the toggle).
   */
  density?: Density;
}

export default function DataTable<T>({ columns, data, onRowClick, emptyMessage, emptyState, isLoading, keyField = 'id', selectable, selectedKeys, onSelectionChange, pagination, tableId, density: densityProp }: DataTableProps<T>) {
  // Phase 9 (UX-M8): density preference. When tableId is set, read
  // localStorage at mount; otherwise use the prop default (or
  // 'comfortable'). Persist writes via setDensity.
  const [density, setDensityState] = useState<Density>(() =>
    tableId ? readDensityPref(tableId) : (densityProp ?? 'comfortable'),
  );
  useEffect(() => {
    // If tableId changes (rare but possible if a parent swaps it),
    // re-read the persisted preference.
    if (tableId) setDensityState(readDensityPref(tableId));
  }, [tableId]);

  const setDensity = (d: Density) => {
    setDensityState(d);
    writeDensityPref(tableId, d);
  };
  const cellCls   = DENSITY_CELL_CLASS[density];
  const headerCls = DENSITY_HEADER_CLASS[density];
  // Phase 4 closure (UX-M1): swap the centered spinner + "Loading..."
  // text — which paints into a tiny vertical span and then jumps to a
  // full-height table on resolve, the canonical CLS source — for a
  // layout-shape-matching skeleton table sized to the actual column
  // count. The eye reads "table loading here" and the eventual data
  // lands in the same DOM rectangle with zero reflow.
  if (isLoading) {
    return <Skeleton variant="table" columns={columns.length + (selectable ? 1 : 0)} />;
  }

  if (!data.length) {
    // UX-M3 / Phase 1: prefer the rich <EmptyState /> slot when supplied;
    // fall back to the legacy string render so existing call sites with
    // emptyMessage="…" stay unchanged.
    if (emptyState) {
      return <>{emptyState}</>;
    }
    return (
      <div className="flex items-center justify-center py-16 text-ink-faint">
        {emptyMessage || 'No data found'}
      </div>
    );
  }

  const allKeys = data.map((item) => (item as Record<string, unknown>)[keyField] as string);
  const allSelected = selectable && selectedKeys && allKeys.length > 0 && allKeys.every(k => selectedKeys.has(k));

  const toggleAll = () => {
    if (!onSelectionChange) return;
    if (allSelected) {
      onSelectionChange(new Set());
    } else {
      onSelectionChange(new Set(allKeys));
    }
  };

  const toggleOne = (key: string) => {
    if (!onSelectionChange || !selectedKeys) return;
    const next = new Set(selectedKeys);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    onSelectionChange(next);
  };

  return (
    <div className="overflow-x-auto">
      {tableId && (
        <DensityToggle current={density} onChange={setDensity} />
      )}
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b-2 border-surface-border bg-surface-muted">
            {selectable && (
              <th scope="col" className={`w-10 ${headerCls}`}>
                <input
                  type="checkbox"
                  checked={allSelected || false}
                  onChange={toggleAll}
                  className="rounded border-surface-border bg-white text-brand-500 focus:ring-brand-500 focus:ring-offset-0 cursor-pointer"
                />
              </th>
            )}
            {columns.map(col => (
              <th key={col.key} scope="col" className={`${headerCls} text-left text-xs font-semibold text-ink-muted uppercase tracking-wider ${col.className || ''}`}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item, i) => {
            const rowKey = (item as Record<string, unknown>)[keyField] as string ?? `row-${i}`;
            const isSelected = selectable && selectedKeys?.has(rowKey);
            return (
              <tr
                key={rowKey}
                onClick={() => onRowClick?.(item)}
                className={`border-b border-surface-border/50 transition-colors hover:bg-surface-muted ${onRowClick ? 'cursor-pointer' : ''} ${isSelected ? 'bg-brand-50' : ''}`}
              >
                {selectable && (
                  <td className={`w-10 ${cellCls}`}>
                    <input
                      type="checkbox"
                      checked={isSelected || false}
                      onChange={(e) => { e.stopPropagation(); toggleOne(rowKey); }}
                      onClick={(e) => e.stopPropagation()}
                      className="rounded border-surface-border bg-white text-brand-500 focus:ring-brand-500 focus:ring-offset-0 cursor-pointer"
                    />
                  </td>
                )}
                {columns.map(col => (
                  <td key={col.key} className={`${cellCls} text-ink ${col.className || ''}`}>
                    {col.render(item)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
      {pagination && pagination.total > 0 && (
        <PaginationControls {...pagination} />
      )}
    </div>
  );
}

/**
 * Phase 9 UX-M8: 3-button row-density toggle. Renders only when the
 * parent DataTable was given a `tableId` (the opt-in signal that this
 * page wants the per-table localStorage persistence).
 */
function DensityToggle({ current, onChange }: { current: Density; onChange: (d: Density) => void }) {
  const opts: { value: Density; label: string }[] = [
    { value: 'compact',     label: 'Compact' },
    { value: 'comfortable', label: 'Cozy' },
    { value: 'spacious',    label: 'Spacious' },
  ];
  return (
    <div className="flex justify-end mb-1.5" role="group" aria-label="Row density">
      <div className="inline-flex rounded-md border border-surface-border bg-surface text-xs overflow-hidden" data-testid="datatable-density-toggle">
        {opts.map((o, i) => (
          <button
            key={o.value}
            type="button"
            onClick={() => onChange(o.value)}
            aria-pressed={current === o.value}
            data-testid={`datatable-density-${o.value}`}
            className={
              `px-2.5 py-1 transition-colors ` +
              (current === o.value
                ? 'bg-brand-500 text-white'
                : 'text-ink-muted hover:text-ink hover:bg-surface-muted') +
              (i > 0 ? ' border-l border-surface-border' : '')
            }
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

// F-1 closure (cat-k-e85d1099b2d7): pagination footer for DataTable
// consumers that want prev/next + page counter + per-page selector
// against a paginated backend response. Disabling logic guards the
// boundaries (prev disabled on page 1; next disabled when page *
// per_page >= total).
function PaginationControls({ page, perPage, total, onPageChange, onPerPageChange, perPageOptions }: PaginationProps) {
  const start = total === 0 ? 0 : (page - 1) * perPage + 1;
  const end = Math.min(page * perPage, total);
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  const isFirst = page <= 1;
  const isLast = page >= lastPage;
  const options = perPageOptions ?? [25, 50, 100, 200];
  return (
    <div className="flex items-center justify-between border-t border-surface-border px-4 py-3 text-sm text-ink-muted">
      <span>
        Showing <span className="font-medium text-ink">{start}</span>–<span className="font-medium text-ink">{end}</span> of <span className="font-medium text-ink">{total.toLocaleString()}</span>
      </span>
      <div className="flex items-center gap-3">
        {onPerPageChange && (
          <label className="flex items-center gap-2 text-xs">
            <span>Rows per page:</span>
            <select
              value={perPage}
              onChange={e => onPerPageChange(Number(e.target.value))}
              className="rounded border border-surface-border bg-white px-2 py-1 text-xs text-ink focus:outline-none focus:border-brand-400"
            >
              {options.map(opt => (
                <option key={opt} value={opt}>{opt}</option>
              ))}
            </select>
          </label>
        )}
        <span className="text-xs">
          Page <span className="font-medium text-ink">{page}</span> of <span className="font-medium text-ink">{lastPage}</span>
        </span>
        <div className="flex gap-1">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={isFirst}
            className="rounded border border-surface-border px-3 py-1 text-xs text-ink hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            Prev
          </button>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={isLast}
            className="rounded border border-surface-border px-3 py-1 text-xs text-ink hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

export type { Column, PaginationProps };

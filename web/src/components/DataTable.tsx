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
  isLoading?: boolean;
  keyField?: string;
  selectable?: boolean;
  selectedKeys?: Set<string>;
  onSelectionChange?: (keys: Set<string>) => void;
  pagination?: PaginationProps;
}

export default function DataTable<T>({ columns, data, onRowClick, emptyMessage, isLoading, keyField = 'id', selectable, selectedKeys, onSelectionChange, pagination }: DataTableProps<T>) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-ink-muted">
        <svg className="animate-spin h-5 w-5 mr-3" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        Loading...
      </div>
    );
  }

  if (!data.length) {
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
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b-2 border-surface-border bg-surface-muted">
            {selectable && (
              <th className="px-3 py-3 w-10">
                <input
                  type="checkbox"
                  checked={allSelected || false}
                  onChange={toggleAll}
                  className="rounded border-surface-border bg-white text-brand-500 focus:ring-brand-500 focus:ring-offset-0 cursor-pointer"
                />
              </th>
            )}
            {columns.map(col => (
              <th key={col.key} className={`px-4 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-wider ${col.className || ''}`}>
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
                  <td className="px-3 py-3 w-10">
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
                  <td key={col.key} className={`px-4 py-3 text-ink ${col.className || ''}`}>
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

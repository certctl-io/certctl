interface Column<T> {
  key: string;
  label: string;
  render: (item: T) => React.ReactNode;
  className?: string;
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
}

export default function DataTable<T>({ columns, data, onRowClick, emptyMessage, isLoading, keyField = 'id', selectable, selectedKeys, onSelectionChange }: DataTableProps<T>) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-slate-400">
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
      <div className="flex items-center justify-center py-16 text-slate-500">
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
          <tr className="border-b-2 border-slate-700">
            {selectable && (
              <th className="px-3 py-3 w-10">
                <input
                  type="checkbox"
                  checked={allSelected || false}
                  onChange={toggleAll}
                  className="rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 cursor-pointer"
                />
              </th>
            )}
            {columns.map(col => (
              <th key={col.key} className={`px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider ${col.className || ''}`}>
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
                className={`border-b border-slate-700/50 transition-colors hover:bg-blue-500/5 ${onRowClick ? 'cursor-pointer' : ''} ${isSelected ? 'bg-blue-500/10' : ''}`}
              >
                {selectable && (
                  <td className="px-3 py-3 w-10">
                    <input
                      type="checkbox"
                      checked={isSelected || false}
                      onChange={(e) => { e.stopPropagation(); toggleOne(rowKey); }}
                      onClick={(e) => e.stopPropagation()}
                      className="rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 cursor-pointer"
                    />
                  </td>
                )}
                {columns.map(col => (
                  <td key={col.key} className={`px-4 py-3 ${col.className || ''}`}>
                    {col.render(item)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export type { Column };

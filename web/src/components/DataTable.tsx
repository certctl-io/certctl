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
}

export default function DataTable<T>({ columns, data, onRowClick, emptyMessage, isLoading }: DataTableProps<T>) {
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

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b-2 border-slate-700">
            {columns.map(col => (
              <th key={col.key} className={`px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider ${col.className || ''}`}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item, i) => (
            <tr
              key={i}
              onClick={() => onRowClick?.(item)}
              className={`border-b border-slate-700/50 transition-colors hover:bg-blue-500/5 ${onRowClick ? 'cursor-pointer' : ''}`}
            >
              {columns.map(col => (
                <td key={col.key} className={`px-4 py-3 ${col.className || ''}`}>
                  {col.render(item)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export type { Column };

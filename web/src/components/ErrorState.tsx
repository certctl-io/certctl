interface ErrorStateProps {
  error: Error;
  onRetry?: () => void;
}

export default function ErrorState({ error, onRetry }: ErrorStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-400">
      <svg className="w-12 h-12 text-red-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
      </svg>
      <p className="text-sm mb-2">Failed to load data</p>
      <p className="text-xs text-slate-500 mb-4">{error.message}</p>
      {onRetry && (
        <button onClick={onRetry} className="btn btn-primary text-xs">
          Retry
        </button>
      )}
    </div>
  );
}

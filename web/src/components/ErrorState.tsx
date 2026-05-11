// ErrorState supports two call shapes:
//   1. error-object form: <ErrorState error={err} onRetry={fn} />
//   2. title+message form: <ErrorState title="…" message="…" data-testid="…" />
//
// The title/message form was added by Audit 2026-05-10 CRIT-4
// (BreakglassPage admin GUI) so pages can render a denied/disabled
// banner without manufacturing a synthetic Error. When `title` is
// supplied, it takes precedence over the default headline; when
// `message` is supplied, it takes precedence over `error.message`.
interface ErrorStateProps {
  error?: Error;
  onRetry?: () => void;
  title?: string;
  message?: string;
  'data-testid'?: string;
}

export default function ErrorState({
  error,
  onRetry,
  title,
  message,
  'data-testid': dataTestid,
}: ErrorStateProps) {
  const headline = title ?? 'Failed to load data';
  const detail = message ?? error?.message ?? '';
  return (
    <div
      className="flex flex-col items-center justify-center py-16 text-ink-muted"
      data-testid={dataTestid}
    >
      <svg className="w-12 h-12 text-red-700 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
      </svg>
      <p className="text-sm mb-2 text-ink">{headline}</p>
      {detail && <p className="text-xs text-ink-faint mb-4">{detail}</p>}
      {onRetry && (
        <button onClick={onRetry} className="btn btn-primary text-xs">
          Retry
        </button>
      )}
    </div>
  );
}

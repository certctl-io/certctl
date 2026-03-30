import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { previewDigest, sendDigest } from '../api/client';
import PageHeader from '../components/PageHeader';
import ErrorState from '../components/ErrorState';

export default function DigestPage() {
  const [showConfirm, setShowConfirm] = useState(false);

  const { data: html, isLoading, error, refetch } = useQuery({
    queryKey: ['digest-preview'],
    queryFn: previewDigest,
    retry: false,
  });

  const sendMutation = useMutation({
    mutationFn: sendDigest,
    onSuccess: () => setShowConfirm(false),
  });

  return (
    <>
      <PageHeader
        title="Certificate Digest"
        subtitle="Preview and send the scheduled certificate digest email"
        action={
          <button
            onClick={() => setShowConfirm(true)}
            disabled={!html || sendMutation.isPending}
            className="btn btn-primary text-xs disabled:opacity-50"
          >
            Send Digest Now
          </button>
        }
      />

      <div className="flex-1 overflow-y-auto px-6 py-4">
        {sendMutation.isSuccess && (
          <div className="mb-4 px-4 py-2.5 bg-emerald-50 border border-emerald-200 rounded-lg text-sm text-emerald-700">
            Digest sent successfully.
          </div>
        )}
        {sendMutation.isError && (
          <div className="mb-4 px-4 py-2.5 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
            Failed to send digest: {(sendMutation.error as Error).message}
          </div>
        )}

        {isLoading && (
          <div className="flex items-center justify-center py-20">
            <div className="text-sm text-ink-muted">Loading digest preview...</div>
          </div>
        )}

        {error && (
          <ErrorState
            error={error as Error}
            onRetry={() => refetch()}
          />
        )}

        {html && (
          <div className="bg-white border border-surface-border rounded-lg shadow-sm overflow-hidden">
            <div className="px-4 py-2.5 bg-surface border-b border-surface-border flex items-center justify-between">
              <span className="text-xs text-ink-muted font-medium">Email Preview</span>
              <button
                onClick={() => refetch()}
                className="text-xs text-brand-400 hover:text-brand-500"
              >
                Refresh
              </button>
            </div>
            <iframe
              srcDoc={html}
              title="Digest Preview"
              className="w-full border-0"
              style={{ minHeight: '600px' }}
              sandbox="allow-same-origin"
            />
          </div>
        )}
      </div>

      {showConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowConfirm(false)}>
          <div className="bg-white rounded-lg shadow-xl w-full max-w-sm mx-4" onClick={e => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-surface-border">
              <h3 className="text-lg font-semibold text-ink">Send Digest</h3>
              <p className="text-sm text-ink-muted mt-1">
                This will send the certificate digest email to all configured recipients.
              </p>
            </div>
            <div className="px-6 py-3 border-t border-surface-border flex justify-end gap-2">
              <button onClick={() => setShowConfirm(false)} className="px-4 py-2 text-sm text-ink-muted hover:text-ink rounded border border-surface-border">
                Cancel
              </button>
              <button
                onClick={() => sendMutation.mutate()}
                disabled={sendMutation.isPending}
                className="px-4 py-2 text-sm text-white bg-brand-500 hover:bg-brand-600 rounded disabled:opacity-50"
              >
                {sendMutation.isPending ? 'Sending...' : 'Send'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

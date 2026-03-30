/**
 * Full config viewer modal with sensitive field redaction.
 * Replaces the 60-char truncation in the issuers table.
 * Reusable for targets in M35 — no IssuersPage-specific imports.
 */
import { isSensitiveKey } from '../../config/issuerTypes';

interface ConfigDetailModalProps {
  title: string;
  config: Record<string, unknown>;
  onClose: () => void;
}

export default function ConfigDetailModal({ title, config, onClose }: ConfigDetailModalProps) {
  const entries = Object.entries(config);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <div className="bg-surface border border-surface-border rounded-lg shadow-lg max-w-lg w-full mx-4">
        <div className="border-b border-surface-border px-6 py-4 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-ink">{title}</h2>
          <button onClick={onClose} className="text-ink-muted hover:text-ink transition-colors">
            ✕
          </button>
        </div>
        <div className="px-6 py-4 max-h-96 overflow-y-auto">
          {entries.length === 0 ? (
            <div className="text-sm text-ink-faint py-4 text-center">No configuration data</div>
          ) : (
            <div className="space-y-0">
              {entries.map(([key, val]) => {
                const redacted = isSensitiveKey(key);
                return (
                  <div key={key} className="flex justify-between py-2 border-b border-surface-border/50">
                    <span className="text-sm text-ink-muted">{key}</span>
                    <span className="text-sm text-ink font-mono text-right max-w-xs break-all">
                      {redacted ? '********' : String(val ?? '')}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
        <div className="border-t border-surface-border px-6 py-4 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 border border-surface-border rounded text-ink hover:bg-surface-hover transition-colors text-sm font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

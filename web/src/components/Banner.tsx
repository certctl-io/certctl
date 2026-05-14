// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Banner — the certctl-themed alert / message banner primitive. Phase 1
// closure for FE-M4 (no banner primitives; ~102 inline
// bg-(red|amber|yellow)-50 copy-paste sites across the codebase).
//
// Four severity variants:
//   - error   red surface, role="alert"          — operator action required
//   - warning amber surface, role="alert"        — risky-but-not-fatal
//   - success teal surface, role="status"        — confirmation of last action
//   - info    blue surface, role="status"        — neutral context
//
// role="alert" on error + warning surfaces these to screen readers
// immediately on render (aria-live=assertive equivalent). role="status"
// on success + info surfaces them politely (aria-live=polite).
//
// Optional `onDismiss` adds a close button — useful for transient
// banners. Persistent banners (e.g. "TLS bootstrap incomplete") omit
// it so the operator can't paper over the underlying state.

import type { ReactNode } from 'react';

export type BannerType = 'error' | 'warning' | 'success' | 'info';

export interface BannerProps {
  type: BannerType;
  title?: string;
  children: ReactNode;
  onDismiss?: () => void;
  className?: string;
}

const variantStyles: Record<BannerType, string> = {
  error:   'bg-red-50    border-red-200    text-red-800',
  warning: 'bg-amber-50  border-amber-200  text-amber-800',
  success: 'bg-emerald-50 border-emerald-200 text-emerald-800',
  info:    'bg-blue-50   border-blue-200   text-blue-800',
};

const variantTitleStyles: Record<BannerType, string> = {
  error:   'text-red-900',
  warning: 'text-amber-900',
  success: 'text-emerald-900',
  info:    'text-blue-900',
};

export default function Banner({
  type,
  title,
  children,
  onDismiss,
  className = '',
}: BannerProps) {
  // role="alert" announces immediately; role="status" announces politely.
  // Use alert for actionable / dangerous; status for confirmation /
  // background context.
  const role = type === 'error' || type === 'warning' ? 'alert' : 'status';

  return (
    <div
      role={role}
      className={`border-l-4 p-3 rounded ${variantStyles[type]} ${className}`}
    >
      <div className="flex items-start gap-3">
        <div className="flex-1 text-sm">
          {title && (
            <div className={`font-semibold mb-0.5 ${variantTitleStyles[type]}`}>
              {title}
            </div>
          )}
          <div>{children}</div>
        </div>
        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            aria-label="Dismiss"
            className={`text-xl leading-none opacity-60 hover:opacity-100 transition-opacity ${variantTitleStyles[type]}`}
          >
            ×
          </button>
        )}
      </div>
    </div>
  );
}

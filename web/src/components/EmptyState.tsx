// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// EmptyState — the certctl-themed empty-state primitive. Phase 1
// closure for UX-M3 (no <EmptyState> primitive; DataTable shows a bare
// 'No data found' string).
//
// Two render paths:
//   1) `<EmptyState title="..." description="..." />` — minimum
//      acceptable empty state. Title is required (the user must
//      understand what's missing); description + actions are optional.
//   2) `<EmptyState icon={<Icon />} title="..." description="..."
//        primaryAction={{ label, onClick }} secondaryAction={...} />` —
//      first-run CTA shape. Renders icon at the top, title in the
//      middle, two action buttons at the bottom. Use this on list pages
//      that an operator might hit on their first visit ("No certs yet —
//      [Issue first certificate] [Connect an issuer]").
//
// Composition with DataTable: DataTable accepts `emptyState?: ReactNode`
// (added alongside the existing `emptyMessage?: string` for backward
// compat) so list pages can pass either a string or a full <EmptyState />
// component.

import type { ReactNode } from 'react';

export interface EmptyStateAction {
  label: string;
  onClick: () => void;
}

export interface EmptyStateProps {
  /** Optional icon at the top. Pass any ReactNode (lucide / SVG / emoji). */
  icon?: ReactNode;
  /** Required headline. Keep short: "No certificates yet". */
  title: string;
  /** Optional sub-copy. One sentence explaining the empty condition. */
  description?: string;
  /** Optional primary CTA. Renders as .btn-primary. */
  primaryAction?: EmptyStateAction;
  /** Optional secondary CTA. Renders as .btn-outline alongside primary. */
  secondaryAction?: EmptyStateAction;
  /** Override default centering / padding when nested inside a card. */
  className?: string;
}

export default function EmptyState({
  icon,
  title,
  description,
  primaryAction,
  secondaryAction,
  className,
}: EmptyStateProps) {
  return (
    <div
      role="status"
      className={
        className ||
        'flex flex-col items-center justify-center text-center py-16 px-6'
      }
    >
      {icon && (
        <div className="mb-4 text-ink-faint" aria-hidden="true">
          {icon}
        </div>
      )}
      <h3 className="text-base font-semibold text-ink mb-1">{title}</h3>
      {description && (
        <p className="text-sm text-ink-muted max-w-md mb-4">{description}</p>
      )}
      {(primaryAction || secondaryAction) && (
        <div className="flex items-center gap-2 mt-2">
          {primaryAction && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={primaryAction.onClick}
            >
              {primaryAction.label}
            </button>
          )}
          {secondaryAction && (
            <button
              type="button"
              className="btn btn-outline"
              onClick={secondaryAction.onClick}
            >
              {secondaryAction.label}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Tooltip — Floating-UI-backed replacement for the ~103 native title=
// attributes. Phase 1 builds the primitive; migrating the 103 callsites
// is per-page rolling work that happens in subsequent PRs (per the
// audit prompt's explicit "DO NOT" on one-mega-PR sweeps).
//
// Why Floating-UI: native title= renders poorly on mobile + has no
// reliable show/hide timing, no visual styling, no positioning around
// the edges of the viewport, and (most importantly) zero a11y story
// beyond the browser's default tooltip — which screen readers
// inconsistently surface. Floating-UI gives us:
//   - middleware-driven positioning (auto-flip, shift, offset)
//   - hover + focus triggers (with `useFocus` + `useHover`)
//   - aria-describedby wiring via `useRole`
//   - dismissable via ESC
//
// Usage:
//   <Tooltip content="Some hint">
//     <button>Hover me</button>
//   </Tooltip>
//
// Children must be a single element capable of accepting a ref. For
// non-ref-forwardable children (e.g. plain text), wrap in a span.

import { useState, cloneElement, isValidElement } from 'react';
import type { ReactElement, ReactNode } from 'react';
import {
  useFloating,
  useHover,
  useFocus,
  useDismiss,
  useRole,
  useInteractions,
  flip,
  shift,
  offset,
  autoUpdate,
  FloatingPortal,
} from '@floating-ui/react';

export interface TooltipProps {
  /** Tooltip body — usually a short string; ReactNode is allowed for icons. */
  content: ReactNode;
  /** Single child element that receives the ref + ARIA wiring. */
  children: ReactElement;
  /** Preferred placement; Floating-UI will auto-flip if viewport-clamped. */
  placement?: 'top' | 'right' | 'bottom' | 'left';
  /** Pixel offset between the trigger and the tooltip. Default 6. */
  offsetPx?: number;
}

export default function Tooltip({
  content,
  children,
  placement = 'top',
  offsetPx = 6,
}: TooltipProps) {
  const [open, setOpen] = useState(false);

  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    placement,
    middleware: [offset(offsetPx), flip(), shift({ padding: 8 })],
    whileElementsMounted: autoUpdate,
  });

  const hover = useHover(context, { move: false, delay: { open: 200, close: 0 } });
  const focus = useFocus(context);
  const dismiss = useDismiss(context);
  const role = useRole(context, { role: 'tooltip' });

  const { getReferenceProps, getFloatingProps } = useInteractions([
    hover,
    focus,
    dismiss,
    role,
  ]);

  if (!isValidElement(children)) {
    // Defensive: render the child verbatim; Tooltip wiring is skipped.
    // Console-warn so the misuse is visible during dev.
    if (typeof console !== 'undefined') {
      console.warn(
        '<Tooltip> requires a single React element child; got:',
        children,
      );
    }
    return <>{children}</>;
  }

  // Merge the ref + interaction props onto the child. cloneElement keeps
  // the original child's type + own props; we layer ours on top.
  const triggerProps = getReferenceProps();
  const child = cloneElement(
    children as ReactElement<Record<string, unknown>>,
    {
      ref: refs.setReference,
      ...triggerProps,
    },
  );

  return (
    <>
      {child}
      {open && content && (
        <FloatingPortal>
          <div
            ref={refs.setFloating}
            style={floatingStyles}
            {...getFloatingProps()}
            className="z-50 max-w-xs rounded bg-ink/95 text-white text-xs px-2 py-1 shadow-lg pointer-events-none"
          >
            {content}
          </div>
        </FloatingPortal>
      )}
    </>
  );
}

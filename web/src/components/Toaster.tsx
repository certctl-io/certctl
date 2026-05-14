// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Toaster — the certctl-themed Sonner wrapper. Phase 1 closure for
// UX-H3 (no toast / snackbar system) per the frontend-design-audit.
//
// Mount once near the top of <main.tsx>'s React tree (next to
// QueryClientProvider). Inside any component, import { toast } from
// "sonner" and call toast.success(…) / toast.error(…) / toast.info(…) /
// toast.warning(…). Sonner handles the singleton queue, focus + ARIA
// (role="status" / role="alert"), enter/exit animation, swipe-to-
// dismiss, and respects prefers-reduced-motion automatically.
//
// We surface a thin wrapper rather than the bare <Toaster /> so the
// default position + visual config lives in one place. Pages must NOT
// mount their own Toaster instances — Sonner asserts at runtime if
// multiple are mounted, but the failure mode is "toasts duplicate or
// disappear silently" which is hard to debug. Single import discipline.
//
// Visual position: top-right. Operators are paginated-table-heavy;
// top-right keeps the toast away from row-action click targets at the
// bottom of the list. richColors gives us the per-severity background
// fills (success teal / error red / warning amber / info blue) that
// match the existing .badge-* color tier.

import { Toaster as SonnerToaster } from 'sonner';

export default function Toaster() {
  return (
    <SonnerToaster
      position="top-right"
      richColors
      closeButton
      // 4s default for non-action toasts; persistent for error toasts
      // with action (set per-call via toast.error(msg, { duration: ... })).
      duration={4000}
      // visibleToasts: cap stack so a runaway error loop doesn't drown
      // the screen. 5 is the Sonner default; pinning it explicitly so
      // the choice is documented.
      visibleToasts={5}
    />
  );
}

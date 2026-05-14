// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// CommandPaletteHost — Phase 3 closure: thin wrapper around
// CommandPalette that owns the open/close state + the global
// keyboard listener (meta+k on mac, ctrl+k everywhere else).
//
// Lives at the React tree root (mounted alongside Toaster in
// main.tsx) so the keydown handler is registered once + survives
// page navigations. The handler is intentionally scoped to the
// component lifecycle so HMR + React StrictMode double-mount don't
// leave orphaned listeners.

import { useEffect, useState, lazy, Suspense } from 'react';

// Lazy-load the palette so cmdk's bundle (~25 KB) doesn't land on
// the initial page load — only fetched once the operator hits cmd+k.
const CommandPalette = lazy(() => import('./CommandPalette'));

export default function CommandPaletteHost() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // metaKey on macOS, ctrlKey on Windows / Linux.
      const isCmdK = e.key === 'k' && (e.metaKey || e.ctrlKey);
      if (isCmdK) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  // Only mount the palette tree when first-needed — avoids fetching
  // cmdk's bundle on every page load.
  if (!open) return null;
  return (
    <Suspense fallback={null}>
      <CommandPalette open={open} onOpenChange={setOpen} />
    </Suspense>
  );
}

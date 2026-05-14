// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// ModalDialog — Phase 5 closure for FE-H3 (3 inline-managed modal
// pages — SCEPAdminPage, AgentsPage, ESTAdminPage — set
// role="dialog" + aria-modal="true" + aria-labelledby but no focus
// trap, no ESC-to-close, no backdrop-click-to-close).
//
// Built on Headless UI's <Dialog>, identical pattern to ConfirmDialog
// (Phase 1) but accepts arbitrary <ModalDialog.Body> content rather
// than the constrained confirm/cancel button pair ConfirmDialog
// provides. Use ConfirmDialog for "click YES to do destructive thing";
// use ModalDialog for "modal that contains a form / multi-action
// content / a status display".
//
// What Headless UI gives us for free (same as ConfirmDialog):
//   • automatic focus trap (Tab/Shift-Tab stays inside the dialog)
//   • automatic ESC-to-close → onClose() callback
//   • automatic backdrop-click-to-close → onClose() callback
//   • role="dialog" + aria-modal="true" on the panel
//   • aria-labelledby on the title node
//   • <Transition> respects prefers-reduced-motion via the global
//     @media block in src/index.css
//
// FE-H3 closure scope: the 3 inline-managed modal sites all get
// migrated to this primitive in the same commit. ConfirmDialog stays
// as-is for confirm-only flows it already serves.

import { Fragment } from 'react';
import type { ReactNode } from 'react';
import { Dialog, Transition } from '@headlessui/react';

export interface ModalDialogProps {
  /** Controls visibility. Parent owns the boolean. */
  open: boolean;
  /** Title shown at the top — also acts as aria-labelledby target. */
  title: string;
  /** Fires on ESC, backdrop click, or external close trigger. */
  onClose: () => void;
  /**
   * Dialog body — render the form, status, or multi-action content here.
   * The body is wrapped in the styled panel; consumers don't need to
   * wrap their content in another <div>.
   */
  children: ReactNode;
  /**
   * Footer slot for action buttons. Optional — some modals (e.g. error
   * displays) only show a "Close" affordance which can live inside
   * children. When provided, footer is separated by a top border.
   */
  footer?: ReactNode;
  /** Maximum width — defaults to `max-w-md` (matches ConfirmDialog). */
  maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | '2xl';
}

const maxWidthMap = {
  sm:  'max-w-sm',
  md:  'max-w-md',
  lg:  'max-w-lg',
  xl:  'max-w-xl',
  '2xl': 'max-w-2xl',
} as const;

export default function ModalDialog({
  open,
  title,
  onClose,
  children,
  footer,
  maxWidth = 'md',
}: ModalDialogProps) {
  return (
    <Transition show={open} as={Fragment}>
      <Dialog onClose={onClose} className="relative z-50">
        {/* Backdrop. Headless UI wires backdrop-click → onClose. */}
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-200"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-150"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/40" aria-hidden="true" />
        </Transition.Child>

        {/* Panel container. */}
        <div className="fixed inset-0 flex items-center justify-center p-4">
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-200"
            enterFrom="opacity-0 scale-95"
            enterTo="opacity-100 scale-100"
            leave="ease-in duration-150"
            leaveFrom="opacity-100 scale-100"
            leaveTo="opacity-0 scale-95"
          >
            <Dialog.Panel
              className={`bg-surface w-full ${maxWidthMap[maxWidth]} rounded-lg shadow-xl border border-surface-border`}
            >
              <div className="p-6">
                <Dialog.Title className="text-base font-semibold text-ink mb-3">
                  {title}
                </Dialog.Title>
                <div className="text-sm text-ink">{children}</div>
              </div>
              {footer && (
                <div className="border-t border-surface-border px-6 py-4 flex justify-end gap-2">
                  {footer}
                </div>
              )}
            </Dialog.Panel>
          </Transition.Child>
        </div>
      </Dialog>
    </Transition>
  );
}

// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// ConfirmDialog — the certctl-themed replacement for window.confirm().
// Phase 1 closure for UX-H2 (destructive actions use window.confirm).
//
// Built on Headless UI's <Dialog>, which gives us:
//   - automatic focus trap (Tab/Shift-Tab stays inside the modal)
//   - automatic ESC-to-close (we wire onCancel to it)
//   - automatic backdrop-click-to-close (we wire onCancel to it)
//   - role="dialog" + aria-modal="true" on the panel
//   - aria-labelledby on the title node, aria-describedby on the body
//   - <Transition> handles enter/exit; respects prefers-reduced-motion
//     transparently via the @media block in src/index.css.
//
// Optional `typedConfirmation` raises the friction for the most
// irreversible actions. Passing `typedConfirmation: "delete"` requires
// the operator to literally type the string "delete" into a field
// before the confirm button enables. Reserve it for the worst-case
// actions: archive-this-certificate, delete-root-CA, etc.
//
// Visual posture: destructive variant uses red surface tints + a red
// confirm button matching .btn-danger. Non-destructive uses the
// default brand-teal confirm button.

import { Fragment, useState, useEffect, useRef } from 'react';
import { Dialog, Transition } from '@headlessui/react';

export interface ConfirmDialogProps {
  /** Controls visibility. Parent owns the boolean. */
  open: boolean;
  /** Title shown at the top of the dialog. Concise: "Archive certificate". */
  title: string;
  /** Body copy. Plain text recommended; spell out consequences. */
  message: string;
  /** Label for the confirm button. Defaults to "Confirm". */
  confirmLabel?: string;
  /** Label for the cancel button. Defaults to "Cancel". */
  cancelLabel?: string;
  /** When true, confirm button uses .btn-danger styling. */
  destructive?: boolean;
  /**
   * When set, the operator must type this exact string before the
   * confirm button enables. Use for the most irreversible actions
   * (archive certificate, delete CA, etc.).
   */
  typedConfirmation?: string;
  /** Fires when the confirm button is clicked. Parent closes the dialog. */
  onConfirm: () => void;
  /** Fires on ESC, backdrop click, or cancel button. */
  onCancel: () => void;
}

export default function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  typedConfirmation,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const [typedValue, setTypedValue] = useState('');
  const cancelButtonRef = useRef<HTMLButtonElement>(null);

  // Reset typed-confirmation state every time the dialog closes/reopens.
  // Without this, a previous successful confirmation leaves the field
  // pre-filled on the next confirmation prompt — that's a footgun.
  useEffect(() => {
    if (open) setTypedValue('');
  }, [open]);

  const typedOK = !typedConfirmation || typedValue === typedConfirmation;
  const confirmDisabled = !typedOK;

  const confirmClass = destructive
    ? 'btn btn-danger'
    : 'btn btn-primary';

  return (
    <Transition show={open} as={Fragment}>
      <Dialog
        as="div"
        className="relative z-50"
        onClose={onCancel}
        initialFocus={cancelButtonRef}
      >
        {/* Backdrop */}
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-150"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-100"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/40" aria-hidden="true" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-150"
              enterFrom="opacity-0 translate-y-2 scale-95"
              enterTo="opacity-100 translate-y-0 scale-100"
              leave="ease-in duration-100"
              leaveFrom="opacity-100 translate-y-0 scale-100"
              leaveTo="opacity-0 translate-y-2 scale-95"
            >
              <Dialog.Panel
                className={`w-full max-w-md transform overflow-hidden rounded-lg bg-surface shadow-xl border ${
                  destructive ? 'border-red-200' : 'border-surface-border'
                } p-6`}
              >
                <Dialog.Title
                  as="h3"
                  className="text-lg font-semibold text-ink"
                >
                  {title}
                </Dialog.Title>
                <Dialog.Description
                  as="p"
                  className="mt-2 text-sm text-ink-muted"
                >
                  {message}
                </Dialog.Description>

                {typedConfirmation && (
                  <div className="mt-4">
                    <label
                      htmlFor="confirm-typed-input"
                      className="block text-xs font-medium text-ink-muted mb-1"
                    >
                      Type{' '}
                      <code className="text-ink font-mono">
                        {typedConfirmation}
                      </code>{' '}
                      to enable confirmation:
                    </label>
                    <input
                      id="confirm-typed-input"
                      type="text"
                      autoComplete="off"
                      autoFocus
                      value={typedValue}
                      onChange={(e) => setTypedValue(e.target.value)}
                      className="input w-full"
                    />
                  </div>
                )}

                <div className="mt-6 flex justify-end gap-2">
                  <button
                    ref={cancelButtonRef}
                    type="button"
                    className="btn btn-outline"
                    onClick={onCancel}
                  >
                    {cancelLabel}
                  </button>
                  <button
                    type="button"
                    className={confirmClass}
                    onClick={onConfirm}
                    disabled={confirmDisabled}
                  >
                    {confirmLabel}
                  </button>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  );
}

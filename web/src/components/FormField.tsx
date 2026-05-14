// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// FormField — Phase 5 closure for UX-H4 + the foundation of FE-M1.
//
// Pre-Phase-5 state: 139 <label> elements in production tsx; 6 with
// htmlFor; 0 inputs with id. WCAG 1.3.1 (info-and-relationships) fails
// on ~99% of form fields — screen readers can't programmatically pair
// a label with its input, so "Email" reads as a floating string rather
// than as the accessible name of the adjacent input.
//
// FormField fixes this by generating a stable id with React 18's
// useId() and threading it to BOTH the <label htmlFor=...> AND the
// child input's id prop via cloneElement. Consumers write:
//
//   <FormField label="Email" required>
//     <input type="email" value={email} onChange={…} />
//   </FormField>
//
// — no manual id wiring, no risk of id-mismatch drift, no chance a
// developer copies the JSX and forgets to update one of the two
// strings. The label-↔-input binding is correct by construction.
//
// Composition with react-hook-form is straight-forward — RHF's
// register('field') returns onChange/onBlur/ref/name which spread onto
// the input alongside FormField's auto-id. The Zod-resolver path picks
// up errors and FormField surfaces them via the `error` prop slot.

import { Children, cloneElement, isValidElement, useId } from 'react';
import type { ReactElement, ReactNode } from 'react';

interface FormFieldProps {
  /** Visible label text. Required for a11y — never render an unbound input. */
  label: string;
  /** Render `*` next to the label when true (display-only; validation lives in Zod). */
  required?: boolean;
  /** Optional helper / description text below the input. */
  description?: string;
  /** Optional error message — when set, surfaces below the input + flags aria-invalid. */
  error?: string;
  /** Optional class override for the wrapping div. */
  className?: string;
  /**
   * Exactly one input-shaped child (<input>, <select>, <textarea>, or any
   * forwardRef'd component that accepts `id` + `aria-describedby` +
   * `aria-invalid` as props). FormField clones it and injects the
   * auto-generated id so the label-↔-input pairing is correct by
   * construction.
   */
  children: ReactNode;
}

export default function FormField({
  label,
  required,
  description,
  error,
  className,
  children,
}: FormFieldProps) {
  // useId() returns a stable id that's unique per render-tree-position,
  // safe under StrictMode, and SSR-friendly. Two siblings get different
  // ids automatically.
  const reactId = useId();
  const inputId = `field-${reactId}`;
  const descId = description ? `desc-${reactId}` : undefined;
  const errorId = error ? `err-${reactId}` : undefined;

  // Build the aria-describedby chain from optional description + error.
  // Browsers concatenate space-separated ids, so screen readers announce
  // "Email, [description], [error]".
  const describedBy = [descId, errorId].filter(Boolean).join(' ') || undefined;

  const onlyChild = Children.only(children);
  if (!isValidElement(onlyChild)) {
    // Surface a clear error in dev rather than render a broken control.
    throw new Error('FormField expects exactly one valid React element child');
  }

  // cloneElement preserves the child's existing props (including any
  // RHF `register(...)` spread) and overlays the FormField-managed
  // a11y props on top. The child's `id` / `aria-*` are always set
  // here, but `name`/`value`/`onChange` from the child are preserved.
  const childWithA11y = cloneElement(
    onlyChild as ReactElement<Record<string, unknown>>,
    {
      id: inputId,
      'aria-describedby': describedBy,
      'aria-invalid': error ? true : undefined,
      'aria-required': required ? true : undefined,
    },
  );

  return (
    <div className={className ?? 'mb-4'}>
      <label
        htmlFor={inputId}
        className="block text-sm font-medium text-ink mb-1.5"
      >
        {label}
        {required && (
          <span className="text-red-600 ml-0.5" aria-hidden="true">*</span>
        )}
      </label>
      {childWithA11y}
      {description && (
        <p id={descId} className="mt-1 text-xs text-ink-muted">
          {description}
        </p>
      )}
      {error && (
        <p id={errorId} role="alert" className="mt-1 text-xs text-red-700">
          {error}
        </p>
      )}
    </div>
  );
}

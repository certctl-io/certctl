// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Combobox — Headless UI-backed typeahead select primitive. Phase 1
// closure for UX-M4 (~53 native HTML <select> elements with no
// typeahead surface). Migrating callsites is per-page rolling work
// in subsequent PRs; Phase 1 builds the primitive.
//
// Compared with native <select>:
//   - typeahead filter narrows options as the operator types
//   - keyboard nav (Up/Down/Enter/Esc) handled by Headless UI
//   - aria-expanded / aria-activedescendant / aria-labelledby wired
//     for free
//   - styled to match the certctl .input + .card token palette
//
// Generic on the option value type T (string IDs are typical; arbitrary
// objects work too — supply a `getKey` + `getLabel`).

import { useState, useMemo } from 'react';
import { Combobox as HeadlessCombobox } from '@headlessui/react';

export interface ComboboxProps<T> {
  /** The currently-selected option, or null if none. */
  value: T | null;
  /** Fires when the operator picks an option. */
  onChange: (next: T | null) => void;
  /** Full options list — Combobox filters internally on typed query. */
  options: T[];
  /** Stable string key per option (used for React `key` + filter equality). */
  getKey: (option: T) => string;
  /** Human-readable label rendered in the input + dropdown row. */
  getLabel: (option: T) => string;
  /** Optional placeholder when no value is selected. */
  placeholder?: string;
  /** Optional `id` on the input element (label wiring). */
  inputId?: string;
  /** Disabled state. */
  disabled?: boolean;
  /** Extra className on the outer wrapper. */
  className?: string;
}

export default function Combobox<T>({
  value,
  onChange,
  options,
  getKey,
  getLabel,
  placeholder,
  inputId,
  disabled,
  className = '',
}: ComboboxProps<T>) {
  const [query, setQuery] = useState('');

  // Filter is local + case-insensitive substring against the label.
  // For >1000-option lists this should move to server-side; not Phase
  // 1's problem.
  const filtered = useMemo(() => {
    if (!query) return options;
    const needle = query.toLowerCase();
    return options.filter((o) => getLabel(o).toLowerCase().includes(needle));
  }, [options, query, getLabel]);

  return (
    <HeadlessCombobox
      value={value}
      onChange={onChange}
      disabled={disabled}
    >
      <div className={`relative ${className}`}>
        <HeadlessCombobox.Input
          id={inputId}
          className="input w-full"
          placeholder={placeholder}
          displayValue={(o: T | null) => (o ? getLabel(o) : '')}
          onChange={(e) => setQuery(e.target.value)}
        />
        <HeadlessCombobox.Options
          className="absolute z-30 mt-1 max-h-60 w-full overflow-auto rounded border border-surface-border bg-surface shadow-lg focus:outline-none"
        >
          {filtered.length === 0 && query !== '' && (
            <div className="px-3 py-2 text-sm text-ink-faint">
              No matches.
            </div>
          )}
          {filtered.map((option) => (
            <HeadlessCombobox.Option
              key={getKey(option)}
              value={option}
              className={({ active, selected }) =>
                `cursor-pointer px-3 py-2 text-sm ${
                  active ? 'bg-brand-50 text-brand-700' : 'text-ink'
                } ${selected ? 'font-semibold' : ''}`
              }
            >
              {getLabel(option)}
            </HeadlessCombobox.Option>
          ))}
        </HeadlessCombobox.Options>
      </div>
    </HeadlessCombobox>
  );
}

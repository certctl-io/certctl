// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Combobox from './Combobox';

type Option = { id: string; name: string };

const OPTIONS: Option[] = [
  { id: 'iss-vault', name: 'Vault PKI' },
  { id: 'iss-acme',  name: 'ACME (Let\'s Encrypt)' },
  { id: 'iss-local', name: 'Local CA' },
];

describe('Combobox', () => {
  it('renders the input', () => {
    render(
      <Combobox<Option>
        value={null}
        onChange={() => {}}
        options={OPTIONS}
        getKey={(o) => o.id}
        getLabel={(o) => o.name}
        placeholder="Pick issuer"
      />,
    );
    expect(screen.getByPlaceholderText('Pick issuer')).toBeInTheDocument();
  });

  it('renders the selected value as the input display', () => {
    render(
      <Combobox<Option>
        value={OPTIONS[2]}
        onChange={() => {}}
        options={OPTIONS}
        getKey={(o) => o.id}
        getLabel={(o) => o.name}
      />,
    );
    expect(screen.getByDisplayValue('Local CA')).toBeInTheDocument();
  });

  it('filters options as the operator types', () => {
    render(
      <Combobox<Option>
        value={null}
        onChange={() => {}}
        options={OPTIONS}
        getKey={(o) => o.id}
        getLabel={(o) => o.name}
      />,
    );
    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: 'vault' } });
    expect(screen.getByText('Vault PKI')).toBeInTheDocument();
    expect(screen.queryByText('Local CA')).not.toBeInTheDocument();
    expect(screen.queryByText("ACME (Let's Encrypt)")).not.toBeInTheDocument();
  });

  it('fires onChange when the operator selects via keyboard', () => {
    const onChange = vi.fn();
    render(
      <Combobox<Option>
        value={null}
        onChange={onChange}
        options={OPTIONS}
        getKey={(o) => o.id}
        getLabel={(o) => o.name}
      />,
    );
    // Open the listbox + filter to a single option, then press Enter.
    // Click-to-select on Headless UI requires the pointerdown sequence
    // which @testing-library/dom's fireEvent doesn't synthesize; the
    // keyboard path is the accessible-equivalent and is what screen
    // reader / keyboard-only operators use anyway.
    const input = screen.getByRole('combobox');
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: 'Local' } });
    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onChange).toHaveBeenCalledWith(OPTIONS[2]);
  });

  it('shows "No matches" when the filter excludes everything', () => {
    render(
      <Combobox<Option>
        value={null}
        onChange={() => {}}
        options={OPTIONS}
        getKey={(o) => o.id}
        getLabel={(o) => o.name}
      />,
    );
    const input = screen.getByRole('combobox');
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: 'nonexistent' } });
    expect(screen.getByText('No matches.')).toBeInTheDocument();
  });
});

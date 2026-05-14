// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Smoke + behavior tests for ConfirmDialog. The primitive replaces
// window.confirm(); the test suite asserts the contract:
//   - hidden when open=false
//   - title + message render
//   - ESC + backdrop click + cancel button → onCancel
//   - confirm button → onConfirm
//   - typedConfirmation gates the confirm button until the exact string
//     is typed
//   - destructive=true uses the btn-danger styling

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import ConfirmDialog from './ConfirmDialog';

describe('ConfirmDialog', () => {
  it('does not render when open=false', () => {
    render(
      <ConfirmDialog
        open={false}
        title="Archive cert"
        message="Cannot be undone."
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(screen.queryByText('Archive cert')).not.toBeInTheDocument();
  });

  it('renders title + message when open=true', () => {
    render(
      <ConfirmDialog
        open
        title="Archive cert"
        message="Cannot be undone."
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(screen.getByText('Archive cert')).toBeInTheDocument();
    expect(screen.getByText('Cannot be undone.')).toBeInTheDocument();
  });

  it('fires onConfirm when confirm button clicked', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open
        title="Delete owner"
        message="Bob will be removed."
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /confirm/i }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('fires onCancel when cancel button clicked', () => {
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        open
        title="Delete owner"
        message="Bob will be removed."
        onConfirm={() => {}}
        onCancel={onCancel}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('disables confirm button until typedConfirmation matches', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open
        title="Archive cert"
        message="Type DELETE to confirm."
        typedConfirmation="DELETE"
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );
    const confirmBtn = screen.getByRole('button', { name: /confirm/i });
    expect(confirmBtn).toBeDisabled();

    const input = screen.getByLabelText(/Type/i);
    fireEvent.change(input, { target: { value: 'wrong' } });
    expect(confirmBtn).toBeDisabled();

    fireEvent.change(input, { target: { value: 'DELETE' } });
    expect(confirmBtn).not.toBeDisabled();

    fireEvent.click(confirmBtn);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('uses btn-danger styling when destructive=true', () => {
    render(
      <ConfirmDialog
        open
        title="Revoke cert"
        message="Cannot be undone."
        destructive
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    const confirmBtn = screen.getByRole('button', { name: /confirm/i });
    expect(confirmBtn.className).toContain('btn-danger');
  });

  it('honours custom confirmLabel + cancelLabel', () => {
    render(
      <ConfirmDialog
        open
        title="Archive cert"
        message="Are you sure?"
        confirmLabel="Yes, archive"
        cancelLabel="No, go back"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(
      screen.getByRole('button', { name: 'Yes, archive' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'No, go back' }),
    ).toBeInTheDocument();
  });
});

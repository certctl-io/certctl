// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Banner from './Banner';

describe('Banner', () => {
  it('renders the children', () => {
    render(<Banner type="info">Operator note</Banner>);
    expect(screen.getByText('Operator note')).toBeInTheDocument();
  });

  it('renders the optional title', () => {
    render(
      <Banner type="error" title="Save failed">
        Permission denied.
      </Banner>,
    );
    expect(screen.getByText('Save failed')).toBeInTheDocument();
    expect(screen.getByText('Permission denied.')).toBeInTheDocument();
  });

  it('uses role="alert" for error variant', () => {
    render(<Banner type="error">Permission denied.</Banner>);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('uses role="alert" for warning variant', () => {
    render(<Banner type="warning">Stale data.</Banner>);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('uses role="status" for success variant', () => {
    render(<Banner type="success">Saved.</Banner>);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('uses role="status" for info variant', () => {
    render(<Banner type="info">Heads up.</Banner>);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('applies variant-specific bg + border classes', () => {
    const { container } = render(<Banner type="error">err</Banner>);
    const root = container.firstChild as HTMLElement;
    expect(root.className).toContain('bg-red-50');
    expect(root.className).toContain('border-red-200');
  });

  it('hides dismiss button when onDismiss not supplied', () => {
    render(<Banner type="info">No close affordance.</Banner>);
    expect(screen.queryByRole('button', { name: /dismiss/i })).toBeNull();
  });

  it('renders dismiss button + fires onDismiss when supplied', () => {
    const onDismiss = vi.fn();
    render(
      <Banner type="info" onDismiss={onDismiss}>
        Closable.
      </Banner>,
    );
    fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});

// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import EmptyState from './EmptyState';

describe('EmptyState', () => {
  it('renders the title', () => {
    render(<EmptyState title="No certificates yet" />);
    expect(screen.getByText('No certificates yet')).toBeInTheDocument();
  });

  it('renders description when provided', () => {
    render(
      <EmptyState
        title="No certificates yet"
        description="Issue your first certificate to get started."
      />,
    );
    expect(
      screen.getByText('Issue your first certificate to get started.'),
    ).toBeInTheDocument();
  });

  it('renders icon slot when provided', () => {
    render(
      <EmptyState
        icon={<span data-testid="empty-icon">📜</span>}
        title="No certificates"
      />,
    );
    expect(screen.getByTestId('empty-icon')).toBeInTheDocument();
  });

  it('renders primaryAction button and fires its onClick', () => {
    const onClick = vi.fn();
    render(
      <EmptyState
        title="No certificates"
        primaryAction={{ label: 'Issue certificate', onClick }}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Issue certificate' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('renders secondaryAction button and fires its onClick', () => {
    const onClick = vi.fn();
    render(
      <EmptyState
        title="No certificates"
        secondaryAction={{ label: 'Read docs', onClick }}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Read docs' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('renders both actions side-by-side', () => {
    render(
      <EmptyState
        title="No certificates"
        primaryAction={{ label: 'Issue', onClick: () => {} }}
        secondaryAction={{ label: 'Connect issuer', onClick: () => {} }}
      />,
    );
    expect(screen.getByRole('button', { name: 'Issue' })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Connect issuer' }),
    ).toBeInTheDocument();
  });

  it('exposes role="status" for screen readers', () => {
    render(<EmptyState title="No data" />);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});

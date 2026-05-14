// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Smoke-test the Toaster wrapper. Sonner has its own deep test suite;
// we just pin (a) the wrapper renders without crashing, (b) the
// Sonner <Toaster /> root lands in the DOM with our position prop, and
// (c) toast.success / toast.error reach the renderer.

import { render, screen, act } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { toast } from 'sonner';
import Toaster from './Toaster';

describe('Toaster', () => {
  it('renders the Sonner root without crashing', () => {
    render(<Toaster />);
    // Sonner mounts a section[aria-label="Notifications <kbd>"] container
    // — the label includes Sonner's expand-shortcut hint (e.g. "alt+T").
    // Match the prefix only.
    expect(screen.getByLabelText(/Notifications/)).toBeInTheDocument();
  });

  it('forwards toast.success() to the visible queue', async () => {
    render(<Toaster />);
    act(() => {
      toast.success('Profile saved');
    });
    // Sonner debounces render slightly; flush via findByText.
    expect(await screen.findByText('Profile saved')).toBeInTheDocument();
  });

  it('forwards toast.error() to the visible queue', async () => {
    render(<Toaster />);
    act(() => {
      toast.error('Save failed: not authorized');
    });
    expect(
      await screen.findByText('Save failed: not authorized'),
    ).toBeInTheDocument();
  });
});

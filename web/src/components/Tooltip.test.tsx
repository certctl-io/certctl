// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Tooltip smoke + interaction tests. Floating-UI's positioning math
// requires a real browser layout engine; we just assert the wiring:
//   - children render at rest (no tooltip)
//   - focus reveals the tooltip body in the portal
//   - escape dismisses

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import Tooltip from './Tooltip';

describe('Tooltip', () => {
  it('renders the trigger at rest with no tooltip visible', () => {
    render(
      <Tooltip content="Hint">
        <button>Hover me</button>
      </Tooltip>,
    );
    expect(screen.getByRole('button', { name: 'Hover me' })).toBeInTheDocument();
    expect(screen.queryByText('Hint')).not.toBeInTheDocument();
  });

  it('reveals tooltip body on focus', () => {
    render(
      <Tooltip content="Hint visible">
        <button>Focusable trigger</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button', { name: 'Focusable trigger' });
    fireEvent.focus(trigger);
    // FloatingPortal renders into document.body; queryable.
    expect(screen.getByText('Hint visible')).toBeInTheDocument();
  });

  it('dismisses on Escape after focus-open', () => {
    render(
      <Tooltip content="Press escape">
        <button>Focusable</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole('button', { name: 'Focusable' });
    fireEvent.focus(trigger);
    expect(screen.getByText('Press escape')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByText('Press escape')).not.toBeInTheDocument();
  });
});

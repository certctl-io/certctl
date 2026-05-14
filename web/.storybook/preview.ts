// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 8 TEST-H3 closure — Storybook preview config.
//
// Loads the global stylesheet (Tailwind + the certctl tokens + the
// self-hosted Inter/JetBrains fonts from Phase 0) so every story
// renders against the same visual system as production. Without
// this import, stories render unstyled and the a11y addon's contrast
// signal becomes noise.

import type { Preview } from '@storybook/react';
import '../src/index.css';

const preview: Preview = {
  parameters: {
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    a11y: {
      // Phase 8: addon-a11y runs axe-core on every story by default.
      // The 'todo' setting reports violations as warnings (not test
      // failures) until each component's stories pass cleanly. Flip
      // to 'error' once the backlog clears.
      test: 'todo',
    },
  },
};

export default preview;

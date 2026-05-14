// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 8 TEST-H3 closure — Storybook 8 configuration with the Vite
// builder. Reuses the existing Vite config from web/vite.config.ts
// (including the Phase 4 manualChunks, the Phase 0 fontsource imports,
// the test-block exclusions) so stories render against the same
// build pipeline production uses.
//
// Addon scope:
//   • @storybook/addon-a11y — runs axe-core on every story render +
//     surfaces violations in the Storybook UI. Phase 5 shipped axe
//     coverage for primitives via Vitest (web/src/test/a11y.test.tsx);
//     this addon extends that signal to every component variant
//     showcased here, per-render. Catches contrast / label-binding /
//     focus regressions that the per-component Vitest suite misses.
//
// Story discovery: `**/*.stories.{ts,tsx}` under src/ — stories live
// next to the component they document.

import type { StorybookConfig } from '@storybook/react-vite';

const config: StorybookConfig = {
  stories: ['../src/**/*.stories.@(ts|tsx)'],
  addons: [
    '@storybook/addon-a11y',
  ],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  docs: {
    autodocs: 'tag',
  },
};

export default config;

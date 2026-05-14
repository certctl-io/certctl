// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 8 TEST-H3 closure — Storybook configuration scaffold.
//
// DEPS NOT INSTALLED IN PACKAGE.JSON. The first attempt added
// `@storybook/react-vite ^8.6.0` + `@storybook/addon-a11y ^8.6.0`
// + `storybook ^8.6.0` to package.json, but Storybook 8's peerDeps
// cap Vite at v6 — the certctl project ships Vite 8 (Phase 4
// manualChunks rewrite). CI fail confirmed the peer-conflict via
// `npm ci`. Hotfix #9 removed the deps to unblock CI.
//
// To install:
//   cd web && npm install --save-dev storybook@^9.0.0 \
//     @storybook/react-vite@^9.0.0 @storybook/addon-a11y@^9.0.0
//   # Storybook 9 supports Vite 7+8 — verified against storybook.js.org
//   # docs before installing.
//
// Once installed, this main.ts + preview.ts work as-is. The 8
// committed *.stories.tsx files import @storybook/react types and
// will typecheck cleanly. tsconfig.json excludes them today so
// `npm run build` stays green in the meantime.
//
// Reuses the existing Vite config from web/vite.config.ts
// (including the Phase 4 manualChunks, the Phase 0 fontsource
// imports, the test-block exclusions) so stories render against
// the same build pipeline production uses.
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

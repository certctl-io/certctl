// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 8 TEST-H3 closure — Storybook configuration. Fully wired
// 2026-05-14 via Storybook 10.
//
// Version-selection history (recorded so the next operator who
// upgrades Vite doesn't re-walk the same wall):
//   • Phase 8 first attempt: Storybook 8.6 — peer-capped at Vite 6,
//     project shipped Vite 8 (Phase 4 manualChunks rewrite). CI's
//     `npm ci` failed ERESOLVE; Hotfix #9 removed the deps.
//   • This file's earlier header speculated "Storybook 9 supports
//     Vite 7+8" — that was wrong. Verified at install time
//     2026-05-14: Storybook 9.1.20's peer range is Vite 5/6/7,
//     ERESOLVE'd again.
//   • Storybook 10.4.0 is the first version with explicit Vite 8
//     in the peer range (^5.0.0 || ^6.0.0 || ^7.0.0 || ^8.0.0).
//     Installed cleanly. All 8 *.stories.tsx files typecheck +
//     `storybook build` succeeds (~3s, 17 chunks emitted).
//
// tsconfig.json no longer excludes *.stories.tsx — Storybook 10's
// @storybook/react types are correct and the existing story files
// validate against them. `npm run build` is unchanged (Vite still
// only emits the production bundle; stories live in a separate
// `npm run storybook:build` script).
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

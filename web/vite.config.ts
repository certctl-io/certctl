import { defineConfig } from 'vite'
import { configDefaults } from 'vitest/config'
import react from '@vitejs/plugin-react'

// C-1 closure (cat-u-vite_dev_proxy_plaintext_drift): pre-C-1 the dev
// proxy targeted http://localhost:8443 against an HTTPS-only backend
// (HTTPS-only since v2.0.47 — see docs/tls.md). Every dev-server API
// call 502'd. Post-C-1 the proxy targets https:// with secure:false
// because the dev cert is self-signed by deploy/test bootstrap and
// changes per-checkout — production stops validation at the reverse
// proxy or load balancer, not the Vite dev server.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api':    { target: 'https://localhost:8443', secure: false, changeOrigin: true },
      '/health': { target: 'https://localhost:8443', secure: false, changeOrigin: true },
    }
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // Phase 4 closure (FE-M5 + SCALE-H1): vendor manualChunks. Pre-Phase-4
    // the single index-*.js chunk weighed ~1.07 MB raw / ~281 KB gz because
    // every dependency landed in the same first-load file. Splitting React,
    // React Router, TanStack Query, Recharts, and lucide-react into their
    // own chunks lets the browser:
    //   • Cache vendor chunks across deploys (only index-*.js rotates when
    //     feature code changes — vendor hashes only flip when those
    //     packages bump in package-lock.json).
    //   • Parallelise vendor downloads on cold loads (HTTP/2 multiplex).
    //   • Skip Recharts entirely on cold loads of non-Dashboard routes
    //     (recharts is ~410 KB unminified, see bundlephobia.com).
    // Combined with React.lazy() per route in main.tsx the cold-load
    // budget for a non-Dashboard route drops to vendor.react +
    // vendor.router + index. Dashboard pulls vendor.recharts on demand.
    // Vite 8 uses rolldown which requires manualChunks to be a function
    // (id) => string, not the object-shape Vite-5-era rollup accepted.
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('node_modules/react-router-dom'))   return 'vendor-router';
          if (id.includes('node_modules/@tanstack/react-query')) return 'vendor-query';
          if (id.includes('node_modules/recharts'))           return 'vendor-recharts';
          if (id.includes('node_modules/lucide-react'))       return 'vendor-icons';
          if (id.includes('node_modules/react/')
              || id.includes('node_modules/react-dom/')
              || id.includes('node_modules/scheduler/')) {
            return 'vendor-react';
          }
          return undefined;
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    // Exclude Playwright e2e specs from the Vitest run. The harness in
    // src/__tests__/e2e/ uses @playwright/test's test.describe(), which
    // throws "did not expect test.describe() to be called here" under
    // Vitest. Playwright runs them via `npm run e2e` against
    // web/playwright.config.ts (testDir: './src/__tests__/e2e').
    exclude: [...configDefaults.exclude, 'src/__tests__/e2e/**'],
  },
})

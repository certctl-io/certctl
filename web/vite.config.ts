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
// Phase 9 FE-L1 closure: ship the package.json version into the
// bundle as a build-time constant. ErrorBoundary's copy-trace payload
// uses this so a copied stack trace tells the operator which release
// produced the error. Pulled from package.json at config-load time
// (no runtime cost). Falls back to 'dev' if unreadable.
function readPkgVersion(): string {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const pkg = require('./package.json') as { version?: string };
    return pkg.version || 'dev';
  } catch {
    return 'dev';
  }
}

export default defineConfig({
  plugins: [react()],
  define: {
    // Compile-time replace of __APP_VERSION__ in src files. Quoted
    // so the replaced token becomes a string literal in the bundle.
    __APP_VERSION__: JSON.stringify(readPkgVersion()),
  },
  server: {
    port: 5173,
    proxy: {
      '/api':    { target: 'https://localhost:8443', secure: false, changeOrigin: true },
      '/health': { target: 'https://localhost:8443', secure: false, changeOrigin: true },
    }
  },
  build: {
    outDir: 'dist',
    // Phase 9 closure (PERF-M2): 'hidden' generates source maps to
    // disk but does NOT emit a `//# sourceMappingURL=` comment in the
    // production JS chunks — so they're not loadable via the browser
    // (no risk of exposing original source to operators in DevTools),
    // but the operator (or a future Sentry/error-reporting integration)
    // can still upload them as release artifacts for symbolication of
    // FE-L1 ErrorBoundary stack traces. Pre-fix the value was `false`
    // (no maps at all), which means ANY production exception's stack
    // traces are minified-only — useless for triage.
    sourcemap: 'hidden',
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

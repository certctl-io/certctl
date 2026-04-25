import { defineConfig } from 'vite'
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
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
})

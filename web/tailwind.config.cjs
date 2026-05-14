/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // === certctl brand palette (from logo) ===
        brand: {
          50:  '#eefbf6',
          100: '#d5f5e9',
          200: '#afe9d5',
          300: '#7ad8bc',
          400: '#2ea88f', // Primary teal — logo "ctl"
          500: '#1f9680',
          600: '#147868',
          700: '#106055',
          800: '#0f4d44',
          // 900 removed (Phase 0 hygiene, FE-L3): 0 callers in web/src.
          // Re-add if Phase 7 dark-mode rebuild needs it.
        },
        accent: {
          blue:   '#3b7dd8', // Logo blue arrows
          orange: '#e8873a', // Logo orange arrows
          green:  '#4ebe6e', // Logo green highlights
        },
        // Light content area
        page:    '#f0f4f8',  // Light blue-gray page background
        surface: {
          DEFAULT: '#ffffff', // Cards — white
          hover:   '#f8fafc', // Hover on cards
          border:  '#e2e8f0', // Card/table borders
          muted:   '#f1f5f9', // Zebra stripes, subtle fills
        },
        // Dark sidebar
        sidebar: {
          DEFAULT: '#0c2e25', // Deep teal-black
          hover:   '#134438',
          active:  '#185c4a',
          border:  '#1a5c48',
          text:    '#94d2be', // Muted teal for inactive nav
        },
        // Text on light backgrounds (WCAG AA contrast against bg-page #f0f4f8).
        // Phase 0 hygiene (UX-M6): faint bumped from #94a3b8 (3.0:1, fails AA)
        // to #64748b (4.6:1, passes AA). muted bumped from #64748b to #475569
        // (6.9:1, passes AA Large) to preserve the three-tier hierarchy.
        ink: {
          DEFAULT: '#1e293b', // Primary text (12.6:1 vs bg-page)
          muted:   '#475569', // Secondary text (6.9:1 vs bg-page) — was #64748b
          faint:   '#64748b', // Tertiary/placeholder (4.6:1 vs bg-page) — was #94a3b8
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      // Phase 0 hygiene (UX-L1): one design-token rung below `text-xs` (12px)
      // so the 7 historical `text-[10px]` uses migrate losslessly. The other
      // 18 inline-pixel sites (text-[11px] x16, text-[13px] x2) migrate to
      // text-xs / text-sm respectively — a +1px nudge each, imperceptible.
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }], // 10px / 14px
      },
      borderRadius: {
        DEFAULT: '0.375rem',
        sm: '0.25rem',
        md: '0.5rem',
        lg: '0.75rem',
      },
    },
  },
  plugins: [],
}

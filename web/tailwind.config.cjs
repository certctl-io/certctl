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
          900: '#0d3f39',
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
        // Text on light backgrounds
        ink: {
          DEFAULT: '#1e293b', // Primary text
          muted:   '#64748b', // Secondary text
          faint:   '#94a3b8', // Tertiary/placeholder
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
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

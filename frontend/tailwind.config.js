/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          50:  '#eff9ff',
          100: '#dbf1ff',
          200: '#b8e6ff',
          300: '#7ad4ff',
          400: '#36befc',
          500: '#0ca5ed',
          600: '#0086cb',
          700: '#016aa3',
          800: '#065a86',
          900: '#0b4b6f',
          950: '#073049',
        },
        accent: {
          blue:    { light: '#eff9ff', DEFAULT: '#0ca5ed', dark: '#016aa3' },
          green:   { light: '#ecfdf5', DEFAULT: '#10b981', dark: '#059669' },
          orange:  { light: '#fff7ed', DEFAULT: '#f97316', dark: '#ea580c' },
          purple:  { light: '#f5f3ff', DEFAULT: '#8b5cf6', dark: '#7c3aed' },
          red:     { light: '#fef2f2', DEFAULT: '#ef4444', dark: '#dc2626' },
          cyan:    { light: '#ecfeff', DEFAULT: '#06b6d4', dark: '#0891b2' },
          amber:   { light: '#fffbeb', DEFAULT: '#f59e0b', dark: '#d97706' },
          teal:    { light: '#f0fdfa', DEFAULT: '#14b8a6', dark: '#0d9488' },
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          info: '#64748b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      fontSize: {
        'kpi': ['2rem', { lineHeight: '2.5rem', fontWeight: '700' }],
        'kpi-sm': ['1.5rem', { lineHeight: '2rem', fontWeight: '700' }],
      },
      borderRadius: {
        'card': '0.75rem',
        'button': '0.5rem',
        'modal': '1rem',
        'pill': '9999px',
      },
      boxShadow: {
        'card': '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)',
        'card-hover': '0 4px 12px rgba(0,0,0,0.08), 0 2px 4px rgba(0,0,0,0.04)',
        'glow': '0 0 20px -5px rgba(12,165,237,0.15)',
      },
    },
  },
  plugins: [],
};

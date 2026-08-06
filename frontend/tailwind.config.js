/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // ── Brand Palette ─────────────────────────────────────
        brand: {
          50:  '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        // ── Accent Colors for KPI Cards ──────────────────────
        accent: {
          blue:    { light: '#eff6ff', DEFAULT: '#3b82f6', dark: '#1d4ed8' },
          green:   { light: '#ecfdf5', DEFAULT: '#10b981', dark: '#059669' },
          orange:  { light: '#fff7ed', DEFAULT: '#f97316', dark: '#ea580c' },
          purple:  { light: '#f5f3ff', DEFAULT: '#8b5cf6', dark: '#7c3aed' },
          red:     { light: '#fef2f2', DEFAULT: '#ef4444', dark: '#dc2626' },
          cyan:    { light: '#ecfeff', DEFAULT: '#06b6d4', dark: '#0891b2' },
          amber:   { light: '#fffbeb', DEFAULT: '#f59e0b', dark: '#d97706' },
          teal:    { light: '#f0fdfa', DEFAULT: '#14b8a6', dark: '#0d9488' },
        },
        // ── Severity ──────────────────────────────────────────
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          info: '#6b7280',
        },
        // ── Semantic Surfaces ─────────────────────────────────
        surface: {
          // Light mode
          page:      '#f7fafc',
          card:      '#ffffff',
          hover:     '#f1f5f9',
          elevated:  '#ffffff',
          // Dark mode overrides handled via dark: prefix
        },
      },
      // ── Typography ────────────────────────────────────────
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        display: ['Inter', 'system-ui', 'sans-serif'],
      },
      fontSize: {
        'kpi': ['2rem', { lineHeight: '2.5rem', fontWeight: '700', letterSpacing: '-0.02em' }],
        'kpi-sm': ['1.5rem', { lineHeight: '2rem', fontWeight: '700', letterSpacing: '-0.01em' }],
      },
      // ── Spacing ───────────────────────────────────────────
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '120': '30rem',
        '160': '40rem',
      },
      // ── Border Radius ─────────────────────────────────────
      borderRadius: {
        'card': '1rem',
        'button': '0.625rem',
        'modal': '1.25rem',
        'pill': '9999px',
      },
      // ── Shadows ───────────────────────────────────────────
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0,0,0,0.04), 0 1px 2px -1px rgba(0,0,0,0.04)',
        'card-hover': '0 4px 12px -2px rgba(0,0,0,0.08), 0 2px 4px -1px rgba(0,0,0,0.04)',
        'card-dark': '0 1px 3px 0 rgba(0,0,0,0.3), 0 1px 2px -1px rgba(0,0,0,0.2)',
        'card-hover-dark': '0 4px 16px -4px rgba(0,0,0,0.5), 0 2px 6px -1px rgba(0,0,0,0.3)',
        'dropdown': '0 10px 25px -5px rgba(0,0,0,0.08), 0 4px 10px -6px rgba(0,0,0,0.04)',
        'modal': '0 25px 50px -12px rgba(0,0,0,0.15)',
        'nav': '0 1px 2px 0 rgba(0,0,0,0.03)',
        'glow': '0 0 20px -5px rgba(59,130,246,0.2)',
        'glow-dark': '0 0 20px -5px rgba(59,130,246,0.15)',
      },
      // ── Animations ────────────────────────────────────────
      animation: {
        'fade-in': 'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'slide-right': 'slideRight 0.3s ease-out',
        'slide-left': 'slideLeft 0.3s ease-out',
        'scale-in': 'scaleIn 0.3s ease-out',
        'counter': 'counter 0.6s ease-out',
        'pulse-soft': 'pulseSoft 2s ease-in-out infinite',
        'float': 'float 3s ease-in-out infinite',
        'shimmer': 'shimmer 2s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideRight: {
          '0%': { opacity: '0', transform: 'translateX(-8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        slideLeft: {
          '0%': { opacity: '0', transform: 'translateX(8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        scaleIn: {
          '0%': { opacity: '0', transform: 'scale(0.96)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        pulseSoft: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-4px)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      // ── Grid ──────────────────────────────────────────────
      gridTemplateColumns: {
        'dashboard': 'repeat(12, minmax(0, 1fr))',
      },
    },
  },
  plugins: [],
};

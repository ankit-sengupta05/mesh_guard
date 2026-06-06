/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Brand palette — deep security aesthetic
        mesh: {
          bg:        '#09090f',
          surface:   '#0f0f1a',
          panel:     '#13131f',
          border:    '#1e1e2e',
          accent:    '#6366f1',
          'accent-2':'#8b5cf6',
          danger:    '#ef4444',
          warn:      '#f59e0b',
          success:   '#10b981',
          info:      '#3b82f6',
          muted:     '#4b5563',
          text:      '#e2e8f0',
          'text-dim':'#94a3b8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'mesh-grid': `
          linear-gradient(rgba(99,102,241,0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(99,102,241,0.03) 1px, transparent 1px)
        `,
      },
      backgroundSize: {
        'grid-sm': '24px 24px',
      },
      animation: {
        'pulse-slow':   'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow':         'glow 2s ease-in-out infinite alternate',
        'slide-in':     'slideIn 0.3s ease-out',
        'fade-in':      'fadeIn 0.4s ease-out',
        'threat-flash': 'threatFlash 0.6s ease-out',
      },
      keyframes: {
        glow: {
          '0%':   { boxShadow: '0 0 5px rgba(99,102,241,0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(99,102,241,0.6), 0 0 40px rgba(99,102,241,0.2)' },
        },
        slideIn: {
          '0%':   { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)',      opacity: '1' },
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        threatFlash: {
          '0%':   { backgroundColor: 'rgba(239,68,68,0.3)' },
          '100%': { backgroundColor: 'transparent' },
        },
      },
      boxShadow: {
        'glow-accent':  '0 0 20px rgba(99,102,241,0.3)',
        'glow-danger':  '0 0 20px rgba(239,68,68,0.3)',
        'glow-success': '0 0 20px rgba(16,185,129,0.3)',
        'panel':        '0 4px 24px rgba(0,0,0,0.4)',
        'card':         '0 2px 12px rgba(0,0,0,0.3)',
      },
    },
  },
  plugins: [],
}

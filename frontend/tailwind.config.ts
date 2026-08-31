import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          50: '#f8fafc',
          900: '#0f172a',
          950: '#020617',
        },
        amber: {
          500: '#f59e0b',
          600: '#d97706',
        },
        red: {
          500: '#ef4444',
          600: '#dc2626',
        },
        yellow: {
          500: '#eab308',
          600: '#ca8a04',
        },
        blue: {
          500: '#3b82f6',
          600: '#2563eb',
        },
      },
      fontFamily: {
        mono: ['Fira Code', 'Courier New', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 20px rgba(59, 130, 246, 0.3)',
      },
    },
  },
  plugins: [],
}

export default config

import type { Config } from 'tailwindcss';

/** ARGUS design tokens: "The Intelligence Void". Every colour in the app comes from here. */
const config: Config = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        obsidian: '#080A0E',
        graphite: '#151A22',
        elevated: '#1D242E',
        line: 'rgba(185,194,206,0.12)',
        'line-strong': 'rgba(185,194,206,0.24)',
        amber: { DEFAULT: '#FF9D35', dim: 'rgba(255,157,53,0.14)' },
        cyan: { DEFAULT: '#52D9E8', dim: 'rgba(82,217,232,0.12)' },
        threat: { DEFAULT: '#E84B55', dim: 'rgba(232,75,85,0.14)' },
        titanium: { DEFAULT: '#B9C2CE', mute: '#7C8796', faint: '#4A5360' },
        paper: '#EEF1F4',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        micro: ['10px', { lineHeight: '14px', letterSpacing: '0.14em' }],
        label: ['11px', { lineHeight: '16px', letterSpacing: '0.08em' }],
        data: ['12px', { lineHeight: '18px' }],
        body: ['13px', { lineHeight: '20px' }],
      },
      borderRadius: { DEFAULT: '2px', sm: '1px', md: '3px', lg: '4px' },
      boxShadow: { panel: '0 1px 0 0 rgba(185,194,206,0.06) inset, 0 24px 48px -24px rgba(0,0,0,0.6)' },
      keyframes: {
        sweep: { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(400%)' } },
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0.35' } },
      },
      animation: { sweep: 'sweep 1.8s linear infinite', blink: 'blink 1.6s ease-in-out infinite' },
    },
  },
  plugins: [],
};
export default config;

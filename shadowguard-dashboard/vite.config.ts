import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// server.host is gated on `--mode tailscale` (see .env.tailscale) rather than
// always-on: day-to-day `npm run dev` stays localhost-only and nothing about
// normal usage changes. Binding to all interfaces only happens when you
// deliberately run `npm run dev -- --mode tailscale` to share with teammates
// on the tailnet -- see that command's notes for the full swap-in/out flow.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: { host: mode === 'tailscale' },
}));

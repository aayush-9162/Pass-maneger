import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';
import { defineConfig, loadEnv } from 'vite';

/**
 * Content-Security-Policy for the dev server.
 *
 * Production builds are static files served by the API, which applies its own
 * policy - see `webContentSecurityPolicy()` in the backend. This mirrors it so
 * a CSP violation shows up during development rather than after a deploy.
 *
 * Two development-only relaxations: `'unsafe-inline'` for the React refresh
 * preamble Vite injects into index.html, and `ws:` for the HMR socket. The
 * production build emits no inline script at all.
 */
function buildDevCsp(apiUrl: string): string {
  // A relative API URL means same-origin, so `'self'` already covers it.
  let apiOrigin = '';
  if (!apiUrl.startsWith('/')) {
    try {
      apiOrigin = new URL(apiUrl).origin;
    } catch {
      // Malformed value: fall back to same-origin only rather than emitting a
      // broken directive that would disable the whole policy.
      apiOrigin = '';
    }
  }

  return [
    "default-src 'self'",
    // Google's sign-in button: its script, stylesheet, iframe and API, by path.
    "script-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/client",
    "style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style",
    'frame-src https://accounts.google.com/gsi/',
    /*
     * `https:`/`http:` beyond self: the Passwords page shows each entry's site
     * logo - the icon relay lives on the API origin and site favicons come from
     * whatever sites people save, unknowable ahead of time. Images cannot carry
     * script; connect-src still pins where code may talk to.
     */
    `img-src 'self' data: blob: https: http:${apiOrigin ? ` ${apiOrigin}` : ''}`,
    "font-src 'self' data:",
    `connect-src 'self' ws: https://accounts.google.com/gsi/${apiOrigin ? ` ${apiOrigin}` : ''}`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join('; ');
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, import.meta.dirname, 'VITE_');
  const apiUrl = env.VITE_API_URL ?? 'http://localhost:4000/api/v1';

  return {
    plugins: [react()],

    resolve: {
      alias: { '@': resolve(import.meta.dirname, 'src') },
    },

    server: {
      port: 3000,
      // The API's CORS allow-list names this exact origin.
      strictPort: true,
      headers: {
        'Content-Security-Policy': buildDevCsp(apiUrl),
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        // Not no-referrer: Google's button checks the page origin via the referrer.
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        // Lets Google's sign-in popup report back to this window.
        'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
      },
    },

    build: {
      // `out/`, which is where WEB_ROOT already points in existing deployments.
      outDir: 'out',
      emptyOutDir: true,
      // Shipped readable for review, as the extension's bundle is: this code
      // derives the master key, so it should be inspectable in the browser.
      sourcemap: true,
    },
  };
});

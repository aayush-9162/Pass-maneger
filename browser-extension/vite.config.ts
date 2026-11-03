import react from '@vitejs/plugin-react';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig, loadEnv, type Plugin } from 'vite';

/**
 * Finish the shipped manifest: strip documentation keys, and point
 * `host_permissions` at the API this build talks to.
 *
 * The permission is derived from `VITE_API_URL` rather than kept by hand in
 * `public/manifest.json`: the two must match exactly or the service worker's
 * fetch is blocked before it reaches the network, and a build for the network
 * address with a manifest still naming localhost fails in exactly that
 * unhelpful way. It stays a single origin - never a wildcard.
 *
 * JSON has no comments, so the source manifest explains each permission in
 * `_comment_*` keys - which is worth keeping, because "why does a password
 * manager want `tabs`?" is a question that deserves an answer sitting next to
 * the permission rather than in a document nobody opens.
 *
 * Chrome does not recognise those keys and reports each one as a warning on the
 * extension card. Warnings that are known-harmless are the worst kind: they
 * train whoever installs this to ignore the warning area, and the next warning
 * will be a real one. So the comments stay in source and are removed on the way
 * into `dist`.
 */
function finalizeManifest(apiUrl: string): Plugin {
  return {
    name: 'passm:finalize-manifest',
    // After the `public/` copy, so this rewrites the emitted file.
    closeBundle() {
      const manifestPath = resolve(__dirname, 'dist/manifest.json');

      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
      const shipped = Object.fromEntries(
        Object.entries(manifest).filter(([key]) => !key.startsWith('_comment')),
      );
      shipped.host_permissions = [`${new URL(apiUrl).origin}/*`];

      writeFileSync(manifestPath, `${JSON.stringify(shipped, null, 2)}\n`);
    },
  };
}

/**
 * Build for the extension pages and the service worker (ES modules).
 *
 * The content script is built by `vite.content.config.ts` instead, because it
 * must be a classic IIFE: content scripts run in the page's isolated world,
 * which has no ES-module loader. Splitting the two builds is simpler and more
 * predictable than trying to coax one Rollup pass into emitting both formats.
 *
 * `manifest.json` lives in `public/`; see {@link finalizeManifest} for the two
 * changes made on the way into `dist`.
 */
export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    finalizeManifest(
      loadEnv(mode, __dirname, 'VITE_').VITE_API_URL ?? 'http://localhost:4000/api/v1',
    ),
  ],

  resolve: {
    alias: { '@': resolve(__dirname, 'src') },
  },

  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Minified for size (the popup ships React), but with source maps so the
    // shipped bundle is still reviewable - which matters for an extension that
    // asks for broad content-script access.
    minify: 'esbuild',
    sourcemap: true,
    target: 'chrome111',

    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        sidepanel: resolve(__dirname, 'sidepanel.html'),
        // Hidden document that gives the extension a DOM for clipboard access.
        offscreen: resolve(__dirname, 'offscreen.html'),
        background: resolve(__dirname, 'src/background/service-worker.ts'),
      },
      output: {
        // Stable, unhashed names: manifest.json references them directly.
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },

  define: {
    // Vite would otherwise leave `process.env.NODE_ENV` in the React runtime,
    // and there is no `process` inside an extension page.
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production'),
  },
}));

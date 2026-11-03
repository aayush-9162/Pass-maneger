/**
 * Serving the web console from the API process.
 *
 * Optional, enabled by pointing `WEB_ROOT` at the console's Vite build. It
 * exists because it is by far the best shape for a LAN deployment reached by IP:
 *
 *  - **One origin.** The console fetches the API at a relative path, so there is
 *    no CORS surface to configure or get wrong, and no second origin to trust.
 *  - **One port.** Only one firewall rule, and only one certificate.
 *  - **Cookies just work.** Same-origin means `SameSite=Lax` is sufficient;
 *    `SameSite=None` (and therefore mandatory TLS) is not needed.
 *
 * The alternative - console and API on separate ports - remains supported for
 * development; leave `WEB_ROOT` unset and configure `CORS_ORIGINS` instead.
 */

import fs from 'node:fs';
import path from 'node:path';

import express, { type RequestHandler, type Router } from 'express';

import { env } from '../config/env';
import { logger } from '../config/logger';

/**
 * Cache policy.
 *
 * Vite emits content-hashed filenames under `/assets`, so those are immutable
 * and cached for a year. HTML documents must never be cached: a stale one would
 * keep loading a JavaScript bundle that no longer exists after a deploy.
 */
function assetHeaders(webRoot: string): (res: express.Response, filePath: string) => void {
  const hashedAssets = path.join(webRoot, 'assets') + path.sep;

  return (res, filePath) => {
    if (filePath.startsWith(hashedAssets)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      return;
    }

    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, must-revalidate');
      return;
    }

    res.setHeader('Cache-Control', 'public, max-age=3600');
  };
}

/**
 * Build a router that serves the built console.
 *
 * @param webRoot Absolute path to the build directory (`frontend/out/`).
 */
export function createWebRouter(webRoot: string): Router {
  const router = express.Router();

  const staticHandler: RequestHandler = express.static(webRoot, {
    index: 'index.html',
    // Directory listings would expose the build's file layout.
    dotfiles: 'ignore',
    etag: true,
    lastModified: true,
    setHeaders: assetHeaders(webRoot),
    fallthrough: true,
  });

  router.use(staticHandler);

  /**
   * Single-page-app fallback.
   *
   * The console routes in the browser, so `/admin/users` has no file of its
   * own: every path that is not a real file gets `index.html`, and the client
   * router decides what to show - including its own "page not found".
   *
   * Two exclusions keep this from masking real errors. `/api` is mounted first
   * and handles its own not-found case. A missing file with an extension
   * (`/assets/old-a1b2.js` after a deploy) is a genuine 404, not a page -
   * answering it with HTML would hand the browser a script that is not one.
   */
  const indexDocument = path.join(webRoot, 'index.html');
  router.use((req, res, next) => {
    if ((req.method !== 'GET' && req.method !== 'HEAD') || path.extname(req.path) !== '') {
      next();
      return;
    }

    res.setHeader('Cache-Control', 'no-store, must-revalidate');
    res.sendFile(indexDocument);
  });

  return router;
}

/** Resolve and validate the configured web root, logging what was decided. */
export function resolveWebRoot(): string | null {
  if (!env.webRoot) return null;

  const indexDocument = path.join(env.webRoot, 'index.html');
  if (!fs.existsSync(indexDocument)) {
    // Not fatal: the API is still fully usable, and failing to boot over a
    // missing UI asset would be a poor trade.
    logger.error(
      'WEB_ROOT is set but contains no index.html - the console will not be served. ' +
        'Build it with: npm run build:web',
      { webRoot: env.webRoot },
    );
    return null;
  }

  return env.webRoot;
}

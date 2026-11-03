/**
 * Site-logo relay.
 *
 * The console and the extension show a site's favicon beside each password.
 * They cannot ask the public icon services directly: those endpoints answer
 * unknown domains with a placeholder image - which browsers render even under
 * a 404 status - and publish no CORS headers, so a page can never tell a real
 * logo from a grey globe. This relay asks from the server, where the actual
 * status code is visible, and passes on either the image or an honest empty
 * 404 that an `<img>` tag reliably treats as an error. That error is what
 * lets the UI fall back to its lettered tile.
 *
 * Unauthenticated by design: `<img>` cannot attach a bearer token. It
 * discloses nothing - the caller chooses the hostname - and it reaches
 * exactly one fixed upstream, the icon service, with the hostname only ever a
 * path segment there; it cannot be steered at internal addresses.
 *
 * Fetched live per request; the server stores nothing. `Cache-Control` lets
 * the browser cache the image the way it caches any other.
 */

import { Router } from 'express';

/** Plain DNS hostname: labels of letters/digits/hyphens, at least one dot. */
const HOSTNAME =
  /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$/;

const UPSTREAM_TIMEOUT_MS = 6_000;

/** Favicons are tiny; anything bigger than this is not one. */
const MAX_ICON_BYTES = 200 * 1024;

export const iconRoutes = Router();

iconRoutes.get('/:host', async (req, res) => {
  const host = String(req.params.host ?? '').toLowerCase();

  if (host.length > 253 || !HOSTNAME.test(host)) {
    res.status(404).end();
    return;
  }

  try {
    const upstream = await fetch(
      `https://icons.duckduckgo.com/ip3/${encodeURIComponent(host)}.ico`,
      { signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS), redirect: 'follow' },
    );

    const type = upstream.headers.get('content-type') ?? 'image/x-icon';
    if (!upstream.ok || !type.startsWith('image/')) {
      res.status(404).end();
      return;
    }

    const body = Buffer.from(await upstream.arrayBuffer());
    if (body.byteLength === 0 || body.byteLength > MAX_ICON_BYTES) {
      res.status(404).end();
      return;
    }

    res.setHeader('Content-Type', type);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Override the app-wide same-site resource policy: this image is embedded
    // by the console, which may be served from a different host than the API.
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.send(body);
  } catch {
    // Upstream unreachable or too slow. 404 rather than 5xx: to the caller
    // the outcome is the same - no logo today - and the tile falls back.
    res.status(404).end();
  }
});

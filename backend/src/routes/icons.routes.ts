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
 * Answers are remembered for a day - in memory here, and by the browser via
 * `Cache-Control` - including "no logo for this site". A list of passwords
 * asks for one logo per entry on every load, and before this each one went to
 * the icon service again, and every miss was retried by the browser too.
 * Remembering also bounds what this unauthenticated endpoint can make the
 * server fetch: one upstream request per hostname per day, whoever asks. The
 * route is therefore exempt from the global request limit (see app.ts).
 */

import { Router } from 'express';

/** Plain DNS hostname: labels of letters/digits/hyphens, at least one dot. */
const HOSTNAME =
  /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$/;

const UPSTREAM_TIMEOUT_MS = 6_000;

/** Favicons are tiny; anything bigger than this is not one. */
const MAX_ICON_BYTES = 200 * 1024;

/** How long a logo, or the absence of one, is remembered. */
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/** Hostnames remembered at once; the oldest is forgotten first. */
const CACHE_MAX_ENTRIES = 2000;

type IconResult = { type: string; body: Buffer } | null;

const cache = new Map<string, { result: IconResult; expires: number }>();
/** Lookups in flight, so a page asking twice at once fetches once. */
const pending = new Map<string, Promise<IconResult>>();

async function fetchIcon(host: string): Promise<IconResult> {
  try {
    const upstream = await fetch(
      `https://icons.duckduckgo.com/ip3/${encodeURIComponent(host)}.ico`,
      { signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS), redirect: 'follow' },
    );

    const type = upstream.headers.get('content-type') ?? 'image/x-icon';
    if (!upstream.ok || !type.startsWith('image/')) return null;

    const body = Buffer.from(await upstream.arrayBuffer());
    if (body.byteLength === 0 || body.byteLength > MAX_ICON_BYTES) return null;

    return { type, body };
  } catch {
    // Upstream unreachable or too slow: no logo today, and the tile falls back.
    return null;
  }
}

async function lookupIcon(host: string): Promise<IconResult> {
  const cached = cache.get(host);
  if (cached && cached.expires > Date.now()) return cached.result;

  let inFlight = pending.get(host);
  if (!inFlight) {
    inFlight = fetchIcon(host).finally(() => pending.delete(host));
    pending.set(host, inFlight);
  }
  const result = await inFlight;

  // Re-inserted so the Map's insertion order is least-recently-fetched first.
  cache.delete(host);
  cache.set(host, { result, expires: Date.now() + CACHE_TTL_MS });
  if (cache.size > CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  return result;
}

export const iconRoutes = Router();

iconRoutes.get('/:host', async (req, res) => {
  const host = String(req.params.host ?? '').toLowerCase();

  if (host.length > 253 || !HOSTNAME.test(host)) {
    res.status(404).end();
    return;
  }

  const icon = await lookupIcon(host);

  // Cached either way: a site with no logo today will not have one in a minute,
  // and without this the browser asked again on every page load.
  res.setHeader('Cache-Control', 'public, max-age=86400');

  if (!icon) {
    // 404 rather than 5xx: to the caller the outcome is the same - no logo -
    // and an <img> reliably treats it as an error, so the tile falls back.
    res.status(404).end();
    return;
  }

  res.setHeader('Content-Type', icon.type);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Override the app-wide same-site resource policy: this image is embedded
  // by the console, which may be served from a different host than the API.
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.send(icon.body);
});

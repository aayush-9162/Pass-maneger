/**
 * HTTP security headers and CORS.
 *
 * ## Helmet
 *
 * This process serves JSON, not HTML, so the CSP is locked to `default-src
 * 'none'`. That is not theatre: if a browser is ever tricked into rendering an
 * API response as a document, the policy stops any script in it from executing -
 * the last line of defence against reflected XSS through an API endpoint.
 *
 * ## CORS
 *
 * Requests are credentialed (the refresh token is a cookie), so `*` is not an
 * option - the browser refuses it, and it would defeat the point. Origins come
 * from an explicit allow-list. An unknown origin gets a response with no CORS
 * headers rather than an error: the browser then blocks it, and we avoid turning
 * a probe into a 500 that pollutes error metrics.
 */

import cors, { type CorsOptions } from 'cors';
import type { RequestHandler } from 'express';
import helmet from 'helmet';

import { HEADERS } from '@passm/shared';

import { env } from '../config/env';
import { logger } from '../config/logger';
import { BadRequestError } from '../utils/errors';

/**
 * Is this deployment actually served over TLS?
 *
 * Either this process terminates it, or a trusted proxy in front does. When
 * plaintext HTTP has been explicitly enabled for a LAN, it is not.
 */
const servedOverTls = env.tls.enabled || (env.trustProxyHops > 0 && !env.allowInsecureHttp);

/**
 * Global security headers, minus the CSP.
 *
 * The CSP is applied per branch instead: the API and the web console need very
 * different policies, and a single global policy would either break the console
 * or be uselessly permissive for the API. See {@link apiContentSecurityPolicy}
 * and {@link webContentSecurityPolicy}.
 */
export function securityHeaders(): RequestHandler {
  return helmet({
    contentSecurityPolicy: false,

    /**
     * HSTS only over TLS - announcing it over plaintext is meaningless, and
     * announcing it from a LAN host that may legitimately serve HTTP would pin
     * browsers to HTTPS and lock users out.
     *
     * Note it is a no-op for a bare IP address either way: RFC 6797 applies HSTS
     * to domain names only, which is one more reason a LAN-by-IP deployment
     * should use a real certificate rather than rely on this header.
     */
    hsts: servedOverTls
      ? { maxAge: env.security.hstsMaxAge, includeSubDomains: true, preload: false }
      : false,

    // Stop content-type sniffing turning a JSON body into an executable document.
    noSniff: true,
    /*
     * Cross-origin requests carry the origin only - never a path - and
     * same-origin ones the full URL. Not `no-referrer`: Google's sign-in button
     * checks the page's origin against the OAuth client's authorised origins
     * using the referrer, and refuses to render without one.
     */
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // No framing at all: this API has no embeddable surface.
    frameguard: { action: 'deny' },
    // Cross-origin isolation headers. `same-site` still allows the SPA and the
    // extension, which are configured as explicit CORS origins.
    crossOriginResourcePolicy: { policy: 'same-site' },
    // `-allow-popups` so Google's sign-in popup can hand its result back to
    // the console; anything stricter severs that window reference.
    crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
    // Not set: it breaks the extension's fetch to this API for no gain on a
    // JSON-only surface.
    crossOriginEmbedderPolicy: false,
    // Removes `X-Powered-By`, which otherwise advertises Express and its version.
    hidePoweredBy: true,
  });
}

/**
 * CSP for API responses.
 *
 * This branch only ever returns JSON, so everything is denied. If a browser is
 * ever tricked into rendering an API response as a document, nothing in it can
 * execute - the last line of defence behind correct content types.
 */
export function apiContentSecurityPolicy(): RequestHandler {
  return helmet.contentSecurityPolicy({
    useDefaults: false,
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
    },
  });
}

/**
 * What Google Identity Services needs, scoped to its own paths as Google
 * documents - not the whole of accounts.google.com.
 */
const GOOGLE_SIGN_IN_ORIGINS = {
  script: 'https://accounts.google.com/gsi/client',
  style: 'https://accounts.google.com/gsi/style',
  frame: 'https://accounts.google.com/gsi/',
  connect: 'https://accounts.google.com/gsi/',
} as const;

/**
 * CSP for the web console, when this process serves it.
 *
 * `connect-src 'self'` is exact here rather than an origin list: in the
 * single-origin deployment the console calls the API on the same host and port,
 * so it cannot be induced to talk to anywhere else at all.
 *
 * `script-src` has no `'unsafe-inline'`: the Vite build loads every script from
 * a file, including the pre-paint theme script, so an injected inline script
 * cannot run even if an XSS flaw lets one into the page.
 */
export function webContentSecurityPolicy(): RequestHandler {
  return helmet.contentSecurityPolicy({
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", GOOGLE_SIGN_IN_ORIGINS.script],
      styleSrc: ["'self'", "'unsafe-inline'", GOOGLE_SIGN_IN_ORIGINS.style],
      /*
       * `https:` (and `http:` for LAN intranet hosts) because the Passwords
       * page shows each entry's site logo, fetched live from whatever site
       * the entry names - unknowable ahead of time. Images cannot carry
       * script, and connect-src still pins where code may talk to.
       */
      imgSrc: ["'self'", 'data:', 'blob:', 'https:', 'http:'],
      fontSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", GOOGLE_SIGN_IN_ORIGINS.connect],
      // The sign-in button renders in an iframe served by Google.
      frameSrc: [GOOGLE_SIGN_IN_ORIGINS.frame],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      objectSrc: ["'none'"],
    },
  });
}

/** Origins that may make credentialed requests. */
function buildAllowedOrigins(): Set<string> {
  const allowed = new Set<string>(env.cors.origins);

  for (const extensionOrigin of env.cors.extensionOrigins) {
    // Accept either a bare extension id or a full origin, and normalise.
    allowed.add(
      extensionOrigin.startsWith('chrome-extension://')
        ? extensionOrigin
        : `chrome-extension://${extensionOrigin}`,
    );
  }

  return allowed;
}

const allowedOrigins = buildAllowedOrigins();

export function corsMiddleware(): RequestHandler {
  const options: CorsOptions = {
    origin(origin, callback) {
      // No Origin header: same-origin navigation, curl, health checks, or a
      // server-to-server call. Nothing to authorise.
      if (!origin) {
        callback(null, true);
        return;
      }

      if (allowedOrigins.has(origin)) {
        callback(null, true);
        return;
      }

      logger.warn('Blocked cross-origin request from an unlisted origin', { origin });
      // `false` omits the CORS headers, so the browser blocks it. Passing an
      // Error here would surface as a 500 instead.
      callback(null, false);
    },

    // Required for the httpOnly refresh-token cookie to be sent.
    credentials: true,

    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

    /**
     * Every custom request header must be listed here.
     *
     * A browser preflights any request carrying a non-simple header and refuses
     * to send the real one unless the server names that header in
     * `Access-Control-Allow-Headers`. Adding a header on the client without
     * adding it here fails *only in a browser* - server-to-server callers and
     * test scripts skip preflight entirely, so the gap is invisible until
     * someone opens the console.
     */
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      HEADERS.REQUEST_ID,
      HEADERS.DEVICE_ID,
      HEADERS.DEVICE_FINGERPRINT,
      HEADERS.DEVICE_NAME,
      HEADERS.CSRF_TOKEN,
      'x-client-type',
    ],

    // Clients need to read these off the response.
    exposedHeaders: [HEADERS.REQUEST_ID, 'Retry-After', 'RateLimit-Reset'],

    // Cache preflights for 10 minutes to cut the OPTIONS round trips.
    maxAge: 600,

    optionsSuccessStatus: 204,
  };

  return cors(options);
}

/**
 * Reject plaintext HTTP in production.
 *
 * Behind a TLS-terminating proxy the app only sees HTTP, so the decision is made
 * from `X-Forwarded-Proto` - which is why `TRUST_PROXY_HOPS` must be set
 * correctly. Without a trusted proxy this middleware would be reading a
 * client-controlled header, so it deliberately does nothing in that case.
 *
 * GET/HEAD are redirected (a browser can follow it); anything else is refused,
 * because a redirect on a POST would either drop the body or replay a credential
 * over the very cleartext connection being objected to.
 */
export const enforceHttps: RequestHandler = (req, res, next) => {
  // Explicitly disabled for a plaintext LAN deployment: redirecting to a scheme
  // this server does not answer on would make the app unreachable.
  if (env.allowInsecureHttp || !env.isProduction || env.trustProxyHops === 0) {
    next();
    return;
  }

  // `req.secure` already accounts for the trusted X-Forwarded-Proto chain.
  if (req.secure) {
    next();
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    res.redirect(308, `https://${req.headers.host ?? ''}${req.originalUrl}`);
    return;
  }

  next(new BadRequestError('HTTPS is required for this request.'));
};

/**
 * Reject requests whose body is not JSON.
 *
 * `express.json()` would silently leave `req.body` empty for a mismatched
 * content type, and validation would then report confusing "field is required"
 * errors instead of the real problem. It also blocks the form-encoded POST that
 * a classic CSRF attack relies on, since a cross-origin form cannot set
 * `Content-Type: application/json`.
 */
export const requireJsonContentType: RequestHandler = (req, _res, next) => {
  if (!['POST', 'PUT', 'PATCH'].includes(req.method)) {
    next();
    return;
  }

  // A body-less POST (e.g. /logout with no options) is legitimate.
  const hasBody =
    req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0';
  const isChunked = req.headers['transfer-encoding'] !== undefined;

  if (!hasBody && !isChunked) {
    next();
    return;
  }

  if (!req.is('application/json')) {
    next(new BadRequestError('Content-Type must be application/json.'));
    return;
  }

  next();
};

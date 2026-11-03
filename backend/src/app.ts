/**
 * Express application assembly.
 *
 * Separated from `server.ts` so the app can be constructed without binding a
 * port - which is what makes it testable with supertest.
 *
 * The middleware order below is deliberate; the comments explain why each step
 * sits where it does. Reordering this list changes the security posture.
 */

import { API_PREFIX } from '@passm/shared';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import express, { type Express } from 'express';

import { env } from './config/env';
import { logger } from './config/logger';
import {
  accessLogger,
  apiContentSecurityPolicy,
  corsMiddleware,
  createWebRouter,
  deviceContext,
  enforceHttps,
  errorHandler,
  globalLimiter,
  notFoundHandler,
  requestContext,
  requireJsonContentType,
  resolveWebRoot,
  securityHeaders,
  webContentSecurityPolicy,
} from './middleware';
import { apiRouter } from './routes';

export function createApp(): Express {
  const app = express();

  // -------------------------------------------------------------------------
  // Application settings
  // -------------------------------------------------------------------------

  /**
   * Trust exactly as many proxy hops as are actually deployed.
   *
   * This is a security setting, not a convenience one: set it too high and a
   * client can forge `X-Forwarded-For` to defeat rate limiting and account
   * lockout (both keyed by IP); set it too low and every request appears to come
   * from the load balancer, so one abusive user throttles everyone.
   */
  app.set('trust proxy', env.trustProxyHops > 0 ? env.trustProxyHops : false);

  // Removed by helmet as well; disabled here so it is never sent at all.
  app.disable('x-powered-by');
  // ETags on JSON API responses only add conditional-request bookkeeping.
  app.disable('etag');
  // Reject `/api/v1/login/` vs `/api/v1/login` ambiguity and case variance, so
  // route-level middleware cannot be bypassed with a differently-cased path.
  app.set('strict routing', false);
  app.set('case sensitive routing', false);
  // Cap URL-encoded parameter pollution.
  app.set('query parser', 'simple');

  // -------------------------------------------------------------------------
  // 1. Correlation - first, so everything downstream can log a request id.
  // -------------------------------------------------------------------------
  app.use(requestContext);

  // -------------------------------------------------------------------------
  // 2. Transport and headers - before any handler can produce a response.
  // -------------------------------------------------------------------------
  app.use(enforceHttps);
  app.use(securityHeaders());
  app.use(corsMiddleware());

  /**
   * 3. Compression, restricted to GET/HEAD.
   *
   * Compressing a response that mixes a secret with attacker-influenced content
   * enables the BREACH class of attack, where ciphertext length leaks the secret.
   * Every response that carries a token is a POST (`/login`, `/refresh`), so
   * limiting compression to safe methods removes the exposure while still
   * compressing the payloads that actually benefit - user and audit listings.
   */
  app.use(
    compression({
      threshold: 1024,
      filter: (req, res) =>
        (req.method === 'GET' || req.method === 'HEAD') && compression.filter(req, res),
    }),
  );

  // -------------------------------------------------------------------------
  // 4. Body parsing.
  // -------------------------------------------------------------------------
  app.use(cookieParser());

  // Enforced before parsing so a form-encoded cross-origin POST - the classic
  // CSRF shape, which cannot set a JSON content type - is rejected outright.
  app.use(requireJsonContentType);

  app.use(
    express.json({
      limit: env.security.bodyLimit,
      // `strict` rejects a bare top-level value, so only objects and arrays parse.
      strict: true,
      type: 'application/json',
    }),
  );

  // Intentionally no `express.urlencoded`: this API accepts JSON only, and not
  // parsing form bodies removes a whole class of parser-confusion bugs.

  // -------------------------------------------------------------------------
  // 5. Request-scoped context that depends on the parsed body.
  // -------------------------------------------------------------------------
  app.use(deviceContext);

  // -------------------------------------------------------------------------
  // 6. Access logging - registered before the routes so the `finish` listener is
  //    attached even for requests a route never handles.
  // -------------------------------------------------------------------------
  app.use(accessLogger);

  // -------------------------------------------------------------------------
  // 7. Global rate limit, ahead of any route work.
  // -------------------------------------------------------------------------
  app.use(globalLimiter);

  // -------------------------------------------------------------------------
  // 8. API routes, under the strict JSON-only CSP.
  //
  //    `notFoundHandler` is mounted *inside* this branch so an unmatched
  //    `/api/v1/...` path terminates here with a JSON error. Without it the
  //    request would fall through to the static console below and receive an
  //    HTML 404 - which breaks every client that parses the response envelope.
  // -------------------------------------------------------------------------
  app.use(API_PREFIX, apiContentSecurityPolicy(), apiRouter, notFoundHandler);

  // -------------------------------------------------------------------------
  // 9. Web console, when this process serves it (WEB_ROOT).
  //
  //    Mounted after the API so `/api/*` can never be shadowed by a static file,
  //    and under a document CSP rather than the API's `default-src 'none'`.
  // -------------------------------------------------------------------------
  const webRoot = resolveWebRoot();

  if (webRoot) {
    app.use(webContentSecurityPolicy(), createWebRouter(webRoot));
    logger.info('Serving the web console from this process', { webRoot });
  } else {
    /** No console to serve: point callers at the versioned API. */
    app.get('/', (_req, res) => {
      res.status(200).json({
        success: true,
        data: { service: env.appName, api: API_PREFIX },
        requestId: res.locals.requestId,
        timestamp: new Date().toISOString(),
      });
    });
  }

  // -------------------------------------------------------------------------
  // 10. Terminal handlers - must be last, and in this order.
  // -------------------------------------------------------------------------
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

/**
 * Request correlation and access logging.
 *
 * Must be mounted first: everything downstream (logger, error handler, audit
 * trail) reads `req.requestId`. A single id ties an API log line, an audit row
 * and the client's error message together, which is what makes a production
 * incident investigable.
 */

import { HEADERS } from '@passm/shared';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

import { createChildLogger, logger } from '../config/logger';
import { isUuid, newId } from '../utils/ids';
import {
  getClientIp,
  getDeviceIdentity,
  getUserAgent,
  isNonCookieClient,
} from '../utils/request-context';

/**
 * Attach a request id, a bound logger and the normalised request context.
 *
 * A client-supplied `x-request-id` is honoured only when it is a valid UUID.
 * Echoing an arbitrary string would let a caller inject formatting into log
 * lines and forge correlation ids across tenants.
 */
export const requestContext: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  const incoming = req.header(HEADERS.REQUEST_ID);
  const requestId = isUuid(incoming) ? incoming : newId();

  req.requestId = requestId;
  res.locals.requestId = requestId;
  res.setHeader(HEADERS.REQUEST_ID, requestId);

  req.startedAt = process.hrtime.bigint();
  req.log = createChildLogger({
    requestId,
    method: req.method,
    path: req.originalUrl.split('?')[0],
  });

  req.context = {
    requestId,
    ipAddress: getClientIp(req),
    userAgent: getUserAgent(req),
    fromExtension: isNonCookieClient(req),
  };

  next();
};

/**
 * Parse device metadata from headers/body onto the request.
 *
 * Mounted after the body parser so the body fallback works. Returns `null` when
 * the client sent nothing usable; `/login` handles that by allocating an id.
 */
export const deviceContext: RequestHandler = (req: Request, _res: Response, next: NextFunction) => {
  req.deviceIdentity = getDeviceIdentity(req);
  next();
};

/** Paths excluded from access logging to keep health-check noise out of logs. */
const QUIET_PATHS = new Set(['/api/v1/health', '/api/v1/health/ready', '/favicon.ico']);

/**
 * Access log, emitted once per response.
 *
 * Uses the `finish` event rather than wrapping `res.end`, so the entry reflects
 * the real status code and duration even when an error handler rewrote them.
 */
export const accessLogger: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  res.on('finish', () => {
    const path = req.originalUrl.split('?')[0] ?? req.originalUrl;
    if (QUIET_PATHS.has(path) && res.statusCode < 400) return;

    const durationMs = Number(process.hrtime.bigint() - req.startedAt) / 1_000_000;

    const payload = {
      method: req.method,
      path,
      status: res.statusCode,
      durationMs: Math.round(durationMs * 100) / 100,
      ip: req.context?.ipAddress,
      userId: req.auth?.userId,
      sessionId: req.auth?.sessionId,
      contentLength: res.getHeader('content-length'),
    };

    // Severity follows the status class: 5xx is our fault, 4xx is the caller's,
    // and everything else is routine.
    if (res.statusCode >= 500) {
      req.log.error('Request failed', payload);
    } else if (res.statusCode >= 400) {
      req.log.warn('Request rejected', payload);
    } else {
      req.log.http('Request completed', payload);
    }
  });

  res.on('close', () => {
    // The client hung up before the response finished. Worth knowing about: it
    // often means a timeout upstream rather than a problem here.
    if (!res.writableEnded) {
      logger.debug('Client aborted request', {
        requestId: req.requestId,
        method: req.method,
        path: req.originalUrl.split('?')[0],
      });
    }
  });

  next();
};

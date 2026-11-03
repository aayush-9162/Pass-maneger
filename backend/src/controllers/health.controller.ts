/**
 * Health endpoints.
 *
 * The liveness/readiness split matters operationally:
 *
 *  - **Liveness** (`/health`) touches no dependency. It answers "is this process
 *    running?". If it consulted MySQL, a brief database blip would make every
 *    orchestrator kill every healthy pod at once, turning a small outage into a
 *    total one.
 *  - **Readiness** (`/health/ready`) checks MySQL and the cache. A failure here
 *    removes the instance from the load balancer without restarting it, so it
 *    rejoins automatically when the dependency recovers.
 *
 * Neither endpoint requires authentication - a load balancer cannot log in - so
 * both are deliberately free of any internal detail: no versions, no hostnames,
 * no connection strings.
 */

import type { Request, Response } from 'express';

import { checkCacheHealth } from '../config/cache';
import { checkDatabaseHealth } from '../config/database';
import { env } from '../config/env';
import { sendSuccess } from '../utils/api-response';
import { sendError } from '../utils/api-response';
import { ERROR_CODES } from '@passm/shared';

/** GET /health - liveness. Always 200 while the event loop is responsive. */
export function live(_req: Request, res: Response): void {
  sendSuccess(res, {
    status: 'ok',
    service: env.appName,
    uptimeSeconds: Math.floor(process.uptime()),
  });
}

/**
 * GET /health/ready - readiness.
 *
 * Returns 503 when a hard dependency is down, so traffic is withheld until it
 * recovers. The cache is a *soft* dependency: the app is correct without it, so
 * an unhealthy cache is reported but does not fail readiness.
 */
export async function ready(_req: Request, res: Response): Promise<void> {
  const [database, cache] = await Promise.all([checkDatabaseHealth(), checkCacheHealth()]);

  const payload = {
    status: database.ok ? 'ready' : 'degraded',
    checks: {
      database: { ok: database.ok, latencyMs: database.latencyMs },
      cache: { ok: cache.ok, kind: cache.kind, latencyMs: cache.latencyMs },
    },
    uptimeSeconds: Math.floor(process.uptime()),
  };

  if (!database.ok) {
    sendError(
      res,
      503,
      ERROR_CODES.SERVICE_UNAVAILABLE,
      'Service is not ready: the database is unreachable.',
      { retryAfter: 10 },
    );
    return;
  }

  sendSuccess(res, payload);
}

export const healthController = { live, ready };

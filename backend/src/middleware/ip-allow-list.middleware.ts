/**
 * IP allow-list enforcement, and the emergency lock.
 *
 * Both live here because both are whole-request gates evaluated from the same
 * cached policy read, and splitting them would double the settings lookup on
 * every call for no benefit.
 *
 * Ordering matters. This runs *after* authentication, because the allow list has
 * per-user and per-role scopes and an administrator exemption - none of which
 * can be evaluated without knowing who is calling. The cost is that an
 * unauthenticated request from a blocked address still reaches the login
 * handler. That is acceptable: login is separately rate-limited, and blocking
 * pre-authentication would mean the allow list could only ever be global.
 */

import type { NextFunction, Request, RequestHandler, Response } from 'express';

import { ROUTES } from '@passm/shared';

import { logger } from '../config/logger';
import { ipAccessService } from '../services/ip-access.service';
import { securitySettingsService } from '../services/security-settings.service';
import { EmergencyLockError, IpNotAllowedError } from '../utils/errors';
import { getClientIp } from '../utils/request-context';

/**
 * Enforce the allow list.
 *
 * Failures inside the evaluation are swallowed and the request proceeds - see
 * the fail-open reasoning in `ip-access.service`. A blocked *decision* is
 * different from a *failure to decide*, and only the former refuses the request.
 */
export function ipAllowList(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const ip = getClientIp(req);
    const path = req.originalUrl.split('?')[0] ?? req.path;

    void ipAccessService
      .evaluateAndAudit(ip, req.auth ?? null, req.context, path)
      .then((decision) => {
        if (decision.allowed) {
          next();
          return;
        }
        next(new IpNotAllowedError(ip));
      })
      .catch((error: unknown) => {
        logger.error('IP allow list evaluation failed; allowing the request', { error, ip });
        next();
      });
  };
}

/**
 * Paths that stay open while the emergency lock is on.
 *
 * An administrator must be able to sign in and lift the lock, so authentication
 * and the settings surface remain reachable. Without this the lock would be
 * irreversible without a database edit, which makes it a control nobody will
 * ever dare use.
 *
 * Note that signing in is permitted for *everyone*, not only administrators -
 * the server cannot know a caller's role until they have authenticated. What
 * ordinary users get after signing in is the lock message, because every vault
 * route below is still refused.
 */
const LOCK_EXEMPT: readonly RegExp[] = [
  /\/auth\/login$/,
  /\/auth\/logout$/,
  /\/auth\/refresh$/,
  /\/auth\/profile$/,
  /\/health(\/ready)?$/,
  new RegExp(`${ROUTES.SECURITY.CSRF_TOKEN.replace(/\//g, '\\/')}$`),
  new RegExp(`${ROUTES.SECURITY.POLICY.replace(/\//g, '\\/')}$`),
  new RegExp(`${ROUTES.SECURITY.NOTIFICATIONS.replace(/\//g, '\\/')}`),
  // The admin settings surface, so the lock can be lifted from the console.
  new RegExp(`${ROUTES.ADMIN.SETTINGS.replace(/\//g, '\\/')}`),
  new RegExp(`${ROUTES.ADMIN.EMERGENCY_LOCK.replace(/\//g, '\\/')}`),
];

function isLockExempt(path: string): boolean {
  return LOCK_EXEMPT.some((pattern) => pattern.test(path));
}

/**
 * Refuse everything while the break-glass switch is on.
 *
 * Administrators are exempt entirely: the person lifting the lock needs to
 * inspect users, sessions and audit logs to decide whether it is safe to do so.
 * A lock that blinds the responder is a lock that stays on longer.
 */
export function emergencyLockGuard(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const path = req.originalUrl.split('?')[0] ?? req.path;

    if (isLockExempt(path)) {
      next();
      return;
    }

    void securitySettingsService
      .getSettings()
      .then((settings) => {
        if (!settings.emergencyLockActive) {
          next();
          return;
        }

        if (req.auth?.role === 'admin') {
          next();
          return;
        }

        logger.warn('Request refused by the emergency lock', {
          requestId: req.requestId,
          userId: req.auth?.userId,
          path,
        });

        next(new EmergencyLockError(settings.emergencyLockMessage));
      })
      .catch((error: unknown) => {
        // Fail open. If the policy is unreadable we cannot know the lock is on,
        // and refusing every request on a database blip would be an outage
        // caused by the safety mechanism rather than prevented by it.
        logger.error('Could not read the emergency lock state; allowing the request', { error });
        next();
      });
  };
}

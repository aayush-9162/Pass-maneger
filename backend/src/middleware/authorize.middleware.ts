/**
 * Role- and permission-based authorization.
 *
 * Prefer {@link requirePermission} over {@link requireRole}: permissions state
 * *what* the route needs, roles state *who* happens to have it today. When a
 * capability moves between roles, the permission matrix in
 * `shared/src/constants/permissions.ts` changes and every route follows - no
 * route file needs editing, and no route can be forgotten.
 *
 * `requireRole` remains for the few cases where the role itself is the rule
 * (for example: only an administrator may provision accounts, regardless of how
 * permissions are arranged).
 */

import {
  ERROR_CODES,
  ROLE_LABEL,
  roleAtLeast,
  type Permission,
  type RoleName,
} from '@passm/shared';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

import { ForbiddenError } from '../utils/errors';
import { requireAuth } from './authenticate.middleware';

/**
 * Log the denial, then reject.
 *
 * Every refusal is logged at warn: a burst of them is a strong signal of either
 * a broken client or someone probing for privilege escalation.
 */
function deny(req: Request, reason: string, detail: Record<string, unknown>): ForbiddenError {
  req.log.warn(`Authorization denied: ${reason}`, {
    userId: req.auth?.userId,
    role: req.auth?.role,
    path: req.originalUrl.split('?')[0],
    ...detail,
  });

  return new ForbiddenError(
    'You do not have permission to perform this action.',
    reason === 'insufficient role'
      ? ERROR_CODES.INSUFFICIENT_ROLE
      : ERROR_CODES.INSUFFICIENT_PERMISSION,
  );
}

/** Require one of the listed roles exactly. */
export function requireRole(...roles: RoleName[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const auth = requireAuth(req);

    if (!roles.includes(auth.role)) {
      next(deny(req, 'insufficient role', { required: roles }));
      return;
    }

    next();
  };
}

/**
 * Require at least the given role, by privilege level.
 *
 * `requireMinRole('manager')` admits managers and admins. Uses the level values
 * from the shared role table, so inserting a new role in the hierarchy does not
 * require revisiting call sites.
 */
export function requireMinRole(minimum: RoleName): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const auth = requireAuth(req);

    if (!roleAtLeast(auth.role, minimum)) {
      next(
        deny(req, 'insufficient role', {
          required: `${ROLE_LABEL[minimum]} or higher`,
        }),
      );
      return;
    }

    next();
  };
}

/** Require *all* of the listed permissions. */
export function requirePermission(...permissions: Permission[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const auth = requireAuth(req);

    const missing = permissions.filter((permission) => !auth.permissions.includes(permission));
    if (missing.length > 0) {
      next(deny(req, 'missing permission', { missing }));
      return;
    }

    next();
  };
}

/** Require *any one* of the listed permissions. */
export function requireAnyPermission(...permissions: Permission[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const auth = requireAuth(req);

    if (!permissions.some((permission) => auth.permissions.includes(permission))) {
      next(deny(req, 'missing permission', { anyOf: permissions }));
      return;
    }

    next();
  };
}

/**
 * Allow the caller to act on their own record, or on anyone else's if they hold
 * `permission`.
 *
 * This is the guard that prevents the most common IDOR: a route like
 * `GET /users/:id/sessions` where the id is simply trusted. Here an employee may
 * read their own, while only a holder of `session:read:any` may read another's.
 *
 * @param paramName Route parameter holding the target user id.
 */
export function requireSelfOrPermission(
  permission: Permission,
  paramName = 'id',
): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const auth = requireAuth(req);
    const targetUserId = req.params[paramName];

    if (targetUserId !== undefined && targetUserId === auth.userId) {
      next();
      return;
    }

    if (auth.permissions.includes(permission)) {
      next();
      return;
    }

    next(
      deny(req, 'missing permission', {
        required: permission,
        targetUserId,
        note: 'caller is neither the subject nor sufficiently privileged',
      }),
    );
  };
}

/**
 * Require a trusted device.
 *
 * Not applied to any route today - trust currently only governs whether a
 * step-up prompt is skipped. It is provided so that when a genuinely sensitive
 * operation is added (bulk vault export, break-glass admin action), the check is
 * already here and consistent with how trust is granted.
 */
export const requireTrustedDevice: RequestHandler = (
  req: Request,
  _res: Response,
  next: NextFunction,
) => {
  const auth = requireAuth(req);

  if (!auth.deviceTrusted) {
    req.log.warn('Blocked action that requires a trusted device', { userId: auth.userId });
    next(
      new ForbiddenError(
        'This action requires a device you have marked as trusted.',
        ERROR_CODES.DEVICE_NOT_TRUSTED,
      ),
    );
    return;
  }

  next();
};

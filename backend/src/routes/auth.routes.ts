/**
 * Authentication routes.
 *
 * Middleware order is a security property, not a style choice:
 *
 *   rate limit -> validate -> authenticate -> authorize -> handler
 *
 *  - Rate limiting first, so an abusive caller is rejected before any expensive
 *    work (token verification, database round trips).
 *  - Validation before authentication, so malformed input never reaches the token
 *    verifier.
 *
 * This router is mounted twice (see `routes/index.ts`) so both
 * `POST /api/v1/auth/google` and the flat `POST /api/v1/google` work.
 */

import { PERMISSIONS, ROLES } from '@passm/shared';
import { Router } from 'express';

import { authController } from '../controllers/auth.controller';
import { deviceController } from '../controllers/device.controller';
import { sessionController } from '../controllers/session.controller';
import {
  googleLoginSchema,
  logoutSchema,
  refreshSchema,
  registerSchema,
} from '../dto/auth.dto';
import {
  deviceIdParamSchema,
  renameDeviceSchema,
  sessionIdParamSchema,
} from '../dto/device.dto';
import { authenticate } from '../middleware/authenticate.middleware';
import { csrfProtection } from '../middleware/csrf.middleware';
import { requirePermission, requireRole } from '../middleware/authorize.middleware';
import {
  loginIpLimiter,
  refreshLimiter,
  sensitiveOperationLimiter,
} from '../middleware/rate-limit.middleware';
import { validate } from '../middleware/validate.middleware';
import { asyncHandler } from '../utils/async-handler';

export const authRoutes = Router();

// ---------------------------------------------------------------------------
// Public
// ---------------------------------------------------------------------------

/**
 * POST /google - the only way to sign in.
 *
 * There is no password to guess, so the per-account limiter has nothing to
 * protect; the IP limiter still caps how fast one address can present tokens.
 */
authRoutes.post(
  '/google',
  loginIpLimiter,
  validate({ body: googleLoginSchema }),
  asyncHandler(authController.googleLogin),
);

/** GET /google/config - what the sign-in button needs. Public; not a secret. */
authRoutes.get('/google/config', asyncHandler(authController.googleConfig));

/** POST /refresh - the refresh token itself is the credential. */
authRoutes.post(
  '/refresh',
  refreshLimiter,
  validate({ body: refreshSchema }),
  asyncHandler(authController.refresh),
);

// ---------------------------------------------------------------------------
// Authenticated
// ---------------------------------------------------------------------------

/** POST /logout */
authRoutes.post(
  '/logout',
  authenticate,
  csrfProtection(),
  validate({ body: logoutSchema }),
  asyncHandler(authController.logout),
);

/*
 * There is no `POST /login` and no `POST /change-password`: Google is the only
 * credential, and PassM accounts have no password to check or change.
 */

/** GET /profile */
authRoutes.get(
  '/profile',
  authenticate,
  asyncHandler(authController.profile),
);

/**
 * POST /register - admin-only user provisioning.
 *
 * Guarded three ways: the admin role, the explicit `user:create` permission, and
 * a re-check inside `auth.service`. Redundant on purpose - this is the endpoint
 * that mints privilege, so a single missed middleware must not open it.
 */
authRoutes.post(
  '/register',
  authenticate,
  csrfProtection(),
  requireRole(ROLES.ADMIN),
  requirePermission(PERMISSIONS.USER_CREATE),
  sensitiveOperationLimiter,
  validate({ body: registerSchema }),
  asyncHandler(authController.register),
);

// --- Session self-service --------------------------------------------------

authRoutes.get(
  '/sessions',
  authenticate,
  requirePermission(PERMISSIONS.SESSION_READ_SELF),
  asyncHandler(sessionController.listMySessions),
);

authRoutes.delete(
  '/sessions/:sessionId',
  authenticate,
  csrfProtection(),
  requirePermission(PERMISSIONS.SESSION_REVOKE_SELF),
  validate({ params: sessionIdParamSchema }),
  asyncHandler(sessionController.revokeMySession),
);

// --- Device self-service ---------------------------------------------------

authRoutes.get(
  '/devices',
  authenticate,
  requirePermission(PERMISSIONS.DEVICE_READ_SELF),
  asyncHandler(deviceController.listMyDevices),
);

authRoutes.patch(
  '/devices/:deviceId',
  authenticate,
  csrfProtection(),
  requirePermission(PERMISSIONS.DEVICE_MANAGE_SELF),
  validate({ params: deviceIdParamSchema, body: renameDeviceSchema }),
  asyncHandler(deviceController.renameMyDevice),
);

authRoutes.delete(
  '/devices/:deviceId',
  authenticate,
  csrfProtection(),
  requirePermission(PERMISSIONS.DEVICE_MANAGE_SELF),
  validate({ params: deviceIdParamSchema }),
  asyncHandler(deviceController.revokeMyDevice),
);

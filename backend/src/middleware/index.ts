/** Barrel for the middleware layer. */

export { requestContext, deviceContext, accessLogger } from './request-context.middleware';
export {
  securityHeaders,
  apiContentSecurityPolicy,
  webContentSecurityPolicy,
  corsMiddleware,
  enforceHttps,
  requireJsonContentType,
} from './security.middleware';
export { createWebRouter, resolveWebRoot } from './web.middleware';
export {
  globalLimiter,
  loginAccountLimiter,
  loginIpLimiter,
  refreshLimiter,
  sensitiveOperationLimiter,
} from './rate-limit.middleware';
export { validate, type TypedRequest, type ValidationSchemas } from './validate.middleware';
export {
  authenticate,
  requireAuth,
} from './authenticate.middleware';
export {
  requireRole,
  requireMinRole,
  requirePermission,
  requireAnyPermission,
  requireSelfOrPermission,
  requireTrustedDevice,
} from './authorize.middleware';
export {
  notFoundHandler,
  errorHandler,
  installProcessErrorHandlers,
} from './error.middleware';
export { csrfProtection, issueCsrfToken } from './csrf.middleware';
export { ipAllowList, emergencyLockGuard } from './ip-allow-list.middleware';

import type { RequestHandler } from 'express';

import { csrfProtection } from './csrf.middleware';
import { emergencyLockGuard, ipAllowList } from './ip-allow-list.middleware';

/**
 * Security gates that must run *after* authentication.
 *
 * All three need `req.auth`:
 *
 *  - CSRF binds its token to the session id, which is what stops a token minted
 *    for one session being replayed on another.
 *  - The IP allow list has per-user and per-role scopes, and an administrator
 *    exemption. Evaluating it before authentication would silently reduce it to
 *    global rules only.
 *  - The emergency lock exempts administrators, so it has to know who is asking.
 *
 * Mounted per-router rather than globally for exactly that reason: Express runs
 * middleware in order, and every router authenticates itself.
 */
export function postAuthSecurityGates(): RequestHandler[] {
  return [csrfProtection(), ipAllowList(), emergencyLockGuard()];
}

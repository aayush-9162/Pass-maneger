/**
 * Authentication middleware.
 *
 * Establishes `req.auth` from a bearer access token. Three checks, in order:
 *
 *  1. **Cryptographic** - signature, issuer, audience, expiry, token type.
 *  2. **Stateful** - the session row must still be active, unexpired and not
 *     idle-timed-out. This is what makes revocation immediate: a stolen access
 *     token dies with its session, not at its own expiry.
 *  3. **Authorization data refresh** - permissions are re-derived from the role
 *     rather than trusted from the token body. Even if a token's permission array
 *     were somehow tampered with, the effective set comes from the role matrix.
 */

import { ERROR_CODES, isRoleName, permissionsForRole } from '@passm/shared';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

import { sessionService } from '../services/session.service';
import { extractBearerToken, verifyAccessToken } from '../services/token.service';
import { UnauthorizedError } from '../utils/errors';
import { asyncHandler } from '../utils/async-handler';

/**
 * Require a valid access token.
 *
 * On success `req.auth` is populated and `req.log` is re-bound with the user id
 * so every later log line for this request is attributable.
 */
export const authenticate: RequestHandler = asyncHandler(
  async (req: Request, _res: Response, next: NextFunction) => {
    const token = extractBearerToken(req.header('authorization'));

    if (!token) {
      throw new UnauthorizedError(
        'Authentication required. Provide a bearer access token.',
        ERROR_CODES.UNAUTHENTICATED,
      );
    }

    // Throws UnauthorizedError with TOKEN_EXPIRED / TOKEN_INVALID as appropriate;
    // clients branch on that code to decide "refresh" versus "sign in again".
    const claims = verifyAccessToken(token);

    if (!isRoleName(claims.role)) {
      // The signature was valid but the role is unknown - a stale token issued
      // before a role was removed. Fail closed.
      req.log.warn('Access token carries an unknown role', { role: claims.role });
      throw new UnauthorizedError('Your session is no longer valid.', ERROR_CODES.TOKEN_INVALID);
    }

    // Stateful check: revoked, expired or idle sessions are rejected here.
    await sessionService.validateForRequest(claims.sessionId, claims.userId);

    req.auth = {
      userId: claims.userId,
      email: claims.email,
      role: claims.role,
      // Authoritative permissions come from the role, not from the token.
      permissions: permissionsForRole(claims.role),
      sessionId: claims.sessionId,
      deviceRowId: claims.deviceRowId,
      deviceTrusted: claims.deviceTrusted,
      tokenId: claims.tokenId,
    };

    req.log = req.log.child({ userId: claims.userId, sessionId: claims.sessionId });

    // Sliding idle window. Fire-and-forget and internally throttled, so it never
    // adds latency to the request it belongs to.
    void sessionService.touch(claims.sessionId).catch((error: unknown) => {
      req.log.debug('Failed to record session activity', { error });
    });

    next();
  },
);

/**
 * Read `req.auth`, asserting it exists.
 *
 * Controllers behind {@link authenticate} use this instead of `req.auth!`, so a
 * route accidentally mounted without the middleware fails with a clear 401
 * rather than a `TypeError` on undefined.
 *
 * Takes only the `auth` property rather than a full `Request`, so it also
 * accepts the narrowed `TypedRequest` shapes whose validated `query` (with
 * coerced numbers) is deliberately not assignable to Express's `ParsedQs`.
 */
export function requireAuth(req: Pick<Request, 'auth'>): NonNullable<Request['auth']> {
  if (!req.auth) {
    throw new UnauthorizedError('Authentication required.', ERROR_CODES.UNAUTHENTICATED);
  }
  return req.auth;
}

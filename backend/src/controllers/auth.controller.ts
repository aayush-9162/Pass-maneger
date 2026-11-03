/**
 * Authentication controller.
 *
 * Controllers are intentionally thin: translate HTTP into a service call, decide
 * how tokens travel back (cookie versus body), and shape the response. All
 * policy lives in `auth.service`, which keeps the security rules testable without
 * an HTTP layer and impossible to bypass by adding a new route.
 *
 * ### How tokens travel
 *
 * - **Access token**: response body. The SPA holds it in memory only - never in
 *   `localStorage`, where any XSS could read it.
 * - **Refresh token**: httpOnly cookie for browsers, so script cannot reach it.
 *   Returned in the body only for the extension's service worker, which has no
 *   dependable cookie jar for cross-origin calls.
 * - **Device trust token**: httpOnly cookie, always.
 */

import type { Response } from 'express';

import type { GoogleSignInConfig, LoginResponse } from '@passm/shared';

import { env } from '../config/env';
import type {
  GoogleLoginDto,
  LogoutDto,
  RefreshDto,
  RegisterDto,
} from '../dto/auth.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import type { TypedRequest } from '../middleware/validate.middleware';
import { authService } from '../services/auth.service';
import { sendCreated, sendSuccess } from '../utils/api-response';
import {
  clearAuthCookies,
  readDeviceTrustCookie,
  readRefreshTokenCookie,
  setDeviceTrustCookie,
  setRefreshTokenCookie,
} from '../utils/cookies';
import { UnauthorizedError } from '../utils/errors';
import { ERROR_CODES } from '@passm/shared';
import { isNonCookieClient } from '../utils/request-context';

/**
 * POST /auth/google
 *
 * Public. The Google ID token is the credential; rate limited per IP.
 */
export async function googleLogin(req: TypedRequest<GoogleLoginDto>, res: Response): Promise<void> {
  const result = await authService.loginWithGoogle(req.body, req.context, {
    // The console and the extension reach the same endpoint; only the caller
    // knows which it is. Passed down so the service can apply the console
    // access policy without reading the request itself.
    fromExtension: isNonCookieClient(req),
    deviceIdentity: req.deviceIdentity ?? null,
    // An existing trust cookie can keep a device trusted without the user
    // re-checking "remember me" on every sign-in.
    trustCookie: readDeviceTrustCookie(req),
  });

  setRefreshTokenCookie(res, result.refreshToken, result.refreshTokenTtlSeconds);

  if (result.deviceTrust) {
    setDeviceTrustCookie(res, result.deviceTrust.token, result.deviceTrust.ttlSeconds);
  }

  const body: LoginResponse = result.response;

  if (isNonCookieClient(req)) {
    body.tokens.refreshToken = result.refreshToken;
  }

  sendSuccess(res, body);
}

/**
 * POST /auth/refresh
 *
 * Public (the refresh token is the credential). Rotates the token and detects
 * replay; see `session.service`.
 */
export async function refresh(req: TypedRequest<RefreshDto>, res: Response): Promise<void> {
  // Cookie first: for a browser client that is the only trustworthy source, and
  // preferring it means a stale token in the body cannot override a fresh cookie.
  const token = readRefreshTokenCookie(req) ?? req.body.refreshToken;

  if (!token) {
    throw new UnauthorizedError(
      'No refresh token was provided.',
      ERROR_CODES.UNAUTHENTICATED,
    );
  }

  const result = await authService.refresh(token, req.context);

  setRefreshTokenCookie(res, result.refreshToken, result.refreshTokenTtlSeconds);

  const body = { ...result.response };
  if (isNonCookieClient(req)) {
    body.tokens = { ...body.tokens, refreshToken: result.refreshToken };
  }

  sendSuccess(res, body);
}

/**
 * POST /auth/logout
 *
 * Cookies are cleared unconditionally, even if revocation found nothing to do:
 * a client that called logout must never be left holding a usable cookie.
 */
export async function logout(req: TypedRequest<LogoutDto>, res: Response): Promise<void> {
  const auth = requireAuth(req);

  const result = await authService.logout({
    auth,
    allDevices: req.body.allDevices,
    context: req.context,
  });

  clearAuthCookies(res);
  sendSuccess(res, result);
}

/** GET /auth/profile */
export async function profile(req: TypedRequest, res: Response): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, await authService.profile(auth));
}

/**
 * POST /auth/register
 *
 * Admin only: creates an account ahead of its owner's first Google sign-in.
 */
export async function register(req: TypedRequest<RegisterDto>, res: Response): Promise<void> {
  const auth = requireAuth(req);
  const user = await authService.register(req.body, auth, req.context);

  sendCreated(res, { user }, `/api/v1/admin/users/${user.id}`);
}

/**
 * GET /auth/google/config
 *
 * Public. The client id is not a secret - Google embeds it in every sign-in
 * page - and serving it from here means the console and extension need no
 * build-time configuration to match the server.
 */
export async function googleConfig(_req: TypedRequest, res: Response): Promise<void> {
  const body: GoogleSignInConfig = {
    clientId: env.google.clientId ?? null,
    hostedDomain: env.google.allowedDomains.length === 1 ? env.google.allowedDomains[0]! : null,
  };
  sendSuccess(res, body);
}

export const authController = {
  googleLogin,
  googleConfig,
  refresh,
  logout,
  profile,
  register,
};

/**
 * Cookie handling for the refresh token and the device-trust token.
 *
 * Why cookies for browser clients at all: an httpOnly cookie is unreadable by
 * JavaScript, so an XSS payload cannot exfiltrate the long-lived refresh token.
 * The short-lived access token is kept in memory by the SPA instead (never in
 * localStorage), which bounds the damage of a successful XSS to the access
 * token's lifetime.
 *
 * CSRF: cookies are set `SameSite=Lax` by default, and every state-changing
 * endpoint that trusts the cookie (`/refresh`, `/logout`) is additionally
 * protected by the CORS allow-list, which rejects credentialed cross-origin
 * requests from unknown origins.
 */

import { API_PREFIX, COOKIES } from '@passm/shared';
import type { CookieOptions, Request, Response } from 'express';

import { env } from '../config/env';

/**
 * Shared attributes. `path` is scoped to the API prefix so these cookies are
 * never attached to static asset requests.
 */
function baseOptions(maxAgeSeconds: number): CookieOptions {
  return {
    httpOnly: true,
    secure: env.cookies.secure,
    sameSite: env.cookies.sameSite,
    path: API_PREFIX,
    maxAge: maxAgeSeconds * 1000,
    ...(env.cookies.domain ? { domain: env.cookies.domain } : {}),
    // `signed` is unnecessary: both tokens are JWTs that the server verifies
    // cryptographically, and both are additionally bound to a database row.
  };
}

/**
 * Attributes for clearing a cookie.
 *
 * A browser only removes a cookie when the clearing response matches the
 * original attributes, so `path`/`domain`/`sameSite`/`secure` must be repeated
 * here. `maxAge` is deliberately absent - `res.clearCookie` sets its own expiry.
 */
function clearOptions(): CookieOptions {
  return {
    httpOnly: true,
    secure: env.cookies.secure,
    sameSite: env.cookies.sameSite,
    path: API_PREFIX,
    ...(env.cookies.domain ? { domain: env.cookies.domain } : {}),
  };
}

// ---------------------------------------------------------------------------
// Refresh token
// ---------------------------------------------------------------------------

export function setRefreshTokenCookie(res: Response, token: string, ttlSeconds: number): void {
  res.cookie(COOKIES.REFRESH_TOKEN, token, baseOptions(ttlSeconds));
}

export function clearRefreshTokenCookie(res: Response): void {
  res.clearCookie(COOKIES.REFRESH_TOKEN, clearOptions());
}

export function readRefreshTokenCookie(req: Request): string | undefined {
  const value = (req.cookies as Record<string, string> | undefined)?.[COOKIES.REFRESH_TOKEN];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

// ---------------------------------------------------------------------------
// Device trust ("remember this device")
// ---------------------------------------------------------------------------

export function setDeviceTrustCookie(res: Response, token: string, ttlSeconds: number): void {
  res.cookie(COOKIES.DEVICE_TRUST, token, baseOptions(ttlSeconds));
}

export function clearDeviceTrustCookie(res: Response): void {
  res.clearCookie(COOKIES.DEVICE_TRUST, clearOptions());
}

export function readDeviceTrustCookie(req: Request): string | undefined {
  const value = (req.cookies as Record<string, string> | undefined)?.[COOKIES.DEVICE_TRUST];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Remove every auth cookie. Used on logout and on any auth failure path. */
export function clearAuthCookies(res: Response): void {
  clearRefreshTokenCookie(res);
  clearDeviceTrustCookie(res);
}

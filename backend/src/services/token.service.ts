/**
 * JWT issuing and verification.
 *
 * Three token types, three independent signing keys (enforced by env.ts):
 *
 *  | Token        | Lifetime | Carries                    | Stored server-side |
 *  |--------------|----------|----------------------------|--------------------|
 *  | access       | 15m      | identity + permissions     | no                 |
 *  | refresh      | 7d       | session + rotation counter | HMAC in `sessions` |
 *  | device trust | 30d      | device binding             | HMAC in `devices`  |
 *
 * Hardening notes:
 *  - `algorithms: ['HS256']` is pinned on every verify. Omitting it is the
 *    classic algorithm-confusion vulnerability (a forged `alg: none` token).
 *  - Issuer and audience are checked, so a token minted for another service in
 *    the estate cannot be replayed here.
 *  - The `type` claim is checked explicitly: without it, a long-lived refresh
 *    token would be accepted as an access token.
 *  - Access tokens are stateless *but* the authenticate middleware still checks
 *    the session row, so revocation takes effect immediately rather than at
 *    token expiry.
 */

import { ERROR_CODES, TOKEN_TYPE, type Permission, type RoleName } from '@passm/shared';
import jwt, { type JwtPayload, type SignOptions } from 'jsonwebtoken';

import { env } from '../config/env';
import { InternalError, UnauthorizedError } from '../utils/errors';
import { newId } from '../utils/ids';
import { secondsFromNow } from '../utils/date';

const ALGORITHM = 'HS256' as const;

export interface AccessTokenInput {
  userId: string;
  email: string;
  role: RoleName;
  permissions: readonly Permission[];
  sessionId: string;
  deviceRowId: string;
  deviceTrusted: boolean;
}

export interface RefreshTokenInput {
  userId: string;
  sessionId: string;
  deviceRowId: string;
  /** Rotation counter; must match `sessions.refresh_token_generation`. */
  generation: number;
}

export interface DeviceTrustTokenInput {
  userId: string;
  deviceRowId: string;
  /** Client-reported device id, bound so the cookie cannot be moved elsewhere. */
  deviceId: string;
}

export interface IssuedToken {
  token: string;
  /** `jti`, so the caller can persist or log it. */
  tokenId: string;
  expiresAt: Date;
  expiresInSeconds: number;
}

/** Verified access-token claims, in the app's own vocabulary. */
export interface VerifiedAccessToken {
  userId: string;
  email: string;
  role: RoleName;
  permissions: Permission[];
  sessionId: string;
  deviceRowId: string;
  deviceTrusted: boolean;
  tokenId: string;
}

export interface VerifiedRefreshToken {
  userId: string;
  sessionId: string;
  deviceRowId: string;
  generation: number;
  tokenId: string;
}

export interface VerifiedDeviceTrustToken {
  userId: string;
  deviceRowId: string;
  deviceId: string;
  tokenId: string;
}

function baseSignOptions(subject: string, jwtid: string, expiresInSeconds: number): SignOptions {
  return {
    algorithm: ALGORITHM,
    issuer: env.jwt.issuer,
    audience: env.jwt.audience,
    subject,
    jwtid,
    // Seconds (a number) rather than a duration string: no dependency on how the
    // `ms` parser is typed across @types/jsonwebtoken releases.
    expiresIn: expiresInSeconds,
  };
}

/**
 * Translate a jsonwebtoken failure into an API error.
 *
 * Expiry is reported distinctly from invalidity because clients act on it: an
 * expired access token means "refresh and retry", while an invalid one means
 * "sign in again". Neither message reveals anything about the key.
 */
function toAuthError(error: unknown, what: string): UnauthorizedError {
  if (error instanceof jwt.TokenExpiredError) {
    return new UnauthorizedError(`${what} has expired.`, ERROR_CODES.TOKEN_EXPIRED);
  }
  if (error instanceof jwt.NotBeforeError) {
    return new UnauthorizedError(`${what} is not yet valid.`, ERROR_CODES.TOKEN_INVALID);
  }
  if (error instanceof jwt.JsonWebTokenError) {
    return new UnauthorizedError(`${what} is invalid.`, ERROR_CODES.TOKEN_INVALID);
  }
  return new UnauthorizedError(`${what} could not be verified.`, ERROR_CODES.TOKEN_INVALID);
}

/** Verify signature, issuer, audience and expiry; return the raw payload. */
function verify(token: string, secret: string, what: string): JwtPayload {
  let decoded: string | JwtPayload;
  try {
    decoded = jwt.verify(token, secret, {
      // Pinning the algorithm list is what prevents algorithm confusion.
      algorithms: [ALGORITHM],
      issuer: env.jwt.issuer,
      audience: env.jwt.audience,
    });
  } catch (error) {
    throw toAuthError(error, what);
  }

  if (typeof decoded === 'string') {
    throw new UnauthorizedError(`${what} is malformed.`, ERROR_CODES.TOKEN_INVALID);
  }
  return decoded;
}

/** Read a required string claim. */
function requireString(payload: JwtPayload, claim: string, what: string): string {
  const value = payload[claim];
  if (typeof value !== 'string' || value.length === 0) {
    throw new UnauthorizedError(`${what} is missing required data.`, ERROR_CODES.TOKEN_INVALID);
  }
  return value;
}

/** Reject a token whose `type` does not match, e.g. a refresh token sent as access. */
function assertTokenType(payload: JwtPayload, expected: string, what: string): void {
  if (payload.type !== expected) {
    throw new UnauthorizedError(`${what} is of the wrong type.`, ERROR_CODES.TOKEN_INVALID);
  }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

export function signAccessToken(input: AccessTokenInput): IssuedToken {
  const tokenId = newId();
  const expiresInSeconds = env.jwt.accessTtlSeconds;

  const token = jwt.sign(
    {
      type: TOKEN_TYPE.ACCESS,
      email: input.email,
      role: input.role,
      // Permissions are embedded so authorization needs no database round trip.
      // Safe because the token is short-lived and a role change revokes sessions.
      permissions: [...input.permissions],
      sid: input.sessionId,
      did: input.deviceRowId,
      trusted: input.deviceTrusted,
    },
    env.jwt.accessSecret,
    baseSignOptions(input.userId, tokenId, expiresInSeconds),
  );

  return { token, tokenId, expiresAt: secondsFromNow(expiresInSeconds), expiresInSeconds };
}

export function signRefreshToken(input: RefreshTokenInput): IssuedToken {
  const tokenId = newId();
  const expiresInSeconds = env.jwt.refreshTtlSeconds;

  const token = jwt.sign(
    {
      type: TOKEN_TYPE.REFRESH,
      sid: input.sessionId,
      did: input.deviceRowId,
      gen: input.generation,
    },
    env.jwt.refreshSecret,
    baseSignOptions(input.userId, tokenId, expiresInSeconds),
  );

  return { token, tokenId, expiresAt: secondsFromNow(expiresInSeconds), expiresInSeconds };
}

export function signDeviceTrustToken(input: DeviceTrustTokenInput): IssuedToken {
  const tokenId = newId();
  const expiresInSeconds = env.jwt.deviceTrustTtlSeconds;

  const token = jwt.sign(
    {
      type: TOKEN_TYPE.DEVICE_TRUST,
      did: input.deviceRowId,
      deviceId: input.deviceId,
    },
    env.jwt.deviceTrustSecret,
    baseSignOptions(input.userId, tokenId, expiresInSeconds),
  );

  return { token, tokenId, expiresAt: secondsFromNow(expiresInSeconds), expiresInSeconds };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export function verifyAccessToken(token: string): VerifiedAccessToken {
  const what = 'Access token';
  const payload = verify(token, env.jwt.accessSecret, what);
  assertTokenType(payload, TOKEN_TYPE.ACCESS, what);

  const rawPermissions = payload.permissions;

  return {
    userId: requireString(payload, 'sub', what),
    email: requireString(payload, 'email', what),
    role: requireString(payload, 'role', what) as RoleName,
    // Claims from the token are a *hint*; `authorize` re-resolves permissions
    // from the role, so a tampered list cannot escalate privilege.
    permissions: Array.isArray(rawPermissions)
      ? rawPermissions.filter((item): item is Permission => typeof item === 'string')
      : [],
    sessionId: requireString(payload, 'sid', what),
    /**
     * Read leniently. `devices.id` is nulled by an ON DELETE SET NULL when a
     * device row is pruned, so a still-valid session can legitimately have no
     * device. Rejecting the token in that case would sign the user out for a
     * housekeeping action. The device association is informational; the
     * authorization decision rests on `sid` and `role`.
     */
    deviceRowId: typeof payload.did === 'string' ? payload.did : '',
    deviceTrusted: payload.trusted === true,
    tokenId: requireString(payload, 'jti', what),
  };
}

export function verifyRefreshToken(token: string): VerifiedRefreshToken {
  const what = 'Refresh token';
  const payload = verify(token, env.jwt.refreshSecret, what);
  assertTokenType(payload, TOKEN_TYPE.REFRESH, what);

  const generation = payload.gen;
  if (typeof generation !== 'number' || !Number.isInteger(generation) || generation < 0) {
    throw new UnauthorizedError(`${what} is missing required data.`, ERROR_CODES.TOKEN_INVALID);
  }

  return {
    userId: requireString(payload, 'sub', what),
    sessionId: requireString(payload, 'sid', what),
    deviceRowId: requireString(payload, 'did', what),
    generation,
    tokenId: requireString(payload, 'jti', what),
  };
}

export function verifyDeviceTrustToken(token: string): VerifiedDeviceTrustToken {
  const what = 'Device trust token';
  const payload = verify(token, env.jwt.deviceTrustSecret, what);
  assertTokenType(payload, TOKEN_TYPE.DEVICE_TRUST, what);

  return {
    userId: requireString(payload, 'sub', what),
    deviceRowId: requireString(payload, 'did', what),
    deviceId: requireString(payload, 'deviceId', what),
    tokenId: requireString(payload, 'jti', what),
  };
}

/**
 * Extract a bearer token from the Authorization header.
 *
 * Rejects anything that is not exactly `Bearer <token>` - being lenient here
 * (accepting a bare token, or a differently-cased scheme) invites clients to
 * depend on the leniency and makes the parsing rules ambiguous.
 */
export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer (\S+)$/.exec(header.trim());
  return match?.[1] ?? null;
}

/** Decode without verifying - diagnostics only, never for an auth decision. */
export function unsafeDecode(token: string): JwtPayload | null {
  try {
    const decoded = jwt.decode(token);
    return decoded !== null && typeof decoded === 'object' ? decoded : null;
  } catch (error) {
    throw new InternalError('Failed to decode token.', { cause: error });
  }
}

export const tokenService = {
  signAccessToken,
  signRefreshToken,
  signDeviceTrustToken,
  verifyAccessToken,
  verifyRefreshToken,
  verifyDeviceTrustToken,
  extractBearerToken,
  unsafeDecode,
};

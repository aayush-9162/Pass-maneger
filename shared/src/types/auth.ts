/** Authentication request/response contracts and JWT claim shapes. */

import type { Permission } from '../constants/permissions';
import type { RoleName } from '../constants/roles';
import type { DeviceIdentity, DevicePlatform } from './device';
import type { PublicUser } from './user';

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/**
 * Sign in with Google.
 *
 * `credential` is the ID token Google Identity Services hands the browser (or
 * the extension's OAuth flow returns). The server verifies its signature,
 * audience, expiry and hosted domain; it is never stored.
 */
export interface GoogleLoginRequest {
  credential: string;
  /** "Remember this device" - issues a device-trust cookie on success. */
  rememberDevice?: boolean;
  /** Device metadata; may also be supplied via headers. */
  device?: DeviceIdentity;
}

/** What a client needs to render the Google sign-in button. Public. */
export interface GoogleSignInConfig {
  /** OAuth 2.0 web client id. Null when the server has not been configured. */
  clientId: string | null;
  /**
   * Google Workspace domain accounts must belong to, e.g. `123cfc.com`. Passed
   * to Google as a hint so the account chooser shows only matching accounts;
   * the server enforces it regardless.
   */
  hostedDomain: string | null;
}

/** Admin-only user provisioning. The user signs in with Google; there is no password. */
export interface RegisterRequest {
  email: string;
  firstName: string;
  lastName: string;
  role: RoleName;
  jobTitle?: string;
}

export interface RefreshRequest {
  /**
   * Optional - the refresh token is normally read from the httpOnly cookie.
   * Non-browser clients (the extension's background worker, CLI tooling) may
   * send it in the body instead.
   */
  refreshToken?: string;
}

export interface LogoutRequest {
  /** Revoke every session for the user, not just the current one. */
  allDevices?: boolean;
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

export interface TokenPair {
  accessToken: string;
  /** Seconds until `accessToken` expires. */
  expiresIn: number;
  tokenType: 'Bearer';
  /**
   * Only returned to non-cookie clients (browser extension). Browser clients
   * receive it as an httpOnly cookie and this field is omitted.
   */
  refreshToken?: string;
}

export interface LoginResponse {
  user: PublicUser;
  tokens: TokenPair;
  session: {
    id: string;
    expiresAt: string;
  };
  device: {
    id: string;
    deviceId: string;
    trusted: boolean;
    /** True when this device was seen for the first time during this login. */
    isNew: boolean;
    trustExpiresAt: string | null;
  };
}

export type RefreshResponse = Omit<LoginResponse, 'device'> & {
  device: { id: string; deviceId: string; trusted: boolean };
};

export interface ProfileResponse {
  user: PublicUser;
  session: {
    id: string;
    ipAddress: string | null;
    createdAt: string;
    lastActivityAt: string;
    expiresAt: string;
  };
  device: {
    id: string;
    deviceId: string;
    name: string;
    platform: DevicePlatform;
    trusted: boolean;
  } | null;
}

export interface LogoutResponse {
  revokedSessions: number;
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

/** Claims common to every token this system issues. */
interface BaseClaims {
  /** Subject: user id. */
  sub: string;
  /** JWT id - for refresh tokens this is the session's rotation id. */
  jti: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

export interface AccessTokenClaims extends BaseClaims {
  type: 'access';
  email: string;
  role: RoleName;
  permissions: Permission[];
  /** Session id this token belongs to; revoking the session kills the token. */
  sid: string;
  /** Device row id. */
  did: string;
  /** Whether the request's device is trusted (drives step-up decisions). */
  trusted: boolean;
}

export interface RefreshTokenClaims extends BaseClaims {
  type: 'refresh';
  sid: string;
  did: string;
  /** Monotonic rotation counter; a stale value means token replay. */
  gen: number;
}

export interface DeviceTrustClaims extends BaseClaims {
  type: 'device_trust';
  /** Device row id. */
  did: string;
  /** `deviceId` reported by the client, bound so the cookie cannot be moved. */
  deviceId: string;
}

export type AnyTokenClaims = AccessTokenClaims | RefreshTokenClaims | DeviceTrustClaims;

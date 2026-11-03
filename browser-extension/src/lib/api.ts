/**
 * API client for the service worker.
 *
 * Differs from the web console's client in one important way: the extension
 * cannot depend on cookies. A service worker's cross-origin `fetch` has no
 * reliable cookie jar for the API's origin, so it identifies itself with
 * `x-client-type: extension` and the API returns the refresh token in the JSON
 * body instead of a `Set-Cookie` header.
 *
 * That token is then kept in `chrome.storage.session` - memory-backed, never on
 * disk, unreachable from content scripts. See `lib/storage.ts`.
 *
 * Item listings carry no passwords. A password crosses this layer only from
 * `itemSecret`, one item at a time, and the server audits each one. There are
 * no write calls: the extension only uses passwords, it never changes them.
 */

import {
  ERROR_CODES,
  HEADERS,
  ROUTES,
  type ApiResponse,
  type GoogleSignInConfig,
  type LoginResponse,
  type MemberSharedVault,
  type ProfileResponse,
  type RefreshResponse,
  type SecretPurpose,
  type SharedItemSecret,
  type SharedVaultItem,
} from '@passm/shared';

import { getApiBaseUrl } from './server';
import { getOrCreateDeviceId } from './storage';

export class ExtensionApiError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number) {
    super(message);
    this.name = 'ExtensionApiError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/** Human readable device label, shown in the user's device list. */
function deviceName(): string {
  const ua = navigator.userAgent;
  const platform = /Windows/.test(ua)
    ? 'Windows'
    : /Mac OS X/.test(ua)
      ? 'macOS'
      : /CrOS/.test(ua)
        ? 'ChromeOS'
        : /Linux/.test(ua)
          ? 'Linux'
          : 'Unknown OS';

  return `PassM extension on ${platform}`;
}

async function buildHeaders(accessToken?: string): Promise<HeadersInit> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    // Tells the API to return tokens in the body rather than as cookies.
    'x-client-type': 'extension',
    [HEADERS.DEVICE_ID]: await getOrCreateDeviceId(),
    [HEADERS.DEVICE_NAME]: deviceName(),
  };

  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  return headers;
}

async function parse<T>(response: Response): Promise<T> {
  let payload: ApiResponse<T> | null = null;

  try {
    payload = (await response.json()) as ApiResponse<T>;
  } catch {
    throw new ExtensionApiError(
      `The server returned an unexpected response (${response.status}).`,
      ERROR_CODES.INTERNAL_ERROR,
      response.status,
    );
  }

  if (payload.success) return payload.data;

  throw new ExtensionApiError(payload.error.message, payload.error.code, response.status);
}

async function send<T>(
  path: string,
  init: {
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
    body?: unknown;
    accessToken?: string;
  },
): Promise<T> {
  let response: Response;

  try {
    response = await fetch(`${await getApiBaseUrl()}${path}`, {
      method: init.method,
      headers: await buildHeaders(init.accessToken),
      // No cookies: the extension carries tokens explicitly, and a stray cookie
      // must not authenticate a request the worker did not intend to.
      credentials: 'omit',
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });
  } catch {
    throw new ExtensionApiError(
      'Cannot reach the PassM server. Check your connection or VPN.',
      ERROR_CODES.SERVICE_UNAVAILABLE,
      0,
    );
  }

  return parse<T>(response);
}

export const extensionApi = {
  // --- Authentication ------------------------------------------------------

  /** The OAuth client id and hosted domain to request Google's ID token with. */
  googleConfig: () =>
    send<GoogleSignInConfig>(ROUTES.AUTH.GOOGLE_CONFIG, { method: 'GET' }),

  /**
   * Sign in with a Google ID token. Device metadata travels in the headers
   * rather than the body, so the request stays identical in shape to every
   * other call the worker makes.
   */
  googleLogin: (credential: string, rememberDevice: boolean) =>
    send<LoginResponse>(ROUTES.AUTH.GOOGLE, {
      method: 'POST',
      body: { credential, rememberDevice },
    }),

  /** Shared vaults this user is a member of, with their rights on each. */
  sharedVaults: (accessToken: string) =>
    send<{ vaults: MemberSharedVault[] }>(ROUTES.SHARED.VAULTS, {
      method: 'GET',
      accessToken,
    }),

  /** Items inside one shared vault, without their passwords. */
  sharedItems: (accessToken: string, vaultId: string) =>
    send<{ items: SharedVaultItem[]; total: number }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/items?pageSize=100`,
      { method: 'GET', accessToken },
    ),

  /** One item's password and TOTP seed. Audited by the server with `purpose`. */
  itemSecret: (accessToken: string, vaultId: string, itemId: string, purpose: SecretPurpose) =>
    send<{ secret: SharedItemSecret }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/items/${itemId}/secret?purpose=${purpose}`,
      { method: 'GET', accessToken },
    ).then((result) => result.secret),

  /**
   * Report something this client observed - a refused reveal, a tampered field.
   *
   * Fire-and-forget by design: the local response - re-masking a field, refusing
   * a reveal - has already happened, and a failure to record it must never turn
   * into an error the user sees instead.
   */
  reportAccessEvent: (
    accessToken: string,
    event: { action: 'reveal_blocked'; itemId: string; field?: 'password'; host?: string },
  ) =>
    send<{ recorded: number }>(ROUTES.SHARED.ACCESS_EVENTS, {
      method: 'POST',
      body: { events: [event] },
      accessToken,
    }).catch(() => ({ recorded: 0 })),

  /** Exchange a refresh token for a new pair. The response rotates both. */
  refresh: (refreshToken: string) =>
    send<RefreshResponse>(ROUTES.AUTH.REFRESH, {
      method: 'POST',
      body: { refreshToken },
    }),

  logout: (accessToken: string, refreshToken: string) =>
    send<{ revokedSessions: number }>(ROUTES.AUTH.LOGOUT, {
      method: 'POST',
      body: { allDevices: false, refreshToken },
      accessToken,
    }),

  profile: (accessToken: string) =>
    send<ProfileResponse>(ROUTES.AUTH.PROFILE, { method: 'GET', accessToken }),
};

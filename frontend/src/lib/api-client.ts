/**
 * API client.
 *
 * ## Where the tokens live
 *
 * The access token is held in a module-scoped variable - deliberately *not* in
 * `localStorage` or `sessionStorage`. Anything in web storage is readable by any
 * script on the page, so a single XSS flaw would hand an attacker a working
 * token. In memory it dies with the tab, and a page reload transparently
 * recovers a new one from the refresh cookie.
 *
 * The refresh token is never visible to this code at all: it is an httpOnly
 * cookie set by the API, which is why every request sets `credentials:
 * 'include'`.
 *
 * ## Transparent refresh
 *
 * A 401 carrying `TOKEN_EXPIRED` triggers one refresh attempt and one retry.
 * Concurrent 401s share a single in-flight refresh (see {@link refreshSession}),
 * so a page that fires five requests at once does not perform five rotations -
 * which, with refresh-token rotation and replay detection, would revoke the
 * session and sign the user out.
 */

import {
  COOKIES,
  ERROR_CODES,
  HEADERS,
  ROUTES,
  type ApiResponse,
  type DeviceInfo,
  type ErrorCode,
  type GoogleLoginRequest,
  type GoogleSignInConfig,
  type LoginResponse,
  type PaginatedResult,
  type ProfileResponse,
  type PublicUser,
  type RefreshResponse,
  type RoleName,
  type SessionInfo,
  type AdminUserListItem,
  type AuditLogEntry,
  type ApiFieldError,
  type AdminDashboardStats,
  type AdminDeviceRow,
  type AdminSessionRow,
  type AdminUserDetail,
  type CreateGrantRequest,
  type CreateSharedItemRequest,
  type CreateSharedVaultRequest,
  type MemberSharedVault,
  type MoveSharedItemRequest,
  type PasswordHealthFinding,
  type PasswordHealthReport,
  type PasswordHealthSummary,
  type RoleSummary,
  type SecretPurpose,
  type SecurityDashboard,
  type SharedVault,
  type SharedVaultGrant,
  type SharedItemSecret,
  type SharedVaultItem,
  type SubmitHealthReportRequest,
  type UpdateGrantRequest,
  type UpdateSharedItemRequest,
  type UpdateSharedVaultRequest,
  type AccessRequest,
  type AccessRequestDecision,
  type AuditEntryView,
  type AuditSearchQuery,
  type CreateAccessRequestBody,
  type DecideAccessRequestBody,
  type ReportAccessEventBody,
  type ClientSecuritySettings,
  type CreateIpRuleRequest,
  type EmergencyLockRequest,
  type EmergencyLockState,
  type IpCheckResult,
  type IpRule,
  type SecurityNotification,
  type SecurityScore,
  type SecuritySettings,
  type SecuritySettingsResponse,
  type StepUpAction,
  type StepUpChallenge,
  type StepUpStatus,
} from '@passm/shared';

import { getDeviceFingerprint, getDeviceId, getDeviceName } from './device';

export const API_BASE_URL = (
  import.meta.env.VITE_API_URL ?? 'http://localhost:4000/api/v1'
).replace(/\/$/, '');

/** Error carrying the API's machine-readable code, so callers can branch on it. */
export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly details: ApiFieldError[];
  readonly requestId: string;
  readonly retryAfter?: number;

  constructor(
    message: string,
    code: ErrorCode,
    statusCode: number,
    options: { details?: ApiFieldError[]; requestId?: string; retryAfter?: number } = {},
  ) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = options.details ?? [];
    this.requestId = options.requestId ?? 'unknown';
    this.retryAfter = options.retryAfter;
  }

  /** Field-level message for a form input, if the API reported one. */
  fieldError(field: string): string | undefined {
    return this.details.find((detail) => detail.field.endsWith(field))?.message;
  }
}

// ---------------------------------------------------------------------------
// Access token (memory only)
// ---------------------------------------------------------------------------

let accessToken: string | null = null;

/** Called by the auth context after login and after each refresh. */
export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

// ---------------------------------------------------------------------------
// Request plumbing
// ---------------------------------------------------------------------------

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  /** Attach the bearer token (default true). */
  authenticated?: boolean;
  /** Refresh once and retry on an expired token (default true). */
  retryOnExpiry?: boolean;
  signal?: AbortSignal;
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

/**
 * Read the CSRF token from its cookie.
 *
 * The cookie is deliberately not `httpOnly` - same-origin script has to read it
 * to echo it back in a header, and that asymmetry is the entire mechanism: a
 * cross-origin page can *cause* the cookie to be sent but cannot read it, so it
 * cannot produce the header.
 */
function readCsrfCookie(): string | null {
  if (typeof document === 'undefined') return null;

  const prefix = `${COOKIES.CSRF_TOKEN}=`;
  for (const part of document.cookie.split('; ')) {
    if (part.startsWith(prefix)) return decodeURIComponent(part.slice(prefix.length));
  }
  return null;
}

/** In-flight token fetch, so a burst of writes triggers one request, not N. */
let csrfInFlight: Promise<string | null> | null = null;

/**
 * Ensure a CSRF token exists, fetching one if not.
 *
 * The token is bound to the current session id server-side, so it must be
 * fetched *after* signing in - a token minted for another session, or for none,
 * is refused. {@link login} and {@link refreshSession} both call this.
 */
export async function ensureCsrfToken(force = false): Promise<string | null> {
  if (!force) {
    const existing = readCsrfCookie();
    if (existing) return existing;
  }

  if (csrfInFlight) return csrfInFlight;

  csrfInFlight = (async () => {
    try {
      const response = await fetch(`${API_BASE_URL}${ROUTES.SECURITY.CSRF_TOKEN}`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        },
      });

      if (!response.ok) return null;
      const payload = (await response.json()) as ApiResponse<{ token: string }>;
      return payload.success ? payload.data.token : null;
    } catch {
      // Offline, or the endpoint is unreachable. The request that needed the
      // token will fail with a clear CSRF error rather than a confusing one.
      return null;
    } finally {
      csrfInFlight = null;
    }
  })();

  return csrfInFlight;
}

/** Methods that change state and therefore need a token. */
const CSRF_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

async function buildHeaders(
  authenticated: boolean,
  hasBody: boolean,
  method: string,
): Promise<HeadersInit> {
  const headers: Record<string, string> = { Accept: 'application/json' };

  if (hasBody) headers['Content-Type'] = 'application/json';
  if (authenticated && accessToken) headers.Authorization = `Bearer ${accessToken}`;

  if (CSRF_METHODS.has(method)) {
    const csrf = await ensureCsrfToken();
    if (csrf) headers[HEADERS.CSRF_TOKEN] = csrf;
  }

  // Device headers accompany every request so the API can keep "last seen"
  // metadata current and spot a fingerprint change on any call, not just login.
  const deviceId = getDeviceId();
  if (deviceId) {
    headers[HEADERS.DEVICE_ID] = deviceId;
    headers[HEADERS.DEVICE_NAME] = getDeviceName();

    const fingerprint = await getDeviceFingerprint();
    if (fingerprint) headers[HEADERS.DEVICE_FINGERPRINT] = fingerprint;
  }

  return headers;
}

/** Parse the response envelope, converting a failure into an {@link ApiError}. */
async function parseResponse<T>(response: Response): Promise<T> {
  let payload: ApiResponse<T> | null = null;

  try {
    payload = (await response.json()) as ApiResponse<T>;
  } catch {
    // 204, or a proxy returning HTML instead of JSON.
    if (response.ok) return undefined as T;
    throw new ApiError(
      `The server returned an unexpected response (${response.status}).`,
      ERROR_CODES.INTERNAL_ERROR,
      response.status,
    );
  }

  if (payload && payload.success) return payload.data;

  const error = payload?.error;
  throw new ApiError(
    error?.message ?? 'The request failed.',
    error?.code ?? ERROR_CODES.INTERNAL_ERROR,
    response.status,
    {
      details: error?.details ?? [],
      requestId: payload?.requestId ?? 'unknown',
      ...(error?.retryAfter !== undefined ? { retryAfter: error.retryAfter } : {}),
    },
  );
}

/** In-flight refresh, shared by every caller that hits a 401 at the same time. */
let refreshInFlight: Promise<boolean> | null = null;

/** Listeners notified when the session ends and the user must sign in again. */
const sessionEndedListeners = new Set<() => void>();

export function onSessionEnded(listener: () => void): () => void {
  sessionEndedListeners.add(listener);
  return () => sessionEndedListeners.delete(listener);
}

function notifySessionEnded(): void {
  accessToken = null;
  for (const listener of sessionEndedListeners) listener();
}

/**
 * Exchange the refresh cookie for a new access token.
 *
 * @returns `true` when a new access token is in place.
 */
export async function refreshSession(): Promise<boolean> {
  // Collapse concurrent attempts: rotation means a second, parallel refresh
  // would present an already-redeemed token and trip replay detection.
  refreshInFlight ??= (async () => {
    try {
      const response = await fetch(`${API_BASE_URL}${ROUTES.AUTH.REFRESH}`, {
        method: 'POST',
        credentials: 'include',
        headers: await buildHeaders(false, true, 'POST'),
        body: JSON.stringify({}),
      });

      const data = await parseResponse<RefreshResponse>(response);
      setAccessToken(data.tokens.accessToken);
      return true;
    } catch {
      // Any failure here means the refresh cookie is gone, expired or revoked.
      setAccessToken(null);
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const {
    method = 'GET',
    body,
    authenticated = true,
    retryOnExpiry = true,
    signal,
  } = options;

  const hasBody = body !== undefined && method !== 'GET';

  const send = async (): Promise<Response> =>
    fetch(`${API_BASE_URL}${path}`, {
      method,
      // Required for the httpOnly refresh cookie to travel with the request.
      credentials: 'include',
      headers: await buildHeaders(authenticated, hasBody, method),
      ...(hasBody ? { body: JSON.stringify(body) } : {}),
      ...(signal ? { signal } : {}),
    });

  let response: Response;
  try {
    response = await send();
  } catch (error) {
    // Network-level failure: DNS, connection refused, CORS block.
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError(
      'Cannot reach the server. Check your connection and try again.',
      ERROR_CODES.SERVICE_UNAVAILABLE,
      0,
    );
  }

  /**
   * One transparent recovery for a stale CSRF token.
   *
   * The token is bound to the session, so it goes stale whenever the session
   * changes underneath the tab - most often after a refresh in another tab, or
   * when the cookie is dropped by a browser clearing site data. Fetching a fresh
   * one and retrying once turns a confusing "reload the page" error into
   * something the user never sees. A second failure is surfaced.
   */
  if (response.status === 403 && CSRF_METHODS.has(method)) {
    const cloned = response.clone();
    let code: ErrorCode | undefined;
    try {
      const payload = (await cloned.json()) as ApiResponse<never>;
      code = payload.success ? undefined : payload.error.code;
    } catch {
      code = undefined;
    }

    if (code === ERROR_CODES.CSRF_TOKEN_INVALID) {
      const refreshed = await ensureCsrfToken(true);
      if (refreshed) response = await send();
    }
  }

  // One transparent refresh + retry for an expired access token.
  if (response.status === 401 && authenticated && retryOnExpiry) {
    const cloned = response.clone();
    let code: ErrorCode | undefined;
    try {
      const payload = (await cloned.json()) as ApiResponse<never>;
      code = payload.success ? undefined : payload.error.code;
    } catch {
      code = undefined;
    }

    if (code === ERROR_CODES.TOKEN_EXPIRED || code === ERROR_CODES.UNAUTHENTICATED) {
      if (await refreshSession()) {
        response = await send();
      } else {
        notifySessionEnded();
      }
    } else if (
      code === ERROR_CODES.SESSION_REVOKED ||
      code === ERROR_CODES.REFRESH_TOKEN_REUSED ||
      code === ERROR_CODES.TOKEN_INVALID
    ) {
      // Not recoverable by refreshing: the session is gone.
      notifySessionEnded();
    }
  }

  return parseResponse<T>(response);
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export interface CreateUserPayload {
  /** The person's Google Workspace address - how they will sign in. */
  email: string;
  firstName: string;
  lastName: string;
  role: RoleName;
  jobTitle?: string;
}

export interface ListUsersParams {
  page?: number;
  pageSize?: number;
  search?: string;
  role?: RoleName;
  status?: string;
  groupId?: string;
  hasMasterPassword?: boolean;
  sortBy?: string;
  sortDir?: 'asc' | 'desc';
}

/** Shared shape of every paginated admin list request. */
export interface AdminListParams {
  page?: number;
  pageSize?: number;
  search?: string;
  sortBy?: string;
  sortDir?: 'asc' | 'desc';
}

/**
 * Build a query string, omitting empty values.
 *
 * Takes an index-signature-free object type so the concrete param interfaces
 * (which have known keys, not an index signature) can be passed directly.
 */
function toQuery(params: object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '') continue;
    search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : '';
}

export const api = {
  // --- Authentication ------------------------------------------------------

  /** What the Google sign-in button needs. Public. */
  getGoogleConfig: () =>
    request<GoogleSignInConfig>(ROUTES.AUTH.GOOGLE_CONFIG, { authenticated: false }),

  /** Sign in with the ID token Google handed the browser. */
  async loginWithGoogle(payload: GoogleLoginRequest): Promise<LoginResponse> {
    const data = await request<LoginResponse>(ROUTES.AUTH.GOOGLE, {
      method: 'POST',
      body: payload,
      authenticated: false,
      retryOnExpiry: false,
    });

    setAccessToken(data.tokens.accessToken);

    // The CSRF token is bound to the session id, so the one this tab may
    // already hold belongs to a session that no longer exists. Fetch a fresh
    // one now rather than letting the first write of the session fail and
    // recover.
    await ensureCsrfToken(true);

    return data;
  },

  async logout(allDevices = false): Promise<{ revokedSessions: number }> {
    try {
      return await request<{ revokedSessions: number }>(ROUTES.AUTH.LOGOUT, {
        method: 'POST',
        body: { allDevices },
        retryOnExpiry: false,
      });
    } finally {
      // Always drop the local token: whatever the server said, this client is
      // finished with the session.
      setAccessToken(null);
    }
  },

  refresh: refreshSession,

  getProfile: () => request<ProfileResponse>(ROUTES.AUTH.PROFILE),

  // --- Self-service sessions and devices ----------------------------------

  listSessions: () => request<{ sessions: SessionInfo[] }>(ROUTES.AUTH.SESSIONS),

  revokeSession: (sessionId: string) =>
    request<{ revoked: boolean; wasCurrentSession: boolean }>(
      `${ROUTES.AUTH.SESSIONS}/${sessionId}`,
      { method: 'DELETE' },
    ),

  listDevices: () => request<{ devices: DeviceInfo[] }>(ROUTES.AUTH.DEVICES),

  renameDevice: (deviceId: string, name: string) =>
    request<{ device: DeviceInfo }>(`${ROUTES.AUTH.DEVICES}/${deviceId}`, {
      method: 'PATCH',
      body: { name },
    }),

  revokeDevice: (deviceId: string) =>
    request<{ device: DeviceInfo; wasCurrentDevice: boolean }>(
      `${ROUTES.AUTH.DEVICES}/${deviceId}`,
      { method: 'DELETE' },
    ),

  // --- Administration ------------------------------------------------------

  /**
   * Create an account ahead of its owner's first Google sign-in.
   *
   * No password: the person signs in with the Google account at this address.
   */
  createUser: (payload: CreateUserPayload) =>
    request<{ user: PublicUser }>(ROUTES.AUTH.REGISTER, {
      method: 'POST',
      body: {
        email: payload.email,
        firstName: payload.firstName,
        lastName: payload.lastName,
        role: payload.role,
        ...(payload.jobTitle ? { jobTitle: payload.jobTitle } : {}),
      },
    }),

  listUsers: (params: ListUsersParams = {}) =>
    request<PaginatedResult<AdminUserListItem>>(`${ROUTES.ADMIN.USERS}${toQuery(params)}`),

  changeUserRole: (userId: string, role: RoleName, revokeSessions = true) =>
    request<{ user: PublicUser }>(`${ROUTES.ADMIN.USERS}/${userId}/role`, {
      method: 'PUT',
      body: { role, revokeSessions },
    }),

  changeUserStatus: (userId: string, status: 'active' | 'suspended', reason?: string) =>
    request<{ user: PublicUser }>(`${ROUTES.ADMIN.USERS}/${userId}/status`, {
      method: 'PUT',
      body: reason ? { status, reason } : { status },
    }),

  listUserSessions: (userId: string) =>
    request<{ sessions: SessionInfo[] }>(`${ROUTES.ADMIN.USERS}/${userId}/sessions`),

  revokeUserSessions: (userId: string) =>
    request<{ revokedSessions: number }>(`${ROUTES.ADMIN.USERS}/${userId}/sessions`, {
      method: 'DELETE',
    }),

  listUserDevices: (userId: string) =>
    request<{ devices: DeviceInfo[] }>(`${ROUTES.ADMIN.USERS}/${userId}/devices`),

  getUserDetail: (userId: string) =>
    request<{ user: AdminUserDetail }>(`${ROUTES.ADMIN.USERS}/${userId}`),

  lockUser: (userId: string, payload: { reason: string; until?: string; revokeSessions?: boolean }) =>
    request<{ user: PublicUser; revokedSessions: number }>(
      `${ROUTES.ADMIN.USERS}/${userId}/lock`,
      { method: 'PUT', body: payload },
    ),

  unlockUser: (userId: string, note?: string) =>
    request<{ user: PublicUser }>(`${ROUTES.ADMIN.USERS}/${userId}/unlock`, {
      method: 'PUT',
      body: note ? { note } : {},
    }),

  /** Full account deletion: sessions ended, access revoked, email freed for reuse. */
  deleteUser: (userId: string) =>
    request<{
      revokedSessions: number;
      revokedGrants: number;
      message: string;
    }>(`${ROUTES.ADMIN.USERS}/${userId}`, { method: 'DELETE' }),

  listRoles: () => request<{ roles: RoleSummary[] }>(ROUTES.ADMIN.ROLES),

  // --- Audit search, export and approvals (Phase 5) ------------------------

  /**
   * Full audit search with names resolved server-side.
   *
   * Distinct from `listAuditLogs`: this one joins actor, target, device and
   * resource so a row for a departed employee still reads as a name rather than
   * an id, and it applies the personal-activity screen for callers without
   * `audit:read:personal`.
   */
  searchAudit: (params: AuditSearchQuery = {}) =>
    request<PaginatedResult<AuditEntryView>>(`${ROUTES.ADMIN.AUDIT_SEARCH}${toQuery(params)}`),

  auditFacets: (windowDays = 30) =>
    request<{
      actions: { action: string; count: number }[];
      addresses: { ipAddress: string; count: number }[];
      devices: { deviceId: string; name: string; count: number }[];
    }>(`${ROUTES.ADMIN.AUDIT_FACETS}${toQuery({ windowDays })}`),

  /**
   * The export URL, for a plain anchor download.
   *
   * Returned rather than fetched because the response is streamed with a
   * `Content-Disposition` header - letting the browser handle it avoids buffering
   * tens of megabytes into a Blob just to hand it straight back.
   *
   * The access token lives in memory only, so this cannot carry an Authorization
   * header; the caller opens it through `downloadAuditExport` below instead.
   */
  auditExportUrl: (params: Record<string, string | number | boolean | undefined> = {}) =>
    `${API_BASE_URL}${ROUTES.ADMIN.AUDIT_EXPORT}${toQuery(params)}`,

  /**
   * Download the export.
   *
   * Fetched with the bearer token and handed to the browser as an object URL.
   * The cap is server-side, so this cannot pull more than the API allows.
   */
  downloadAuditExport: async (
    params: Record<string, string | number | boolean | undefined> = {},
  ): Promise<{ blob: Blob; filename: string }> => {
    const response = await fetch(`${API_BASE_URL}${ROUTES.ADMIN.AUDIT_EXPORT}${toQuery(params)}`, {
      credentials: 'include',
      headers: {
        ...(getAccessToken() ? { Authorization: `Bearer ${getAccessToken()}` } : {}),
        Accept: 'text/csv, application/json',
      },
    });

    if (!response.ok) {
      throw new ApiError(
        response.status === 403
          ? 'Only administrators can export the audit log.'
          : `The export failed (${response.status}).`,
        ERROR_CODES.FORBIDDEN,
        response.status,
      );
    }

    const disposition = response.headers.get('Content-Disposition') ?? '';
    const match = /filename="([^"]+)"/.exec(disposition);

    return {
      blob: await response.blob(),
      filename: match?.[1] ?? 'passm-audit.csv',
    };
  },

  listApprovals: (params: AdminListParams & { status?: string; view?: 'inbox' | 'mine' } = {}) =>
    request<PaginatedResult<AccessRequest>>(`${ROUTES.SHARED.REQUESTS}${toQuery(params)}`),

  pendingApprovalCount: () =>
    request<{ pending: number }>(`${ROUTES.SHARED.REQUESTS}/pending-count`),

  createAccessRequest: (vaultId: string, payload: CreateAccessRequestBody) =>
    request<{ request: AccessRequest }>(`${ROUTES.SHARED.VAULTS}/${vaultId}/requests`, {
      method: 'POST',
      body: payload,
    }),

  decideAccessRequest: (requestId: string, payload: DecideAccessRequestBody) =>
    request<AccessRequestDecision>(`${ROUTES.SHARED.REQUESTS}/${requestId}/decide`, {
      method: 'POST',
      body: payload,
    }),

  cancelAccessRequest: (requestId: string) =>
    request<{ request: AccessRequest }>(`${ROUTES.SHARED.REQUESTS}/${requestId}`, {
      method: 'DELETE',
    }),

  /**
   * Report what this client refused or observed - a blocked reveal, say.
   *
   * Fire-and-forget from the caller's point of view: a failure to record an
   * access event must never block the user.
   */
  reportAccessEvents: (events: ReportAccessEventBody[]) =>
    request<{ recorded: number }>(ROUTES.SHARED.ACCESS_EVENTS, {
      method: 'POST',
      body: { events },
    }).catch(() => ({ recorded: 0 })),

  listAuditLogs: (
    params: AdminListParams & {
      action?: string;
      outcome?: 'success' | 'failure';
      actorUserId?: string;
      targetUserId?: string;
      from?: string;
      to?: string;
    } = {},
  ) => request<PaginatedResult<AuditLogEntry>>(`${ROUTES.ADMIN.AUDIT}${toQuery(params)}`),

  // People-groups are gone: a "group" is a set of passwords - a shared vault
  // of kind `group` - managed through the shared-vault calls below.

  // --- Dashboard, security, sessions and devices ---------------------------

  getDashboard: (windowDays = 30) =>
    request<AdminDashboardStats>(`${ROUTES.ADMIN.DASHBOARD}${toQuery({ windowDays })}`),

  getSecurityDashboard: (windowDays = 30) =>
    request<SecurityDashboard>(`${ROUTES.ADMIN.SECURITY}${toQuery({ windowDays })}`),

  listAllSessions: (params: AdminListParams & { userId?: string; status?: string } = {}) =>
    request<PaginatedResult<AdminSessionRow>>(`${ROUTES.ADMIN.SESSIONS}${toQuery(params)}`),

  revokeSessionById: (sessionId: string) =>
    request<{ revoked: boolean; userId: string | null }>(
      `${ROUTES.ADMIN.SESSIONS}/${sessionId}`,
      { method: 'DELETE' },
    ),

  listAllDevices: (
    params: AdminListParams & { userId?: string; status?: string; platform?: string } = {},
  ) => request<PaginatedResult<AdminDeviceRow>>(`${ROUTES.ADMIN.DEVICES}${toQuery(params)}`),

  revokeDeviceById: (deviceId: string) =>
    request<{ device: DeviceInfo }>(`${ROUTES.ADMIN.DEVICES}/${deviceId}`, { method: 'DELETE' }),

  // --- Password health ------------------------------------------------------

  getHealthSummary: () =>
    request<PasswordHealthSummary>(`${ROUTES.ADMIN.HEALTH}/summary`),

  listHealthReports: (
    params: AdminListParams & { maxScore?: number; issue?: string } = {},
  ) => request<PaginatedResult<PasswordHealthReport>>(`${ROUTES.ADMIN.HEALTH}${toQuery(params)}`),

  getUserHealthReport: (userId: string) =>
    request<{ report: PasswordHealthReport | null; findings: PasswordHealthFinding[] }>(
      `${ROUTES.ADMIN.HEALTH}/${userId}`,
    ),

  /** The caller's own report. */
  getOwnHealthReport: () =>
    request<{
      report: PasswordHealthReport | null;
      findings: PasswordHealthFinding[];
      staleAfterDays: number;
    }>(ROUTES.VAULT.HEALTH),

  submitHealthReport: (payload: SubmitHealthReportRequest) =>
    request<{ report: PasswordHealthReport }>(ROUTES.VAULT.HEALTH, {
      method: 'POST',
      body: payload,
    }),

  // --- Shared vaults --------------------------------------------------------
  //
  // Items travel as plaintext over TLS and are encrypted by the server. The
  // listing carries no passwords; `getSharedItemSecret` fetches one at a time.

  listSharedVaultsAdmin: (
    params: AdminListParams & {
      status?: string;
      kind?: 'group' | 'item';
    } = {},
  ) => request<PaginatedResult<SharedVault>>(`/admin/shared-vaults${toQuery(params)}`),

  getSharedVaultAdmin: (vaultId: string) =>
    request<{ vault: SharedVault }>(`/admin/shared-vaults/${vaultId}`),

  getSharedVaultAccessAdmin: (vaultId: string) =>
    request<{ grants: SharedVaultGrant[] }>(`/admin/shared-vaults/${vaultId}/access`),

  /** The caller's own shared vaults, with their rights on each. */
  listMySharedVaults: () =>
    request<{ vaults: MemberSharedVault[] }>(ROUTES.SHARED.VAULTS),

  createSharedVault: (payload: CreateSharedVaultRequest) =>
    request<{ vault: SharedVault }>(ROUTES.SHARED.VAULTS, { method: 'POST', body: payload }),

  updateSharedVault: (vaultId: string, payload: UpdateSharedVaultRequest) =>
    request<{ vault: SharedVault }>(`${ROUTES.SHARED.VAULTS}/${vaultId}`, {
      method: 'PATCH',
      body: payload,
    }),

  deleteSharedVault: (vaultId: string) =>
    request<{ revokedGrants: number; message: string }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}`,
      { method: 'DELETE' },
    ),

  getSharedVaultAccess: (vaultId: string) =>
    request<{ grants: SharedVaultGrant[] }>(`${ROUTES.SHARED.VAULTS}/${vaultId}/access`),

  addSharedVaultGrant: (vaultId: string, payload: CreateGrantRequest) =>
    request<{ grants: SharedVaultGrant[] }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/grants`,
      { method: 'POST', body: payload },
    ),

  updateSharedVaultGrant: (vaultId: string, grantId: string, payload: UpdateGrantRequest) =>
    request<{ grants: SharedVaultGrant[] }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/grants/${grantId}`,
      { method: 'PATCH', body: payload },
    ),

  revokeSharedVaultGrant: (vaultId: string, grantId: string) =>
    request<{ grants: SharedVaultGrant[]; message: string }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/grants/${grantId}`,
      { method: 'DELETE' },
    ),

  listSharedItems: (
    vaultId: string,
    params: AdminListParams & { type?: string; includeDeleted?: boolean } = {},
  ) =>
    request<PaginatedResult<SharedVaultItem>>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/items${toQuery(params)}`,
    ),

  createSharedItem: (vaultId: string, payload: CreateSharedItemRequest) =>
    request<{ item: SharedVaultItem }>(`${ROUTES.SHARED.VAULTS}/${vaultId}/items`, {
      method: 'POST',
      body: payload,
    }),

  /** An individual password: the server wraps it in a vault of its own. */
  createIndividualItem: (payload: CreateSharedItemRequest) =>
    request<{ item: SharedVaultItem }>(ROUTES.SHARED.ITEMS, { method: 'POST', body: payload }),

  /** One item's password. Audited by the server with `purpose`. */
  getSharedItemSecret: (vaultId: string, itemId: string, purpose: SecretPurpose) =>
    request<{ secret: SharedItemSecret }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/items/${itemId}/secret${toQuery({ purpose })}`,
    ).then((result) => result.secret),

  /** Move to another group, or out to stand alone (`targetVaultId: null`). */
  moveSharedItem: (vaultId: string, itemId: string, payload: MoveSharedItemRequest) =>
    request<{ item: SharedVaultItem }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/items/${itemId}/move`,
      { method: 'POST', body: payload },
    ),

  updateSharedItem: (vaultId: string, itemId: string, payload: UpdateSharedItemRequest) =>
    request<{ item: SharedVaultItem }>(
      `${ROUTES.SHARED.VAULTS}/${vaultId}/items/${itemId}`,
      { method: 'PATCH', body: payload },
    ),

  deleteSharedItem: (vaultId: string, itemId: string) =>
    request<{ permanent: boolean }>(`${ROUTES.SHARED.VAULTS}/${vaultId}/items/${itemId}`, {
      method: 'DELETE',
    }),

  // --- Security policy (Phase 6) -------------------------------------------

  /** Full policy with provenance. Requires `settings:read`. */
  getSecuritySettings: () => request<SecuritySettingsResponse>(ROUTES.ADMIN.SETTINGS),

  updateSecuritySettings: (settings: Partial<SecuritySettings>, reason?: string) =>
    request<{ settings: SecuritySettings; changed: string[]; message: string }>(
      ROUTES.ADMIN.SETTINGS,
      { method: 'PATCH', body: { settings, ...(reason ? { reason } : {}) } },
    ),

  /** Reset one key, or every key when `key` is omitted. */
  resetSecuritySettings: (key?: keyof SecuritySettings) =>
    request<{ settings: SecuritySettings; message: string }>(
      `${ROUTES.ADMIN.SETTINGS}/reset`,
      { method: 'POST', body: key ? { key } : {} },
    ),

  /** The slice of policy this client must honour. Any signed-in user may read it. */
  getSecurityPolicy: () =>
    request<{ policy: ClientSecuritySettings; tlsActive: boolean }>(ROUTES.SECURITY.POLICY),

  // --- IP allow list -------------------------------------------------------

  listIpRules: () =>
    request<{
      rules: IpRule[];
      mode: 'off' | 'audit' | 'enforce';
      appliesToAdmins: boolean;
      callerIp: string;
    }>(ROUTES.ADMIN.IP_RULES),

  createIpRule: (payload: CreateIpRuleRequest) =>
    request<{ rule: IpRule }>(ROUTES.ADMIN.IP_RULES, { method: 'POST', body: payload }),

  setIpRuleEnabled: (id: string, enabled: boolean) =>
    request<{ rule: IpRule }>(`${ROUTES.ADMIN.IP_RULES}/${id}`, {
      method: 'PATCH',
      body: { enabled },
    }),

  deleteIpRule: (id: string) =>
    request<void>(`${ROUTES.ADMIN.IP_RULES}/${id}`, { method: 'DELETE' }),

  /** "Would this address get in?" - runs the real evaluation, not a preview. */
  checkIp: (ip: string) => request<IpCheckResult>(ROUTES.ADMIN.IP_CHECK, {
    method: 'POST',
    body: { ip },
  }),

  // --- Security score ------------------------------------------------------

  getSecurityScore: () => request<SecurityScore>(ROUTES.ADMIN.SCORE),

  getScoreHistory: (days = 30) =>
    request<{ points: { score: number; grade: string; computedAt: string }[] }>(
      `${ROUTES.ADMIN.SCORE}/history?days=${days}`,
    ),

  // --- Emergency lock ------------------------------------------------------

  getEmergencyLock: () => request<EmergencyLockState>(ROUTES.ADMIN.EMERGENCY_LOCK),

  setEmergencyLock: (payload: EmergencyLockRequest) =>
    request<{
      active: boolean;
      message: string;
      sessionsTerminated: number;
      notice: string;
    }>(ROUTES.ADMIN.EMERGENCY_LOCK, { method: 'POST', body: payload }),

  // --- Notifications -------------------------------------------------------

  listNotifications: (params: { page?: number; pageSize?: number; unreadOnly?: boolean } = {}) =>
    request<PaginatedResult<SecurityNotification> & { unreadCount: number }>(
      `${ROUTES.SECURITY.NOTIFICATIONS}${toQuery(params)}`,
    ),

  /** An empty `ids` marks everything read, which is what "mark all" sends. */
  markNotificationsRead: (ids: string[] = []) =>
    request<{ marked: number }>(ROUTES.SECURITY.NOTIFICATIONS_READ, {
      method: 'POST',
      body: { ids },
    }),

  dismissNotification: (id: string) =>
    request<void>(`${ROUTES.SECURITY.NOTIFICATIONS}/${id}`, { method: 'DELETE' }),

  // --- Step-up verification ------------------------------------------------

  createStepUpChallenge: (action: StepUpAction) =>
    request<StepUpChallenge>(ROUTES.SECURITY.STEP_UP_CHALLENGE, {
      method: 'POST',
      body: { action },
    }),

  /** `credential` is a Google ID token requested with the challenge nonce. */
  verifyStepUp: (challengeId: string, credential: string) =>
    request<{ verified: boolean; action: StepUpAction; expiresAt: string }>(
      ROUTES.SECURITY.STEP_UP_VERIFY,
      { method: 'POST', body: { challengeId, credential } },
    ),

  getStepUpStatus: (action: StepUpAction) =>
    request<StepUpStatus>(`${ROUTES.SECURITY.STEP_UP_STATUS}?action=${action}`),
};

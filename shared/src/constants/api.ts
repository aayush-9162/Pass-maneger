/**
 * API surface constants: version prefix, route paths, custom headers and
 * cookie names. Clients import these instead of hardcoding strings so a route
 * rename is a single-file change.
 */

export const API_VERSION = 'v1' as const;
export const API_PREFIX = `/api/${API_VERSION}` as const;

/**
 * Route paths, relative to `API_PREFIX`.
 *
 */
export const ROUTES = {
  HEALTH: '/health',
  READY: '/health/ready',

  AUTH: {
    /** Exchange a Google ID token for a session. The only way to sign in. */
    GOOGLE: '/auth/google',
    /** Public: the OAuth client id and hosted domain the sign-in button needs. */
    GOOGLE_CONFIG: '/auth/google/config',
    LOGOUT: '/auth/logout',
    REFRESH: '/auth/refresh',
    PROFILE: '/auth/profile',
    REGISTER: '/auth/register',
    SESSIONS: '/auth/sessions',
    DEVICES: '/auth/devices',
  },

  ADMIN: {
    USERS: '/admin/users',
    ROLES: '/admin/roles',
    AUDIT: '/admin/audit-logs',
    /** Aggregate statistics for the dashboard. */
    DASHBOARD: '/admin/dashboard',
    /** Detections and sign-in telemetry. */
    SECURITY: '/admin/security',
    /** All sessions across the tenant. */
    SESSIONS: '/admin/sessions',
    /** All devices across the tenant. */
    DEVICES: '/admin/devices',
    /** Org-wide password health. */
    HEALTH: '/admin/password-health',
    /** Audit search and the admin-only export. */
    AUDIT_SEARCH: '/admin/audit-logs/search',
    AUDIT_EXPORT: '/admin/audit-logs/export',
    AUDIT_FACETS: '/admin/audit-logs/facets',
    /** Approval queue across every vault. */
    APPROVALS: '/admin/approvals',
    /** Runtime security policy. */
    SETTINGS: '/admin/settings',
    /** IP allow list rules, plus the "would this address get in?" tester. */
    IP_RULES: '/admin/ip-rules',
    IP_CHECK: '/admin/ip-rules/check',
    /** Computed security posture score. */
    SCORE: '/admin/security-score',
    /** The break-glass switch. */
    EMERGENCY_LOCK: '/admin/emergency-lock',
  },

  /** Per-user security surface: policy the client must honour, alerts, step-up. */
  SECURITY: {
    /** Client-visible slice of the live policy. */
    POLICY: '/security/policy',
    NOTIFICATIONS: '/security/notifications',
    NOTIFICATIONS_READ: '/security/notifications/read',
    /** Begin a Google re-confirmation before a sensitive action. */
    STEP_UP_CHALLENGE: '/security/step-up/challenge',
    STEP_UP_VERIFY: '/security/step-up/verify',
    STEP_UP_STATUS: '/security/step-up/status',
    /** Rotate the CSRF token; also how a fresh client obtains its first one. */
    CSRF_TOKEN: '/security/csrf-token',
  },

  VAULT: {
    /** The caller's own password health report. */
    HEALTH: '/vault/password-health',
  },

  /** Shared vaults. Membership-scoped, not admin-scoped - see `shared.routes.ts`. */
  SHARED: {
    VAULTS: '/shared/vaults',
    /** Create an individual password; the server wraps it in a vault of its own. */
    ITEMS: '/shared/items',
    /** The caller's own approval requests, and ones awaiting their decision. */
    REQUESTS: '/shared/requests',
    /**
     * Report a client-observed access event: a refused reveal, a tampered
     * fill. Secret releases are audited by the server itself, when it serves
     * them.
     */
    ACCESS_EVENTS: '/shared/access-events',
  },
} as const;

/** Custom request headers understood by the API. */
export const HEADERS = {
  /** Stable, client-generated device identifier (UUID v4). */
  DEVICE_ID: 'x-device-id',
  /** Hashed browser/OS fingerprint used to detect device cloning. */
  DEVICE_FINGERPRINT: 'x-device-fingerprint',
  /** Human readable device name shown in the "your devices" UI. */
  DEVICE_NAME: 'x-device-name',
  /** Per-request correlation id, echoed back on every response. */
  REQUEST_ID: 'x-request-id',
  /**
   * CSRF token, echoed back from the `passm_csrf` cookie.
   *
   * A header rather than a body field so it works on DELETE and on
   * `multipart` bodies, and because reading a cookie to set a header is
   * something only same-origin script can do.
   */
  CSRF_TOKEN: 'x-csrf-token',
} as const;

/** Cookie names. All are `httpOnly`; `Secure` is enabled outside development. */
export const COOKIES = {
  REFRESH_TOKEN: 'passm_rt',
  DEVICE_TRUST: 'passm_dt',
  /**
   * CSRF token. Deliberately *not* `httpOnly` - same-origin script has to read
   * it to echo it back in a header, which is the entire mechanism. It is not a
   * credential on its own: knowing it grants nothing without the session cookie.
   */
  CSRF_TOKEN: 'passm_csrf',
} as const;

/** Token type discriminator embedded in every JWT payload. */
export const TOKEN_TYPE = {
  ACCESS: 'access',
  REFRESH: 'refresh',
  DEVICE_TRUST: 'device_trust',
} as const;

export type TokenType = (typeof TOKEN_TYPE)[keyof typeof TOKEN_TYPE];

/** Pagination defaults, shared so client and server agree on the caps. */
export const ADMIN_PAGE_SIZES: readonly number[] = [10, 25, 50, 100];

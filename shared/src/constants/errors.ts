/**
 * Machine readable error codes.
 *
 * The API never leaks internal details; clients branch on `code`, not on the
 * human readable `message`.
 */

export const ERROR_CODES = {
  // --- Validation / client errors -----------------------------------------
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  BAD_REQUEST: 'BAD_REQUEST',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',

  // --- Authentication ------------------------------------------------------
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  UNAUTHENTICATED: 'UNAUTHENTICATED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  REFRESH_TOKEN_REUSED: 'REFRESH_TOKEN_REUSED',
  SESSION_REVOKED: 'SESSION_REVOKED',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  ACCOUNT_DISABLED: 'ACCOUNT_DISABLED',

  // --- Device --------------------------------------------------------------
  DEVICE_NOT_REGISTERED: 'DEVICE_NOT_REGISTERED',
  DEVICE_NOT_TRUSTED: 'DEVICE_NOT_TRUSTED',
  DEVICE_REVOKED: 'DEVICE_REVOKED',
  DEVICE_LIMIT_REACHED: 'DEVICE_LIMIT_REACHED',

  // --- Authorization -------------------------------------------------------
  FORBIDDEN: 'FORBIDDEN',
  INSUFFICIENT_ROLE: 'INSUFFICIENT_ROLE',
  INSUFFICIENT_PERMISSION: 'INSUFFICIENT_PERMISSION',

  // --- Security policy (Phase 6) -------------------------------------------
  /** Missing or mismatched CSRF token. The client should fetch a fresh one and retry once. */
  CSRF_TOKEN_INVALID: 'CSRF_TOKEN_INVALID',
  /** Caller's address is not on the allow list. */
  IP_NOT_ALLOWED: 'IP_NOT_ALLOWED',
  /**
   * The action needs a fresh Google re-confirmation.
   *
   * Distinct from `UNAUTHENTICATED`: the session is perfectly valid and the
   * client must not sign the user out. It should raise the step-up dialog and
   * replay the request.
   */
  STEP_UP_REQUIRED: 'STEP_UP_REQUIRED',
  STEP_UP_FAILED: 'STEP_UP_FAILED',
  /** Everything is suspended by the break-glass switch. */
  EMERGENCY_LOCK_ACTIVE: 'EMERGENCY_LOCK_ACTIVE',
  /** The device is known but awaits administrator approval. */
  DEVICE_PENDING_APPROVAL: 'DEVICE_PENDING_APPROVAL',
  /** A settings write was refused because the environment pins that key. */
  SETTING_LOCKED: 'SETTING_LOCKED',

  // --- Throttling / server -------------------------------------------------
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

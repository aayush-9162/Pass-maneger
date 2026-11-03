/**
 * Application error hierarchy.
 *
 * Every error thrown deliberately by the app is an {@link AppError}: it carries
 * the HTTP status, a stable machine-readable code and a message that is safe to
 * show a user. The error middleware trusts those fields.
 *
 * Anything else that reaches the middleware is treated as a bug: it is logged
 * with full context and reported to the client as a generic 500, so internal
 * details never leak.
 */

import { ERROR_CODES, type ApiFieldError, type ErrorCode } from '@passm/shared';

export interface AppErrorOptions {
  /** Field-level problems, for validation failures. */
  details?: ApiFieldError[];
  /** Seconds until the client may retry (429/503). */
  retryAfter?: number;
  /** Original error, kept for logs only - never serialized to the client. */
  cause?: unknown;
  /** Extra structured context for the log entry. */
  context?: Record<string, unknown>;
}

export class AppError extends Error {
  readonly statusCode: number;
  readonly code: ErrorCode;
  /** `true` = an expected condition (bad input, wrong password, ...). */
  readonly isOperational: boolean;
  readonly details?: ApiFieldError[];
  readonly retryAfter?: number;
  readonly context?: Record<string, unknown>;

  constructor(
    statusCode: number,
    code: ErrorCode,
    message: string,
    options: AppErrorOptions = {},
    isOperational = true,
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.details = options.details;
    this.retryAfter = options.retryAfter;
    this.context = options.context;

    // Keep the stack rooted at the throw site, not at this constructor.
    Error.captureStackTrace(this, new.target);
  }
}

// ---------------------------------------------------------------------------
// 4xx
// ---------------------------------------------------------------------------

export class BadRequestError extends AppError {
  constructor(message = 'The request could not be understood.', options?: AppErrorOptions) {
    super(400, ERROR_CODES.BAD_REQUEST, message, options);
  }
}

export class ValidationError extends AppError {
  constructor(details: ApiFieldError[], message = 'One or more fields are invalid.') {
    super(422, ERROR_CODES.VALIDATION_ERROR, message, { details });
  }
}

/**
 * 401 - not authenticated (or credentials rejected).
 *
 * The default message is intentionally vague: distinguishing "no such user"
 * from "wrong password" hands an attacker a user-enumeration oracle.
 */
export class UnauthorizedError extends AppError {
  constructor(
    message = 'Authentication required.',
    code: ErrorCode = ERROR_CODES.UNAUTHENTICATED,
    options?: AppErrorOptions,
  ) {
    super(401, code, message, options);
  }
}

export class InvalidCredentialsError extends UnauthorizedError {
  constructor() {
    super('Invalid email or password.', ERROR_CODES.INVALID_CREDENTIALS);
  }
}

/** 403 - authenticated, but not permitted. */
export class ForbiddenError extends AppError {
  constructor(
    message = 'You do not have permission to perform this action.',
    code: ErrorCode = ERROR_CODES.FORBIDDEN,
    options?: AppErrorOptions,
  ) {
    super(403, code, message, options);
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found.', options?: AppErrorOptions) {
    super(404, ERROR_CODES.NOT_FOUND, message, options);
  }
}

export class ConflictError extends AppError {
  constructor(message = 'The resource already exists.', options?: AppErrorOptions) {
    super(409, ERROR_CODES.CONFLICT, message, options);
  }
}

export class PayloadTooLargeError extends AppError {
  constructor(message = 'Request body is too large.') {
    super(413, ERROR_CODES.PAYLOAD_TOO_LARGE, message);
  }
}

export class TooManyRequestsError extends AppError {
  constructor(retryAfterSeconds: number, message = 'Too many requests. Please try again later.') {
    super(429, ERROR_CODES.RATE_LIMITED, message, { retryAfter: retryAfterSeconds });
  }
}

/** 423 - account temporarily locked by the failed-login policy. */
export class AccountLockedError extends AppError {
  constructor(retryAfterSeconds: number) {
    super(
      423,
      ERROR_CODES.ACCOUNT_LOCKED,
      'This account is temporarily locked after too many failed sign-in attempts.',
      { retryAfter: retryAfterSeconds },
    );
  }
}

export class AccountDisabledError extends AppError {
  constructor() {
    super(
      403,
      ERROR_CODES.ACCOUNT_DISABLED,
      'This account has been disabled. Contact your administrator.',
    );
  }
}

// ---------------------------------------------------------------------------
// Security policy (Phase 6)
// ---------------------------------------------------------------------------

/**
 * 403 - missing or mismatched CSRF token.
 *
 * Distinct from a generic 403 so the client can tell "I need a fresh token and
 * should retry once" apart from "you are not allowed to do this at all". The
 * message stays vague about *why* it failed; a probe should not learn whether
 * the cookie or the header was the problem.
 */
export class CsrfError extends AppError {
  constructor(message = 'Security token missing or invalid. Reload the page and try again.') {
    super(403, ERROR_CODES.CSRF_TOKEN_INVALID, message);
  }
}

/**
 * 403 - the caller's address is not on the allow list.
 *
 * The address is echoed back deliberately. Whoever is blocked needs to tell an
 * administrator which address to add, and they cannot read it off the server.
 * It reveals nothing the caller does not already know about themselves.
 */
export class IpNotAllowedError extends AppError {
  constructor(ip: string) {
    super(
      403,
      ERROR_CODES.IP_NOT_ALLOWED,
      `Access is not permitted from this network address (${ip}). Contact your administrator.`,
      { context: { ip } },
    );
  }
}

/**
 * 401 - the action needs a fresh master-password check.
 *
 * 401 rather than 403 so it sits in the "authenticate further" family, but the
 * `code` is what clients branch on: they must raise the step-up dialog and
 * replay the request, *not* sign the user out. The session is entirely valid.
 */
export class StepUpRequiredError extends AppError {
  constructor(action: string) {
    super(
      401,
      ERROR_CODES.STEP_UP_REQUIRED,
      'Confirm it is you with Google to continue.',
      { context: { action } },
    );
  }
}

/** 401 - the step-up confirmation did not verify. */
export class StepUpFailedError extends AppError {
  constructor(message = 'That Google confirmation could not be verified.') {
    super(401, ERROR_CODES.STEP_UP_FAILED, message);
  }
}

/**
 * 503 - everything is suspended by the break-glass switch.
 *
 * 503 rather than 403: this is a deliberate, temporary, whole-service
 * condition, and it should read that way to monitoring rather than looking like
 * a permissions bug. `Retry-After` is deliberately absent - nobody knows how
 * long an incident lasts, and inventing a number would be a lie.
 */
export class EmergencyLockError extends AppError {
  constructor(message: string) {
    super(503, ERROR_CODES.EMERGENCY_LOCK_ACTIVE, message);
  }
}

/** 403 - the device is registered but awaits administrator approval. */
export class DevicePendingApprovalError extends AppError {
  constructor() {
    super(
      403,
      ERROR_CODES.DEVICE_PENDING_APPROVAL,
      'This device is waiting for administrator approval before it can be used.',
    );
  }
}

// ---------------------------------------------------------------------------
// 5xx
// ---------------------------------------------------------------------------

/** Non-operational: indicates a bug or an unexpected dependency failure. */
export class InternalError extends AppError {
  constructor(message = 'An unexpected error occurred.', options?: AppErrorOptions) {
    super(500, ERROR_CODES.INTERNAL_ERROR, message, options, false);
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message = 'Service temporarily unavailable.', retryAfterSeconds = 30) {
    super(503, ERROR_CODES.SERVICE_UNAVAILABLE, message, { retryAfter: retryAfterSeconds });
  }
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

/** Narrow an unknown throwable to `Error` without losing information. */
export function toError(value: unknown): Error {
  if (value instanceof Error) return value;
  return new Error(typeof value === 'string' ? value : JSON.stringify(value));
}

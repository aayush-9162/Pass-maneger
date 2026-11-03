/**
 * Central error handling.
 *
 * Two responsibilities, and keeping them together is what makes them auditable:
 *
 *  1. **Translate** anything thrown anywhere in the app into the standard error
 *     envelope, with a stable machine-readable code.
 *  2. **Contain**. Stack traces, SQL text, driver messages and internal paths go
 *     to the log, never to the client. An unrecognised error is always reported
 *     as a generic 500 - it is exactly the errors we did not anticipate that are
 *     most likely to leak something.
 */

import { ERROR_CODES } from '@passm/shared';
import type { ErrorRequestHandler, NextFunction, Request, RequestHandler, Response } from 'express';
import { ZodError } from 'zod';

import { env } from '../config/env';
import { logger } from '../config/logger';
import { clearAuthCookies } from '../utils/cookies';
import {
  AppError,
  NotFoundError,
  PayloadTooLargeError,
  ValidationError,
  isAppError,
} from '../utils/errors';
import { sendError } from '../utils/api-response';
import { isDuplicateEntryError, isMysqlError } from '../utils/sql';

/** 404 for unmatched routes, so unknown paths get the standard envelope too. */
export const notFoundHandler: RequestHandler = (req: Request, _res: Response, next: NextFunction) => {
  next(new NotFoundError(`Route ${req.method} ${req.originalUrl.split('?')[0]} does not exist.`));
};

/** body-parser attaches `type` and `status` to its errors. */
interface BodyParserError extends Error {
  type?: string;
  status?: number;
  statusCode?: number;
}

/**
 * Map an unknown throwable to an {@link AppError}.
 *
 * Each branch handles a class of error that would otherwise surface as a 500 with
 * an unhelpful (or revealing) message.
 */
function normalizeError(error: unknown): AppError {
  if (isAppError(error)) return error;

  // A zod error escaping the validation middleware (e.g. thrown inside a service).
  if (error instanceof ZodError) {
    return new ValidationError(
      error.issues.map((issue) => ({
        field: issue.path.join('.') || 'request',
        message: issue.message,
      })),
    );
  }

  // Body parsing: oversized payload, malformed JSON, unsupported charset.
  const candidate = error as BodyParserError;
  if (candidate?.type === 'entity.too.large') {
    return new PayloadTooLargeError(
      `Request body exceeds the ${env.security.bodyLimit} limit.`,
    );
  }
  if (candidate?.type === 'entity.parse.failed') {
    return new AppError(400, ERROR_CODES.BAD_REQUEST, 'Request body is not valid JSON.');
  }
  if (candidate?.type === 'charset.unsupported' || candidate?.type === 'encoding.unsupported') {
    return new AppError(400, ERROR_CODES.BAD_REQUEST, 'Unsupported request encoding.');
  }

  // MySQL driver errors. Mapped to intent, never surfaced verbatim: the driver
  // message contains table and column names.
  if (isDuplicateEntryError(error)) {
    return new AppError(409, ERROR_CODES.CONFLICT, 'That record already exists.', {
      cause: error,
    });
  }
  if (isMysqlError(error)) {
    if (error.code === 'ER_LOCK_DEADLOCK' || error.code === 'ER_LOCK_WAIT_TIMEOUT') {
      return new AppError(
        503,
        ERROR_CODES.SERVICE_UNAVAILABLE,
        'The service is busy. Please retry in a moment.',
        { retryAfter: 2, cause: error },
      );
    }
    return new AppError(
      500,
      ERROR_CODES.INTERNAL_ERROR,
      'A database error occurred.',
      { cause: error },
      false,
    );
  }

  // Connection-level failures against MySQL or Redis.
  const code = (error as { code?: string })?.code;
  if (code === 'ECONNREFUSED' || code === 'ETIMEDOUT' || code === 'ENOTFOUND') {
    return new AppError(
      503,
      ERROR_CODES.SERVICE_UNAVAILABLE,
      'A required service is unavailable. Please retry shortly.',
      { retryAfter: 10, cause: error },
      false,
    );
  }

  return new AppError(
    500,
    ERROR_CODES.INTERNAL_ERROR,
    'An unexpected error occurred.',
    { cause: error },
    false,
  );
}

/**
 * Terminal error handler. Must be mounted last.
 *
 * Express identifies an error handler by its four-parameter signature, so `next`
 * has to stay in the list even though it is only used for the
 * headers-already-sent case.
 */
export const errorHandler: ErrorRequestHandler = (
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const appError = normalizeError(error);

  // Once headers are out, the response cannot be rewritten. Delegating to
  // Express's default handler closes the connection instead of emitting a
  // corrupt body.
  if (res.headersSent) {
    req.log?.error('Error thrown after response headers were sent', {
      code: appError.code,
      error,
    });
    next(error);
    return;
  }

  const logPayload = {
    code: appError.code,
    statusCode: appError.statusCode,
    path: req.originalUrl.split('?')[0],
    method: req.method,
    userId: req.auth?.userId,
    ...(appError.context ?? {}),
  };

  if (!appError.isOperational || appError.statusCode >= 500) {
    // Unexpected: log the whole error, including the cause chain and stack.
    req.log?.error(appError.message, { ...logPayload, error });
  } else if (appError.statusCode === 401 || appError.statusCode === 403) {
    // Security relevant, but expected. Worth a warn so bursts are visible.
    req.log?.warn(appError.message, logPayload);
  } else {
    req.log?.debug(appError.message, logPayload);
  }

  // A rejected credential means the cookies the browser holds are useless.
  // Clearing them stops a client from looping on a dead refresh token.
  if (
    appError.code === ERROR_CODES.REFRESH_TOKEN_REUSED ||
    appError.code === ERROR_CODES.SESSION_REVOKED
  ) {
    clearAuthCookies(res);
  }

  sendError(res, appError.statusCode, appError.code, appError.message, {
    ...(appError.details ? { details: appError.details } : {}),
    ...(appError.retryAfter !== undefined ? { retryAfter: appError.retryAfter } : {}),
  });
};

/**
 * Last-resort handlers for errors outside the request lifecycle.
 *
 * An unhandled rejection or uncaught exception leaves the process in an unknown
 * state, so the only safe response is to log loudly and let the supervisor
 * (PM2/Kubernetes) restart a clean one. Continuing risks serving requests from a
 * half-broken process, which is worse than a restart.
 */
export function installProcessErrorHandlers(shutdown: (code: number) => void): void {
  process.on('unhandledRejection', (reason: unknown) => {
    logger.error('Unhandled promise rejection - shutting down', { reason });
    shutdown(1);
  });

  process.on('uncaughtException', (error: Error) => {
    logger.error('Uncaught exception - shutting down', { error });
    shutdown(1);
  });
}

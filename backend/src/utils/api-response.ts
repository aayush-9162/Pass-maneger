/**
 * Response envelope helpers.
 *
 * All controllers return through these so the shape stays identical across the
 * API and clients only need one parser (see `ApiResponse` in @passm/shared).
 */

import type { Response } from 'express';

import type {
  ApiErrorResponse,
  ApiFieldError,
  ApiSuccessResponse,
  ErrorCode,
  PaginatedResult,
} from '@passm/shared';

/** Read the correlation id attached by the requestContext middleware. */
function requestIdOf(res: Response): string {
  return (res.locals.requestId as string | undefined) ?? 'unknown';
}

/** Send a success envelope. */
export function sendSuccess<T>(res: Response, data: T, statusCode = 200): void {
  const body: ApiSuccessResponse<T> = {
    success: true,
    data,
    requestId: requestIdOf(res),
    timestamp: new Date().toISOString(),
  };
  res.status(statusCode).json(body);
}

/** 201 with a `Location` header, for resource creation. */
export function sendCreated<T>(res: Response, data: T, location?: string): void {
  if (location) res.setHeader('Location', location);
  sendSuccess(res, data, 201);
}

/** 204, for operations with nothing to return. */
export function sendNoContent(res: Response): void {
  res.status(204).end();
}

/** Send an error envelope. Called by the central error middleware only. */
export function sendError(
  res: Response,
  statusCode: number,
  code: ErrorCode,
  message: string,
  options: { details?: ApiFieldError[]; retryAfter?: number } = {},
): void {
  if (options.retryAfter !== undefined) {
    res.setHeader('Retry-After', String(options.retryAfter));
  }

  const body: ApiErrorResponse = {
    success: false,
    error: {
      code,
      message,
      ...(options.details ? { details: options.details } : {}),
      ...(options.retryAfter !== undefined ? { retryAfter: options.retryAfter } : {}),
    },
    requestId: requestIdOf(res),
    timestamp: new Date().toISOString(),
  };

  res.status(statusCode).json(body);
}

/** Assemble a paginated payload with a consistent page-count calculation. */
export function paginated<T>(
  items: T[],
  total: number,
  page: number,
  pageSize: number,
): PaginatedResult<T> {
  return {
    items,
    page,
    pageSize,
    total,
    totalPages: pageSize > 0 ? Math.ceil(total / pageSize) : 0,
  };
}

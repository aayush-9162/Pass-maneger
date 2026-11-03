/**
 * Uniform response envelope.
 *
 * Every endpoint - success or failure - returns this shape, so clients need a
 * single parsing path and error handling never depends on HTTP status alone.
 */

import type { ErrorCode } from '../constants/errors';

/** A single field-level validation problem. */
export interface ApiFieldError {
  /** Dot/bracket path of the offending field, e.g. `body.email` or `items[0].id`. */
  field: string;
  message: string;
}

export interface ApiSuccessResponse<T> {
  success: true;
  data: T;
  /** Correlation id, also returned in the `x-request-id` header. */
  requestId: string;
  /** ISO-8601 UTC timestamp. */
  timestamp: string;
}

export interface ApiErrorResponse {
  success: false;
  error: {
    code: ErrorCode;
    /** Safe, user-presentable message. Never contains internals or stack traces. */
    message: string;
    /** Present for validation failures. */
    details?: ApiFieldError[];
    /** Present on 429 responses: seconds until the client may retry. */
    retryAfter?: number;
  };
  requestId: string;
  timestamp: string;
}

export type ApiResponse<T> = ApiSuccessResponse<T> | ApiErrorResponse;

/** Narrowing helper for clients. */
export function isApiError<T>(response: ApiResponse<T>): response is ApiErrorResponse {
  return response.success === false;
}

/** Standard pagination request shape (query string). */
export interface PaginationQuery {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortDir?: 'asc' | 'desc';
  search?: string;
}

/** Standard paginated payload. */
export interface PaginatedResult<T> {
  items: T[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export const PAGINATION_DEFAULTS = {
  page: 1,
  pageSize: 25,
  maxPageSize: 100,
} as const;

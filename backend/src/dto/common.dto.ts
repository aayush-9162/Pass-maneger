/**
 * Reusable field schemas.
 *
 * Validation is the app's first line of defence, so the primitives live here and
 * every request DTO composes them. Two properties matter:
 *
 *  - **Normalisation** happens during validation (trim, lowercase), so services
 *    and repositories always see canonical values. Email uniqueness, for
 *    instance, only works because every email is lowercased on the way in.
 *  - **Allow-listing** over blocklisting: free-text fields accept a defined
 *    character set rather than trying to enumerate dangerous input. That closes
 *    stored-XSS and log-injection vectors at the boundary, in addition to the
 *    escaping React does on output.
 */

import { PAGINATION_DEFAULTS, ROLES } from '@passm/shared';
import { z } from 'zod';

/** Characters permitted in human names: letters (any script), spaces, - ' . */
const SAFE_NAME_PATTERN = /^[\p{L}\p{M}][\p{L}\p{M}\s'.-]*$/u;

/** Characters permitted in free-text org fields (adds digits, & , / ( )). */
const SAFE_TEXT_PATTERN = /^[\p{L}\p{M}\p{N}\s'.,&/()-]+$/u;

/**
 * Email address.
 *
 * Lowercased so `Alice@Corp.com` and `alice@corp.com` are the same account, and
 * capped at 255 to match the column width.
 */
export const emailSchema = z
  .string({ required_error: 'Email is required.' })
  .trim()
  .toLowerCase()
  .min(5, 'Email is too short.')
  .max(255, 'Email must be at most 255 characters.')
  .email('Enter a valid email address.');

/** Person name (first/last). */
export const personNameSchema = z
  .string({ required_error: 'This field is required.' })
  .trim()
  .min(1, 'This field is required.')
  .max(100, 'Must be at most 100 characters.')
  .regex(SAFE_NAME_PATTERN, 'Only letters, spaces, apostrophes, hyphens and periods are allowed.');

/** Optional organisational free text (job title). */
export const optionalOrgTextSchema = z
  .string()
  .trim()
  .max(100, 'Must be at most 100 characters.')
  .regex(SAFE_TEXT_PATTERN, 'Contains characters that are not allowed.')
  .optional()
  // Treat an empty string as "not provided" so the column stores NULL.
  .transform((value) => (value === undefined || value === '' ? undefined : value));

export const uuidSchema = z.string().uuid('Must be a valid identifier.');

/** Role name, constrained to the two defined roles. */
export const roleNameSchema = z.enum([ROLES.ADMIN, ROLES.EMPLOYEE], {
  errorMap: () => ({ message: 'Role must be either admin or employee.' }),
});

/** Client-generated device identifier. */
export const clientDeviceIdSchema = z
  .string()
  .trim()
  .min(8, 'Device id is too short.')
  .max(64, 'Device id is too long.')
  .regex(/^[A-Za-z0-9_-]+$/, 'Device id contains invalid characters.');

/** Device metadata accepted in a request body (headers are the usual channel). */
export const deviceIdentitySchema = z
  .object({
    deviceId: clientDeviceIdSchema,
    fingerprint: z
      .string()
      .trim()
      .max(128)
      .regex(/^[A-Za-z0-9+/=_-]+$/, 'Fingerprint contains invalid characters.')
      .optional(),
    name: z.string().trim().max(120).optional(),
    platform: z.enum(['web', 'extension', 'desktop', 'mobile', 'unknown']).optional(),
  })
  .optional();

/**
 * Pagination and sorting.
 *
 * Query values arrive as strings, so numbers are coerced here. `pageSize` is
 * capped: an unbounded value is a cheap denial-of-service vector.
 */
export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(PAGINATION_DEFAULTS.page),
  pageSize: z.coerce
    .number()
    .int()
    .min(1)
    .max(PAGINATION_DEFAULTS.maxPageSize)
    .default(PAGINATION_DEFAULTS.pageSize),
  sortBy: z.string().trim().max(40).optional(),
  sortDir: z.enum(['asc', 'desc']).default('desc'),
  search: z.string().trim().max(120).optional(),
});

export type PaginationQueryDto = z.infer<typeof paginationQuerySchema>;

/** `:id` path parameter. */
export const idParamSchema = z.object({ id: uuidSchema });
export type IdParamDto = z.infer<typeof idParamSchema>;

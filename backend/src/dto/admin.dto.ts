/**
 * Administrative DTOs: locking, master-password reset, health reporting and the
 * dashboard queries.
 */

import {
  HEALTH_ISSUE,
  HEALTH_SEVERITY,
  PAGINATION_DEFAULTS,
  USER_STATUS,
} from '@passm/shared';
import { z } from 'zod';

import { paginationQuerySchema, uuidSchema } from './common.dto';

// ---------------------------------------------------------------------------
// User administration
// ---------------------------------------------------------------------------

/**
 * PUT /admin/users/:id/lock
 *
 * `until` is optional; omitting it means an indefinite lock, which is the usual
 * case for "this person has left" or "we are investigating". A bounded lock is
 * offered for a cooling-off period after suspicious activity.
 */
export const lockUserSchema = z
  .object({
    reason: z
      .string()
      .trim()
      .min(3, 'Give a reason - it is shown to whoever unlocks the account later.')
      .max(200, 'Reason must be at most 200 characters.'),
    until: z.string().datetime({ offset: true }).optional(),
    /** End the user's live sessions immediately. Defaults to true. */
    revokeSessions: z.boolean().default(true),
  })
  .strict()
  .refine((data) => data.until === undefined || new Date(data.until) > new Date(), {
    message: 'The lock must end in the future.',
    path: ['until'],
  });

export type LockUserDto = z.infer<typeof lockUserSchema>;

export const unlockUserSchema = z
  .object({
    note: z.string().trim().max(200).optional(),
  })
  .strict();

export type UnlockUserDto = z.infer<typeof unlockUserSchema>;

// ---------------------------------------------------------------------------
// Tenant-wide session and device listings
// ---------------------------------------------------------------------------

export const listSessionsQuerySchema = paginationQuerySchema
  .extend({
    userId: uuidSchema.optional(),
    status: z.enum(['active', 'rotated', 'revoked', 'expired']).optional(),
    sortBy: z.enum(['lastActivityAt', 'createdAt', 'expiresAt', 'email']).default('lastActivityAt'),
  })
  .strict();

export type ListSessionsQueryDto = z.infer<typeof listSessionsQuerySchema>;

export const listDevicesQuerySchema = paginationQuerySchema
  .extend({
    userId: uuidSchema.optional(),
    status: z.enum(['registered', 'trusted', 'revoked']).optional(),
    platform: z.enum(['web', 'extension', 'desktop', 'mobile', 'unknown']).optional(),
    sortBy: z.enum(['lastUsedAt', 'createdAt', 'name', 'email']).default('lastUsedAt'),
  })
  .strict();

export type ListDevicesQueryDto = z.infer<typeof listDevicesQuerySchema>;

/** `:id` path parameter for a session row. */
export const sessionParamSchema = z.object({ sessionId: uuidSchema }).strict();
export type SessionParamDto = z.infer<typeof sessionParamSchema>;

export const deviceParamSchema = z.object({ deviceId: uuidSchema }).strict();
export type DeviceParamDto = z.infer<typeof deviceParamSchema>;

// ---------------------------------------------------------------------------
// Dashboard and security
// ---------------------------------------------------------------------------

export const dashboardQuerySchema = z
  .object({
    /** Days of history for the activity charts. Capped server-side at 90. */
    windowDays: z.coerce.number().int().min(1).max(90).default(30),
  })
  .strict();

export type DashboardQueryDto = z.infer<typeof dashboardQuerySchema>;

// ---------------------------------------------------------------------------
// Password health
// ---------------------------------------------------------------------------

/**
 * One item's findings, as uploaded by a client.
 *
 * Note what the schema will not accept: there is no field for a password, a
 * hash, an item name or a URL, so a client cannot upload one even by mistake -
 * `.strict()` rejects the whole request if it tries.
 */
const findingSchema = z
  .object({
    itemId: uuidSchema,
    vaultId: z.string().trim().max(36),
    sharedVaultId: uuidSchema.nullable().default(null),
    severity: z.enum([
      HEALTH_SEVERITY.CRITICAL,
      HEALTH_SEVERITY.HIGH,
      HEALTH_SEVERITY.MEDIUM,
      HEALTH_SEVERITY.LOW,
      HEALTH_SEVERITY.OK,
    ]),
    issues: z
      .array(
        z.enum([
          HEALTH_ISSUE.WEAK,
          HEALTH_ISSUE.REUSED,
          HEALTH_ISSUE.OLD,
          HEALTH_ISSUE.COMPROMISED,
          HEALTH_ISSUE.SHORT,
          HEALTH_ISSUE.MISSING,
        ]),
      )
      .max(6),
    strengthScore: z.number().int().min(0).max(4),
    entropyBits: z.number().int().min(0).max(4096),
    passwordLength: z.number().int().min(0).max(1024),
    ageDays: z.number().int().min(0).max(100_000).nullable(),
    duplicateCount: z.number().int().min(0).max(10_000),
  })
  .strict();

export const submitHealthReportSchema = z
  .object({
    generatedAt: z.string().datetime({ offset: true }),
    totalItems: z.number().int().min(0).max(1_000_000),
    assessedItems: z.number().int().min(0).max(1_000_000),
    breachCheckPerformed: z.boolean().default(false),
    // Capped so one upload cannot become an unbounded write. A vault larger than
    // this is real but rare, and the cap is documented in the client, which
    // truncates to the worst findings rather than failing the whole upload.
    findings: z.array(findingSchema).max(5000, 'Too many findings in one report.'),
  })
  .strict();

export type SubmitHealthReportDto = z.infer<typeof submitHealthReportSchema>;

export const listHealthReportsQuerySchema = paginationQuerySchema
  .extend({
    maxScore: z.coerce.number().int().min(0).max(100).optional(),
    issue: z
      .enum([
        HEALTH_ISSUE.WEAK,
        HEALTH_ISSUE.REUSED,
        HEALTH_ISSUE.OLD,
        HEALTH_ISSUE.COMPROMISED,
        HEALTH_ISSUE.SHORT,
        HEALTH_ISSUE.MISSING,
      ])
      .optional(),
    sortBy: z
      .enum(['healthScore', 'weakCount', 'reusedCount', 'compromisedCount', 'generatedAt', 'lastName'])
      .default('healthScore'),
    pageSize: z.coerce
      .number()
      .int()
      .min(1)
      .max(PAGINATION_DEFAULTS.maxPageSize)
      .default(PAGINATION_DEFAULTS.pageSize),
  })
  .strict();

export type ListHealthReportsQueryDto = z.infer<typeof listHealthReportsQuerySchema>;

/** Extra filters the user directory accepts now that the directory exists. */
export const adminUserFiltersSchema = z
  .object({
    groupId: uuidSchema.optional(),
    status: z
      .enum([USER_STATUS.ACTIVE, USER_STATUS.PENDING, USER_STATUS.LOCKED, USER_STATUS.SUSPENDED])
      .optional(),
  })
  .strict();

export type AdminUserFiltersDto = z.infer<typeof adminUserFiltersSchema>;


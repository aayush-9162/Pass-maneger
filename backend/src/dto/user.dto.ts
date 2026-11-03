/** User administration DTOs. */

import { USER_STATUS } from '@passm/shared';
import { z } from 'zod';

import {
  optionalOrgTextSchema,
  paginationQuerySchema,
  personNameSchema,
  roleNameSchema,
  uuidSchema,
} from './common.dto';

/** GET /admin/users - list filters. */
export const listUsersQuerySchema = paginationQuerySchema
  .extend({
    role: roleNameSchema.optional(),
    status: z
      .enum([USER_STATUS.ACTIVE, USER_STATUS.PENDING, USER_STATUS.LOCKED, USER_STATUS.SUSPENDED])
      .optional(),
    groupId: uuidSchema.optional(),
    /** `sortBy` is resolved through an allow-list in the repository. */
    sortBy: z
      .enum(['createdAt', 'email', 'lastName', 'lastLoginAt', 'status', 'role'])
      .default('createdAt'),
  })
  .strict();

export type ListUsersQueryDto = z.infer<typeof listUsersQuerySchema>;

/**
 * PATCH /admin/users/:id - profile fields only.
 *
 * Role and status changes are separate endpoints on purpose: they are the two
 * privilege-relevant mutations, so they get their own audit action and their own
 * permission check rather than hiding inside a generic update.
 */
export const updateUserSchema = z
  .object({
    firstName: personNameSchema.optional(),
    lastName: personNameSchema.optional(),
    /** `null` clears the job title; omitting it changes nothing. */
    jobTitle: optionalOrgTextSchema,
  })
  .strict()
  .refine((data) => Object.values(data).some((value) => value !== undefined), {
    message: 'Provide at least one field to update.',
  });

export type UpdateUserDto = z.infer<typeof updateUserSchema>;

/** PUT /admin/users/:id/role */
export const changeUserRoleSchema = z
  .object({
    role: roleNameSchema,
    /**
     * A role change alters the permissions baked into every live access token,
     * so existing sessions are revoked by default to force re-issue.
     */
    revokeSessions: z.boolean().default(true),
  })
  .strict();

export type ChangeUserRoleDto = z.infer<typeof changeUserRoleSchema>;

/** PUT /admin/users/:id/status */
export const changeUserStatusSchema = z
  .object({
    status: z.enum([USER_STATUS.ACTIVE, USER_STATUS.SUSPENDED]),
    reason: z.string().trim().max(200).optional(),
  })
  .strict();

export type ChangeUserStatusDto = z.infer<typeof changeUserStatusSchema>;

/** GET /admin/audit-logs */
export const listAuditLogsQuerySchema = paginationQuerySchema
  .extend({
    action: z.string().trim().max(64).optional(),
    outcome: z.enum(['success', 'failure']).optional(),
    actorUserId: uuidSchema.optional(),
    targetUserId: uuidSchema.optional(),
    /** ISO-8601 date-time bounds. */
    from: z.string().datetime({ offset: true }).optional(),
    to: z.string().datetime({ offset: true }).optional(),
    sortBy: z.enum(['createdAt']).default('createdAt'),
  })
  .strict()
  .refine(
    (data) => !(data.from && data.to) || new Date(data.from) <= new Date(data.to),
    { message: '`from` must not be after `to`.', path: ['from'] },
  );

export type ListAuditLogsQueryDto = z.infer<typeof listAuditLogsQuerySchema>;

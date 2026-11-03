/**
 * Shared vault DTOs.
 *
 * Item contents arrive as plaintext JSON and are encrypted by the server, so
 * they are validated field by field here: a strict shape with hard size caps,
 * not an opaque blob. Unknown fields are refused rather than stored, so
 * nothing lands in an envelope that no client knows how to show.
 */

import {
  DEFAULT_GROUP_ROLES,
  GRANT_SUBJECT_TYPE,
  SECRET_PURPOSE,
  SHARED_VAULT_STATUS,
  VAULT_ITEM_TYPES,
  VAULT_KIND,
  VAULT_ROLE_LIST,
} from '@passm/shared';
import { z } from 'zod';

import { paginationQuerySchema, uuidSchema } from './common.dto';

const vaultNameSchema = z
  .string({ required_error: 'A name is required.' })
  .trim()
  .min(2, 'Name must be at least 2 characters.')
  .max(150, 'Name must be at most 150 characters.');

/**
 * Named role.
 *
 * Grants are expressed as a role, not as a raw permission list: the server
 * derives the permissions from it, so the two can never disagree and a client
 * cannot invent a combination the product does not define.
 */
const roleSchema = z.enum(VAULT_ROLE_LIST as unknown as [string, ...string[]]);

/** Restrictions that subtract from a role. All default to off. */
const restrictionsSchema = z
  .object({
    hiddenPassword: z.boolean().optional(),
    copyOnly: z.boolean().optional(),
    noEdit: z.boolean().optional(),
    noDelete: z.boolean().optional(),
  })
  .strict()
  .optional();

const itemTypeSchema = z.enum(VAULT_ITEM_TYPES as unknown as [string, ...string[]]);

/** Name, username, URLs, notes - everything shown in a listing. */
const itemDataSchema = z
  .object({
    name: z
      .string({ required_error: 'A name is required.' })
      .trim()
      .min(1, 'A name is required.')
      .max(200, 'Name must be at most 200 characters.'),
    username: z.string().trim().max(500, 'Username is too long.').optional(),
    uris: z
      .array(z.string().trim().min(1).max(2048, 'That address is too long.'))
      .max(20, 'At most 20 addresses per entry.')
      .optional(),
    notes: z.string().max(20_000, 'Notes are too long.').optional(),
    tags: z.array(z.string().trim().min(1).max(50)).max(20).optional(),
  })
  .strict();

/** The part released only on request. Not trimmed: whitespace can be part of a password. */
const itemSecretSchema = z
  .object({
    password: z.string().max(4096, 'Password is too long.').optional(),
    totp: z.string().trim().max(1024, 'TOTP secret is too long.').optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Shared vaults
// ---------------------------------------------------------------------------

export const listSharedVaultsQuerySchema = paginationQuerySchema
  .extend({
    status: z.enum([SHARED_VAULT_STATUS.ACTIVE, SHARED_VAULT_STATUS.ARCHIVED]).optional(),
    kind: z.enum([VAULT_KIND.GROUP, VAULT_KIND.ITEM]).optional(),
    sortBy: z.enum(['name', 'createdAt', 'updatedAt', 'itemCount', 'members']).default('name'),
  })
  .strict();

export type ListSharedVaultsQueryDto = z.infer<typeof listSharedVaultsQuerySchema>;

export const createSharedVaultSchema = z
  .object({
    name: vaultNameSchema,
    description: z.string().trim().max(500).optional(),
    color: z.string().trim().max(24).regex(/^[a-z-]+$/, 'Invalid colour token.').optional(),
    /** `group` (default) = named collection; `item` = wrapper for one individual password. */
    kind: z.enum([VAULT_KIND.GROUP, VAULT_KIND.ITEM]).default(VAULT_KIND.GROUP),
    requireApprovalToJoin: z.boolean().default(false),
    requireApprovalToReveal: z.boolean().default(false),
  })
  .strict();

export type CreateSharedVaultDto = z.infer<typeof createSharedVaultSchema>;

export const updateSharedVaultSchema = z
  .object({
    name: vaultNameSchema.optional(),
    description: z.string().trim().max(500).nullable().optional(),
    color: z.string().trim().max(24).nullable().optional(),
    requireApprovalToJoin: z.boolean().optional(),
    requireApprovalToReveal: z.boolean().optional(),
    /** A role makes this a default group; null stops it being one. */
    autoGrantRole: z.enum(DEFAULT_GROUP_ROLES).nullable().optional(),
    status: z.enum([SHARED_VAULT_STATUS.ACTIVE, SHARED_VAULT_STATUS.ARCHIVED]).optional(),
  })
  .strict()
  .refine((data) => Object.values(data).some((value) => value !== undefined), {
    message: 'Provide at least one field to update.',
  });

export type UpdateSharedVaultDto = z.infer<typeof updateSharedVaultSchema>;

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

export const createGrantSchema = z
  .object({
    subjectType: z.enum([GRANT_SUBJECT_TYPE.USER]).default(GRANT_SUBJECT_TYPE.USER),
    subjectId: uuidSchema,
    role: roleSchema,
    restrictions: restrictionsSchema,
  })
  .strict();

export type CreateGrantDto = z.infer<typeof createGrantSchema>;

export const updateGrantSchema = z
  .object({
    role: roleSchema,
    restrictions: restrictionsSchema,
  })
  .strict();

export type UpdateGrantDto = z.infer<typeof updateGrantSchema>;

// ---------------------------------------------------------------------------
// Shared items
// ---------------------------------------------------------------------------

export const listSharedItemsQuerySchema = paginationQuerySchema
  .extend({
    type: itemTypeSchema.optional(),
    includeDeleted: z.coerce.boolean().optional(),
    updatedSince: z.string().datetime({ offset: true }).optional(),
    sortBy: z.enum(['updatedAt', 'createdAt', 'type']).default('updatedAt'),
  })
  .strict();

export type ListSharedItemsQueryDto = z.infer<typeof listSharedItemsQuerySchema>;

export const createSharedItemSchema = z
  .object({
    type: itemTypeSchema,
    data: itemDataSchema,
    secret: itemSecretSchema.optional(),
    favorite: z.boolean().default(false),
  })
  .strict();

export type CreateSharedItemDto = z.infer<typeof createSharedItemSchema>;

export const updateSharedItemSchema = z
  .object({
    data: itemDataSchema.optional(),
    /** Replaces the stored secret whole. Omit to keep it. */
    secret: itemSecretSchema.optional(),
    favorite: z.boolean().optional(),
    /** Expected current revision. A mismatch is a 409, never a silent overwrite. */
    revision: z.number().int().min(1),
  })
  .strict();

export type UpdateSharedItemDto = z.infer<typeof updateSharedItemSchema>;

export const moveSharedItemSchema = z
  .object({
    /** Another vault, or null to stand alone as an individual password. */
    targetVaultId: uuidSchema.nullable(),
    revision: z.number().int().min(1),
  })
  .strict();

export type MoveSharedItemDto = z.infer<typeof moveSharedItemSchema>;

export const itemSecretQuerySchema = z
  .object({
    purpose: z
      .enum(Object.values(SECRET_PURPOSE) as [string, ...string[]])
      .default(SECRET_PURPOSE.VIEW),
  })
  .strict();

export type ItemSecretQueryDto = z.infer<typeof itemSecretQuerySchema>;

/** `:vaultId` / `:vaultId/:itemId` path parameters. */
export const sharedVaultParamSchema = z.object({ vaultId: uuidSchema }).strict();
export type SharedVaultParamDto = z.infer<typeof sharedVaultParamSchema>;

export const sharedItemParamSchema = z
  .object({ vaultId: uuidSchema, itemId: uuidSchema })
  .strict();
export type SharedItemParamDto = z.infer<typeof sharedItemParamSchema>;

export const grantParamSchema = z.object({ vaultId: uuidSchema, grantId: uuidSchema }).strict();
export type GrantParamDto = z.infer<typeof grantParamSchema>;

/** Device and session management DTOs. */

import { z } from 'zod';

import { uuidSchema } from './common.dto';

/** `:deviceId` path parameter (the internal `devices.id`). */
export const deviceIdParamSchema = z.object({ deviceId: uuidSchema }).strict();
export type DeviceIdParamDto = z.infer<typeof deviceIdParamSchema>;

/** `:sessionId` path parameter. */
export const sessionIdParamSchema = z.object({ sessionId: uuidSchema }).strict();
export type SessionIdParamDto = z.infer<typeof sessionIdParamSchema>;

/**
 * PATCH /auth/devices/:deviceId - rename only.
 *
 * Trust is *not* grantable through this endpoint: it can only be established by
 * a successful password login with `rememberDevice`, so an attacker holding an
 * access token cannot promote their own device to trusted.
 */
export const renameDeviceSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(1, 'Device name is required.')
      .max(120, 'Device name must be at most 120 characters.')
      // Allow-list: letters, digits, spaces and light punctuation.
      .regex(/^[\p{L}\p{M}\p{N}\s'.,()/-]+$/u, 'Device name contains characters that are not allowed.'),
  })
  .strict();

export type RenameDeviceDto = z.infer<typeof renameDeviceSchema>;

/** GET /admin/users/:id/sessions and GET /admin/users/:id/devices */
export const userScopeParamSchema = z.object({ id: uuidSchema }).strict();
export type UserScopeParamDto = z.infer<typeof userScopeParamSchema>;

/** DELETE /admin/users/:userId/devices/:deviceId */
export const userDeviceParamSchema = z
  .object({ userId: uuidSchema, deviceId: uuidSchema })
  .strict();
export type UserDeviceParamDto = z.infer<typeof userDeviceParamSchema>;

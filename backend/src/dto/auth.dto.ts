/**
 * Authentication DTOs.
 *
 * `.strict()` on every object schema rejects unknown keys instead of ignoring
 * them. That turns a client typo (`remember_device` vs `rememberDevice`) into an
 * immediate 422 rather than a silently ignored security preference, and it
 * blocks mass-assignment attempts such as posting `role: "admin"` to `/google`.
 */

import { z } from 'zod';

import {
  deviceIdentitySchema,
  emailSchema,
  optionalOrgTextSchema,
  personNameSchema,
  roleNameSchema,
} from './common.dto';

// ---------------------------------------------------------------------------
// POST /google
// ---------------------------------------------------------------------------

/**
 * Sign in with Google.
 *
 * `credential` is the ID token from Google Identity Services. It is verified in
 * `google-identity.service` and never stored. Google ID tokens are well under
 * 2 KB; the ceiling only stops an oversized body reaching the verifier.
 */
export const googleLoginSchema = z
  .object({
    credential: z.string().trim().min(100).max(4096),
    /** "Remember this device" - issues a device-trust cookie on success. */
    rememberDevice: z.boolean().default(false),
    device: deviceIdentitySchema,
  })
  .strict();

export type GoogleLoginDto = z.infer<typeof googleLoginSchema>;

// ---------------------------------------------------------------------------
// POST /register  (admin only - enforced by route middleware and re-checked
// in the service, so the rule survives a routing mistake)
// ---------------------------------------------------------------------------

/**
 * Create an account ahead of its first Google sign-in.
 *
 * No password: the person signs in with the Google account that owns this
 * address, and the server provisions the vault keys itself. Creating an account
 * in advance is how an administrator gives someone a role other than the
 * default, or access to passwords before they have ever signed in.
 */
export const registerSchema = z
  .object({
    email: emailSchema,
    firstName: personNameSchema,
    lastName: personNameSchema,
    role: roleNameSchema,
    jobTitle: optionalOrgTextSchema,
  })
  .strict();

export type RegisterDto = z.infer<typeof registerSchema>;

// ---------------------------------------------------------------------------
// POST /refresh
// ---------------------------------------------------------------------------

export const refreshSchema = z
  .object({
    /**
     * Optional: browsers send the refresh token as an httpOnly cookie. The body
     * form exists for the extension's service worker, which cannot depend on a
     * cookie jar for cross-origin calls.
     */
    refreshToken: z.string().trim().min(20).max(4096).optional(),
    device: deviceIdentitySchema,
  })
  .strict();

export type RefreshDto = z.infer<typeof refreshSchema>;

// ---------------------------------------------------------------------------
// POST /logout
// ---------------------------------------------------------------------------

export const logoutSchema = z
  .object({
    /** Revoke every session for this user, not just the current one. */
    allDevices: z.boolean().default(false),
    refreshToken: z.string().trim().min(20).max(4096).optional(),
  })
  .strict();

export type LogoutDto = z.infer<typeof logoutSchema>;

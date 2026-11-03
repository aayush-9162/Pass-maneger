/**
 * Security surface request schemas.
 *
 * The settings patch is the interesting one: rather than enumerating sixty
 * fields in Zod and letting them drift from the schema in `@passm/shared`, it
 * accepts an object of known keys and defers per-value checking to
 * `validateSettingValue`, which is the same function the admin UI uses to
 * pre-validate. One definition, three consumers, no drift.
 */

import {
  IP_RULE_SCOPE,
  SECURITY_SETTING_KEYS,
  STEP_UP_ACTION,
  parseCidr,
  type SecuritySettings,
} from '@passm/shared';
import { z } from 'zod';

import { uuidSchema } from './common.dto';

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/**
 * A settings patch.
 *
 * `.strict()` on the wrapper rejects unknown top-level fields. The inner record
 * is keyed by the real setting names, so a typo is a validation error naming the
 * bad key rather than a silently ignored write - which is how you end up
 * believing you tightened a policy that never moved.
 */
export const updateSettingsSchema = z
  .object({
    settings: z
      .record(
        z.enum(SECURITY_SETTING_KEYS as [keyof SecuritySettings, ...(keyof SecuritySettings)[]]),
        z.union([z.boolean(), z.number(), z.string()]),
      )
      .refine((value) => Object.keys(value).length > 0, {
        message: 'Include at least one setting to change.',
      }),
    reason: z.string().trim().max(300).optional(),
  })
  .strict();

export type UpdateSettingsDto = z.infer<typeof updateSettingsSchema>;

export const resetSettingSchema = z
  .object({
    key: z.enum(SECURITY_SETTING_KEYS as [keyof SecuritySettings, ...(keyof SecuritySettings)[]]),
  })
  .strict();

export type ResetSettingDto = z.infer<typeof resetSettingSchema>;

// ---------------------------------------------------------------------------
// IP rules
// ---------------------------------------------------------------------------

/**
 * A CIDR or bare address.
 *
 * Validated with the same parser the matcher uses, so a rule that saves is a
 * rule that can match. Rejecting host bits (`192.168.1.5/24`) would be stricter
 * than necessary - the matcher masks them off - but the message tells the author
 * what they probably meant, and that is handled in the UI rather than by
 * refusing the write.
 */
const cidrField = z
  .string()
  .trim()
  .min(1, 'Enter an address or range.')
  .max(64)
  .refine((value) => parseCidr(value) !== null, {
    message: 'Not a valid IP address or CIDR range. Try 192.168.1.0/24 or 10.0.0.5.',
  });

export const createIpRuleSchema = z
  .object({
    cidr: cidrField,
    label: z.string().trim().min(1, 'Give the rule a name.').max(128),
    scope: z.enum([IP_RULE_SCOPE.GLOBAL, IP_RULE_SCOPE.USER, IP_RULE_SCOPE.ROLE]),
    userId: uuidSchema.nullish(),
    roleName: z.string().trim().max(50).nullish(),
  })
  .strict()
  /**
   * A scoped rule without its target would silently apply to nobody, which
   * looks like a working rule and is not one.
   */
  .refine((value) => value.scope !== IP_RULE_SCOPE.USER || Boolean(value.userId), {
    message: 'Choose the user this rule applies to.',
    path: ['userId'],
  })
  .refine((value) => value.scope !== IP_RULE_SCOPE.ROLE || Boolean(value.roleName), {
    message: 'Choose the role this rule applies to.',
    path: ['roleName'],
  });

export type CreateIpRuleDto = z.infer<typeof createIpRuleSchema>;

export const updateIpRuleSchema = z.object({ enabled: z.boolean() }).strict();
export type UpdateIpRuleDto = z.infer<typeof updateIpRuleSchema>;

export const checkIpSchema = z
  .object({
    ip: z
      .string()
      .trim()
      .min(1)
      .max(64)
      .refine((value) => parseCidr(value) !== null, { message: 'Not a valid IP address.' }),
  })
  .strict();

export type CheckIpDto = z.infer<typeof checkIpSchema>;

// ---------------------------------------------------------------------------
// Step-up
// ---------------------------------------------------------------------------

const stepUpActionField = z.enum([
  STEP_UP_ACTION.REVEAL,
  STEP_UP_ACTION.EXPORT,
  STEP_UP_ACTION.ADMIN_ACTION,
  STEP_UP_ACTION.SETTINGS_CHANGE,
]);

export const stepUpChallengeSchema = z.object({ action: stepUpActionField }).strict();
export type StepUpChallengeDto = z.infer<typeof stepUpChallengeSchema>;

export const stepUpVerifySchema = z
  .object({
    challengeId: uuidSchema,
    /**
     * A fresh Google ID token whose `nonce` is the challenge nonce. Same bounds
     * as the sign-in credential.
     */
    credential: z.string().trim().min(100).max(4096),
  })
  .strict();

export type StepUpVerifyDto = z.infer<typeof stepUpVerifySchema>;

export const stepUpStatusQuerySchema = z.object({ action: stepUpActionField }).strict();
export type StepUpStatusQueryDto = z.infer<typeof stepUpStatusQuerySchema>;


// ---------------------------------------------------------------------------
// Emergency lock
// ---------------------------------------------------------------------------

export const emergencyLockSchema = z
  .object({
    active: z.boolean(),
    /**
     * Mandatory in both directions.
     *
     * Switching the lock on and off are both incident actions, and an audit
     * trail that says "an admin toggled the lock" without saying why is worth
     * very little three months later.
     */
    reason: z.string().trim().min(3, 'Say why. This goes in the audit trail.').max(300),
    message: z.string().trim().max(300).optional(),
    terminateSessions: z.boolean().optional(),
  })
  .strict();

export type EmergencyLockDto = z.infer<typeof emergencyLockSchema>;

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

export const listNotificationsQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(20),
    unreadOnly: z
      .union([z.boolean(), z.enum(['true', 'false'])])
      .transform((value) => value === true || value === 'true')
      .default(false),
  })
  .strict();

export type ListNotificationsQueryDto = z.infer<typeof listNotificationsQuerySchema>;

export const markNotificationsReadSchema = z
  .object({
    /** Empty marks everything read, which is what the "mark all" button sends. */
    ids: z.array(uuidSchema).max(200).default([]),
  })
  .strict();

export type MarkNotificationsReadDto = z.infer<typeof markNotificationsReadSchema>;

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

export const scoreHistoryQuerySchema = z
  .object({
    days: z.coerce.number().int().min(1).max(365).default(30),
  })
  .strict();

export type ScoreHistoryQueryDto = z.infer<typeof scoreHistoryQuerySchema>;

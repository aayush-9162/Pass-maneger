/**
 * Collaboration DTOs: approval requests, audit search and export, and the
 * client-reported access events.
 */

import {
  AUDIT_OUTCOME,
  REQUEST_STATUS,
  REQUEST_TYPE,
  VAULT_ROLE_LIST,
} from '@passm/shared';
import { z } from 'zod';

import { paginationQuerySchema, uuidSchema } from './common.dto';

// ---------------------------------------------------------------------------
// Approval requests
// ---------------------------------------------------------------------------

export const createAccessRequestSchema = z
  .object({
    requestType: z.enum([REQUEST_TYPE.ACCESS, REQUEST_TYPE.REVEAL, REQUEST_TYPE.ELEVATE]),
    requestedRole: z.enum(VAULT_ROLE_LIST as unknown as [string, ...string[]]).optional(),
    itemId: uuidSchema.optional(),
    /**
     * Required, and with a real minimum length.
     *
     * An approver deciding a request with no stated reason is guessing, and the
     * audit row afterwards records that somebody was given access for reasons
     * nobody wrote down.
     */
    reason: z
      .string()
      .trim()
      .min(10, 'Explain why you need this — an approver has nothing to judge otherwise.')
      .max(500),
  })
  .strict();

export type CreateAccessRequestDto = z.infer<typeof createAccessRequestSchema>;

export const decideAccessRequestSchema = z
  .object({
    approve: z.boolean(),
    note: z.string().trim().max(500).optional(),
  })
  .strict();

export type DecideAccessRequestDto = z.infer<typeof decideAccessRequestSchema>;

export const listRequestsQuerySchema = paginationQuerySchema
  .extend({
    status: z
      .enum([
        REQUEST_STATUS.PENDING,
        REQUEST_STATUS.APPROVED,
        REQUEST_STATUS.DENIED,
        REQUEST_STATUS.CANCELLED,
        REQUEST_STATUS.EXPIRED,
      ])
      .optional(),
    sharedVaultId: uuidSchema.optional(),
    /** `mine` = requests I raised; `inbox` = requests awaiting my decision. */
    view: z.enum(['mine', 'inbox']).default('inbox'),
  })
  .strict();

export type ListRequestsQueryDto = z.infer<typeof listRequestsQuerySchema>;

export const requestParamSchema = z.object({ requestId: uuidSchema }).strict();
export type RequestParamDto = z.infer<typeof requestParamSchema>;

// ---------------------------------------------------------------------------
// Audit search and export
// ---------------------------------------------------------------------------

/**
 * Every filter the spec calls for: user, date, IP, action, device.
 *
 * `action` accepts a trailing dot to mean a whole category (`shared_vault.`),
 * which is what the console's grouped dropdown sends.
 */
const auditFilters = {
  search: z.string().trim().max(200).optional(),
  action: z.string().trim().max(64).optional(),
  outcome: z.enum([AUDIT_OUTCOME.SUCCESS, AUDIT_OUTCOME.FAILURE]).optional(),
  actorUserId: uuidSchema.optional(),
  targetUserId: uuidSchema.optional(),
  ipAddress: z.string().trim().max(45).optional(),
  deviceId: uuidSchema.optional(),
  resourceId: uuidSchema.optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  sharedOnly: z.coerce.boolean().optional(),
};

export const auditSearchQuerySchema = paginationQuerySchema
  .extend(auditFilters)
  .strict()
  .refine((data) => !(data.from && data.to) || new Date(data.from) <= new Date(data.to), {
    message: '`from` must not be after `to`.',
    path: ['from'],
  });

export type AuditSearchQueryDto = z.infer<typeof auditSearchQuerySchema>;

/**
 * Export query.
 *
 * Same filters, no pagination - an export is defined by its filters rather than
 * by a page. The row cap lives in the service, not here, so a client cannot
 * raise it.
 */
export const auditExportQuerySchema = z
  .object({
    ...auditFilters,
    format: z.enum(['csv', 'json']).default('csv'),
  })
  .strict()
  .refine((data) => !(data.from && data.to) || new Date(data.from) <= new Date(data.to), {
    message: '`from` must not be after `to`.',
    path: ['from'],
  });

export type AuditExportQueryDto = z.infer<typeof auditExportQuerySchema>;

export const auditFacetsQuerySchema = z
  .object({ windowDays: z.coerce.number().int().min(1).max(365).default(30) })
  .strict();

export type AuditFacetsQueryDto = z.infer<typeof auditFacetsQuerySchema>;

// ---------------------------------------------------------------------------
// Client-reported access events
// ---------------------------------------------------------------------------

/**
 * A view, copy or fill that happened in the browser.
 *
 * Note what this schema cannot carry: there is no field for a value, and
 * `.strict()` rejects the request outright if one is added. A client cannot
 * accidentally - or deliberately - post a password to the audit endpoint.
 */
export const reportAccessEventSchema = z
  .object({
    action: z.enum(['viewed', 'copied', 'filled', 'exported_attempt', 'reveal_blocked']),
    // Hostname only, and bounded: this is client-supplied text that lands in an
    // exportable log, so a full URL (which can carry tokens in its query string)
    // is rejected rather than trimmed.
    host: z
      .string()
      .max(253)
      .regex(/^[a-z0-9.-]+$/i, 'must be a hostname, without scheme, path or port')
      .optional(),
    itemId: uuidSchema,
    sharedVaultId: uuidSchema.optional(),
    field: z
      .enum(['password', 'totp', 'note', 'card_number', 'private_key', 'api_secret'])
      .optional(),
  })
  .strict();

export type ReportAccessEventDto = z.infer<typeof reportAccessEventSchema>;

/**
 * Batched reporting.
 *
 * A user opening ten items in a minute should cost one request, not ten. The
 * cap keeps a misbehaving client from turning the audit table into a firehose.
 */
export const reportAccessEventsSchema = z
  .object({
    events: z.array(reportAccessEventSchema).min(1).max(50),
  })
  .strict();

export type ReportAccessEventsDto = z.infer<typeof reportAccessEventsSchema>;

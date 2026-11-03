/**
 * Audit trail writer.
 *
 * Two rules shape this module:
 *
 *  1. **Auditing must not break the request.** A failed INSERT into
 *     `audit_logs` is logged at error level and swallowed. Rejecting a
 *     legitimate login because the audit table is full would turn a logging
 *     problem into an outage.
 *  2. **Metadata must never contain secrets.** Values are sanitised through an
 *     allow-list of primitive types, key names are screened, and the payload is
 *     size-capped. Structured context is genuinely useful in an investigation;
 *     an accidentally logged password is a breach.
 */

import { AUDIT_OUTCOME, type AuditAction, type AuditOutcome } from '@passm/shared';

import { logger } from '../config/logger';
import type { SqlExecutor } from '../config/database';
import { auditLogRepository } from '../repositories/audit-log.repository';
import type { RequestContext } from '../types/auth.types';

/** Key fragments that must never appear in audit metadata. */
const FORBIDDEN_KEY_FRAGMENTS = [
  'password',
  'token',
  'secret',
  'hash',
  'verifier',
  'salt',
  'cookie',
  'authorization',
  'key',
];

const MAX_METADATA_KEYS = 20;
const MAX_STRING_LENGTH = 200;
const MAX_METADATA_BYTES = 4096;

/**
 * Reduce arbitrary metadata to audit-safe JSON.
 *
 * Only primitives and shallow arrays of primitives survive; nested objects are
 * dropped rather than walked, which keeps the sanitiser simple enough to trust.
 */
function sanitizeMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | null {
  if (!metadata) return null;

  const output: Record<string, unknown> = {};
  let keyCount = 0;

  for (const [key, value] of Object.entries(metadata)) {
    if (keyCount >= MAX_METADATA_KEYS) break;

    const lowerKey = key.toLowerCase();
    if (FORBIDDEN_KEY_FRAGMENTS.some((fragment) => lowerKey.includes(fragment))) {
      continue;
    }

    if (value === null || value === undefined) continue;

    if (typeof value === 'string') {
      output[key] = value.slice(0, MAX_STRING_LENGTH);
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      output[key] = value;
    } else if (Array.isArray(value)) {
      output[key] = value
        .slice(0, 10)
        .filter(
          (item): item is string | number | boolean =>
            typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean',
        )
        .map((item) => (typeof item === 'string' ? item.slice(0, MAX_STRING_LENGTH) : item));
    } else {
      // Objects, functions, Buffers: skipped deliberately.
      continue;
    }

    keyCount += 1;
  }

  if (Object.keys(output).length === 0) return null;

  // Final size guard: a JSON column write should never be megabytes.
  const serialized = JSON.stringify(output);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_METADATA_BYTES) {
    return { truncated: true, keys: Object.keys(output).slice(0, MAX_METADATA_KEYS) };
  }

  return output;
}

export interface AuditEventInput {
  action: AuditAction;
  outcome?: AuditOutcome;
  /** Who performed the action. Null for pre-authentication events. */
  actorUserId?: string | null;
  actorEmail?: string | null;
  /** Who the action was performed on, when different from the actor. */
  targetUserId?: string | null;
  sessionId?: string | null;
  deviceId?: string | null;
  metadata?: Record<string, unknown>;
  /** What the action was performed on. */
  resourceType?: string | null;
  resourceId?: string | null;
  /**
   * True when the resource is organisational property.
   *
   * Decides who may see the row: managers get the organisational trail, and
   * personal-vault activity is screened from them. Defaults to false, so a new
   * call site errs towards treating an event as personal - the more private of
   * the two readings.
   */
  isSharedResource?: boolean;
  context?: RequestContext;
}

export const auditService = {
  /**
   * Append an audit entry.
   *
   * Awaitable, but never rejects. Callers may `void` it when the write is not
   * on a decision path - or await it inside a transaction (pass `executor`) when
   * the entry must land atomically with the change it describes.
   */
  async record(input: AuditEventInput, executor?: SqlExecutor): Promise<void> {
    try {
      await auditLogRepository.insert(
        {
          action: input.action,
          outcome: input.outcome ?? AUDIT_OUTCOME.SUCCESS,
          actorUserId: input.actorUserId ?? null,
          actorEmail: input.actorEmail ?? null,
          targetUserId: input.targetUserId ?? null,
          sessionId: input.sessionId ?? null,
          deviceId: input.deviceId ?? null,
          ipAddress: input.context?.ipAddress ?? null,
          userAgent: input.context?.userAgent ?? null,
          requestId: input.context?.requestId ?? null,
          metadata: sanitizeMetadata(input.metadata),
          resourceType: input.resourceType ?? null,
          resourceId: input.resourceId ?? null,
          isSharedResource: input.isSharedResource ?? false,
        },
        executor,
      );
    } catch (error) {
      // Escalate loudly in the application log: a silent audit gap is a
      // compliance problem, so it must be visible to monitoring even though the
      // request is allowed to continue.
      logger.error('Failed to write audit log entry', {
        action: input.action,
        outcome: input.outcome ?? AUDIT_OUTCOME.SUCCESS,
        requestId: input.context?.requestId,
        error,
      });
    }
  },

  /** Convenience wrapper for a failure outcome. */
  async recordFailure(input: Omit<AuditEventInput, 'outcome'>, executor?: SqlExecutor): Promise<void> {
    return this.record({ ...input, outcome: AUDIT_OUTCOME.FAILURE }, executor);
  },

  /** Read side, used by the admin audit endpoint. */
  list: auditLogRepository.list.bind(auditLogRepository),
};

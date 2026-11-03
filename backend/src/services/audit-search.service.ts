/**
 * Audit search, export, and the client-reported access events.
 *
 * ## Who sees what
 *
 * Item-level auditing records both organisational and personal activity, and
 * those are not the same thing. "Who opened the production root password" is a
 * compliance question any manager responsible for that vault may ask. "What did
 * Alice look at in her own vault on Tuesday" is not - it is a record of her
 * private activity that happens to live in the same table.
 *
 * So `excludePersonalItemAccess` is applied for every caller without
 * `audit:read:personal`, in the repository rather than here, so a future caller
 * that builds its own query cannot forget it.
 *
 * ## Export
 *
 * Admin-only, capped, and itself audited - an export is a bulk extraction of
 * personal data and the trail should show who took one.
 *
 * There is deliberately no counterpart for vault *contents*. The server holds no
 * key, so any export it produced would be ciphertext; and the console does not
 * offer a client-side one, because turning "can read a credential" into "can
 * walk out with the whole vault in one click" is the exact step worth refusing.
 */

import {
  AUDIT_ACTIONS,
  AUDIT_OUTCOME,
  PERMISSIONS,
  type AuditAction,
  type AuditEntryView,
  type PaginatedResult,
} from '@passm/shared';

import { logger } from '../config/logger';
import type {
  AuditExportQueryDto,
  AuditSearchQueryDto,
  ReportAccessEventsDto,
} from '../dto/collaboration.dto';
import {
  auditLogRepository,
  type AuditSearchFilter,
} from '../repositories/audit-log.repository';
import { sharedVaultRepository } from '../repositories/shared-vault.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import { paginated } from '../utils/api-response';
import { ForbiddenError } from '../utils/errors';
import { auditService } from './audit.service';
import { notificationService } from './notification.service';

/** Hard ceiling on an export, whatever the filters match. */
const EXPORT_ROW_CAP = 100_000;

/** Client-reported action to the audit action it records. */
const ACCESS_EVENT_ACTIONS: Record<string, AuditAction> = {
  viewed: AUDIT_ACTIONS.ITEM_VIEWED,
  copied: AUDIT_ACTIONS.ITEM_COPIED,
  filled: AUDIT_ACTIONS.ITEM_FILLED,
  exported_attempt: AUDIT_ACTIONS.ITEM_EXPORT_BLOCKED,
  reveal_blocked: AUDIT_ACTIONS.ITEM_REVEAL_BLOCKED,
};

/** CSV cell escaping. A trail full of user-supplied text needs it. */
function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '""';

  let text = typeof value === 'object' ? JSON.stringify(value) : String(value);

  // A cell beginning with =, +, - or @ is executed as a formula by Excel and
  // Sheets. Prefixing with a single quote neutralises it - the trail is often
  // opened in a spreadsheet, and an audit export should not be able to run code
  // on the auditor's machine.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;

  return `"${text.replace(/"/g, '""')}"`;
}

const EXPORT_COLUMNS = [
  'timestamp',
  'action',
  'outcome',
  'actor_email',
  'actor_name',
  'target_email',
  'target_name',
  'resource_type',
  'resource_name',
  'is_shared_resource',
  'ip_address',
  'device_name',
  'session_id',
  'request_id',
  'metadata',
] as const;

function toCsvRow(entry: AuditEntryView): string {
  return [
    entry.createdAt,
    entry.action,
    entry.outcome,
    entry.actorEmail,
    entry.actorName,
    entry.targetEmail,
    entry.targetName,
    entry.resourceType,
    entry.resourceName,
    entry.isSharedResource ? 'shared' : 'personal',
    entry.ipAddress,
    entry.deviceName,
    entry.sessionId,
    entry.requestId,
    entry.metadata,
  ]
    .map(csvCell)
    .join(',');
}

export const auditSearchService = {
  /** Build the repository filter, applying the personal-activity screen. */
  toFilter(
    query: AuditSearchQueryDto | AuditExportQueryDto,
    actor: AuthContext,
  ): AuditSearchFilter {
    const canSeePersonal = actor.permissions.includes(PERMISSIONS.AUDIT_READ_PERSONAL);

    return {
      ...(query.search ? { search: query.search } : {}),
      ...(query.action ? { action: query.action } : {}),
      ...(query.outcome ? { outcome: query.outcome } : {}),
      ...(query.actorUserId ? { actorUserId: query.actorUserId } : {}),
      ...(query.targetUserId ? { targetUserId: query.targetUserId } : {}),
      ...(query.ipAddress ? { ipAddress: query.ipAddress } : {}),
      ...(query.deviceId ? { deviceId: query.deviceId } : {}),
      ...(query.resourceId ? { resourceId: query.resourceId } : {}),
      ...(query.from ? { from: query.from } : {}),
      ...(query.to ? { to: query.to } : {}),
      ...(query.sharedOnly ? { sharedOnly: true } : {}),
      excludePersonalItemAccess: !canSeePersonal,
    };
  },

  async search(
    query: AuditSearchQueryDto,
    actor: AuthContext,
  ): Promise<PaginatedResult<AuditEntryView>> {
    const result = await auditLogRepository.search({
      ...this.toFilter(query, actor),
      page: query.page,
      pageSize: query.pageSize,
      sortDir: query.sortDir,
    });

    return paginated(result.items, result.total, result.page, result.pageSize);
  },

  async facets(windowDays: number) {
    return auditLogRepository.facets(windowDays);
  },

  /**
   * Stream an export.
   *
   * Yields text chunks so the controller can write them straight to the socket:
   * a year of audit history is tens of megabytes, and building that string in
   * memory to send it in one piece is how an export endpoint takes the process
   * down.
   */
  async *exportStream(
    query: AuditExportQueryDto,
    actor: AuthContext,
    context: RequestContext,
  ): AsyncGenerator<string> {
    if (!actor.permissions.includes(PERMISSIONS.AUDIT_EXPORT)) {
      throw new ForbiddenError('Only administrators can export the audit log.');
    }

    const filter = this.toFilter(query, actor);
    let rows = 0;

    if (query.format === 'csv') yield `${EXPORT_COLUMNS.join(',')}\n`;
    else yield '[';

    let first = true;

    for await (const chunk of auditLogRepository.streamForExport(filter, 1000, EXPORT_ROW_CAP)) {
      if (query.format === 'csv') {
        yield chunk.map(toCsvRow).join('\n') + '\n';
      } else {
        for (const entry of chunk) {
          yield `${first ? '' : ','}${JSON.stringify(entry)}`;
          first = false;
        }
      }
      rows += chunk.length;
    }

    if (query.format === 'json') yield ']';

    // Recorded after the fact so the row count is real rather than intended.
    await auditService.record({
      action: AUDIT_ACTIONS.AUDIT_EXPORTED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      isSharedResource: true,
      metadata: {
        rows,
        format: query.format,
        truncated: rows >= EXPORT_ROW_CAP,
        ...(query.from ? { from: query.from } : {}),
        ...(query.to ? { to: query.to } : {}),
        ...(query.action ? { action: query.action } : {}),
      },
    });

    logger.info('Audit log exported', { actorUserId: actor.userId, rows, format: query.format });
  },

  /**
   * Record events the server could not observe.
   *
   * Viewing and copying happen in the browser after decryption, so an honest
   * client reports them here. That records what an honest client did; a modified
   * one can stay silent, and no design that decrypts client-side can prevent
   * that. It is still worth having - every access by every normal user is
   * captured, which is what an access review actually needs.
   *
   * The events are attributed to the caller from their token, never from the
   * body, so a client cannot report somebody else's activity.
   */
  async reportAccessEvents(
    dto: ReportAccessEventsDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ recorded: number }> {
    let recorded = 0;

    for (const event of dto.events) {
      const action = ACCESS_EVENT_ACTIONS[event.action];
      if (!action) continue;

      // A claimed shared-vault event is verified: without this, any client could
      // mark its own personal activity as organisational, or attach it to a
      // vault it has nothing to do with.
      let isShared = false;
      if (event.sharedVaultId) {
        isShared = await sharedVaultRepository.isEntitled(event.sharedVaultId, actor.userId);
      }

      await auditService.record({
        action,
        // A blocked reveal is a refusal, not something that succeeded. Recording
        // it as a success made it read like a normal access in the trail.
        outcome:
          event.action === 'exported_attempt' || event.action === 'reveal_blocked'
            ? AUDIT_OUTCOME.FAILURE
            : AUDIT_OUTCOME.SUCCESS,
        actorUserId: actor.userId,
        actorEmail: actor.email,
        context,
        resourceType: event.sharedVaultId ? 'shared_vault' : 'vault_item',
        resourceId: event.sharedVaultId ?? event.itemId,
        isSharedResource: isShared,
        // The item id, which field, and where it happened - never the value.
        // There is no schema field that could carry one.
        //
        // `host` is the site the browser was on. Without it "a reveal was
        // blocked" is close to useless for an investigation: the item id names
        // a row nobody can read, whereas the hostname says which account was
        // being gone after.
        // Host first: the trail truncates long metadata, and the hostname is the
        // part a reader actually needs. An item id that scrolls off the end
        // costs nothing; a hostname that does costs the investigation.
        metadata: {
          ...(event.host ? { host: event.host } : {}),
          ...(event.field ? { field: event.field } : {}),
          itemId: event.itemId,
        },
      });

      // A refused reveal is the one access event worth waking an administrator
      // for. The extension already re-masked the field, so nothing here is
      // preventive - this is how the attempt stops being invisible.
      //
      // Not awaited: the client is reporting something that already happened,
      // and it must not wait on a fan-out to every administrator.
      if (event.action === 'reveal_blocked') {
        void notificationService.notifyPasswordTamper({
          userId: actor.userId,
          name: actor.email,
          host: event.host ?? null,
        });
      }

      recorded += 1;
    }

    return { recorded };
  },
};

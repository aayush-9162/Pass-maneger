/**
 * Audit log repository.
 *
 * Append-only. There is deliberately no update or delete method: an audit trail
 * that the application can rewrite is not an audit trail. Retention is handled
 * out-of-band (partition drop / archive job), not from here.
 */

import type { AuditAction, AuditEntryView, AuditOutcome } from '@passm/shared';

import {
  execute,
  query,
  queryOne,
  type RowDataPacket,
  type SqlExecutor,
  type SqlParam,
} from '../config/database';
import {
  mapAuditLogRow,
  type AuditLogRecord,
  type AuditLogRow,
} from '../models/audit-log.model';
import { newId } from '../utils/ids';
import {
  likePattern,
  limitClause,
  limitOffsetClause,
  resolvePagination,
  resolveSortDirection,
} from '../utils/sql';

const AUDIT_COLUMNS = `
  id, action, outcome, actor_user_id, actor_email, target_user_id,
  session_id, device_id, ip_address, user_agent, request_id, metadata, created_at
`;

export interface CreateAuditLogInput {
  action: AuditAction;
  outcome: AuditOutcome;
  actorUserId?: string | null;
  actorEmail?: string | null;
  targetUserId?: string | null;
  sessionId?: string | null;
  deviceId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string | null;
  metadata?: Record<string, unknown> | null;
  /** What the action was performed on: `vault_item`, `shared_vault`, ... */
  resourceType?: string | null;
  resourceId?: string | null;
  /**
   * True when the resource is organisational property.
   *
   * Drives who may see the row. Item access inside somebody's *personal* vault
   * is their private activity and is hidden from managers; the same action on a
   * shared vault is a compliance record everyone responsible for it may read.
   */
  isSharedResource?: boolean;
}

export interface ListAuditLogsFilter {
  page?: number;
  pageSize?: number;
  sortDir?: string;
  action?: string;
  outcome?: AuditOutcome;
  actorUserId?: string;
  targetUserId?: string;
  from?: string;
  to?: string;
}

interface CountRow extends RowDataPacket {
  total: number;
}

export const auditLogRepository = {
  /**
   * Append one entry.
   *
   * `metadata` is JSON-serialised here; the caller is responsible for keeping it
   * free of secrets (see `audit.service`, which allow-lists what goes in).
   */
  async insert(input: CreateAuditLogInput, executor?: SqlExecutor): Promise<string> {
    const id = newId();

    await execute(
      `INSERT INTO audit_logs (
         id, action, outcome, actor_user_id, actor_email, target_user_id,
         session_id, device_id, ip_address, user_agent, request_id, metadata,
         resource_type, resource_id, is_shared_resource
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        input.action,
        input.outcome,
        input.actorUserId ?? null,
        input.actorEmail ?? null,
        input.targetUserId ?? null,
        input.sessionId ?? null,
        input.deviceId ?? null,
        input.ipAddress ?? null,
        input.userAgent ?? null,
        input.requestId ?? null,
        input.metadata ? JSON.stringify(input.metadata) : null,
        input.resourceType ?? null,
        input.resourceId ?? null,
        input.isSharedResource ? 1 : 0,
      ],
      executor,
    );

    return id;
  },

  /** Paginated, filterable trail. Ordered by `created_at` only (indexed). */
  async list(
    filter: ListAuditLogsFilter = {},
    executor?: SqlExecutor,
  ): Promise<{ items: AuditLogRecord[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['1 = 1'];
    const params: SqlParam[] = [];

    if (filter.action) {
      conditions.push('action = ?');
      params.push(filter.action);
    }
    if (filter.outcome) {
      conditions.push('outcome = ?');
      params.push(filter.outcome);
    }
    if (filter.actorUserId) {
      conditions.push('actor_user_id = ?');
      params.push(filter.actorUserId);
    }
    if (filter.targetUserId) {
      conditions.push('target_user_id = ?');
      params.push(filter.targetUserId);
    }
    if (filter.from) {
      conditions.push('created_at >= ?');
      params.push(new Date(filter.from));
    }
    if (filter.to) {
      conditions.push('created_at <= ?');
      params.push(new Date(filter.to));
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    // Only `created_at` is sortable: it is the one column with an index that can
    // serve an ORDER BY on a table this large.
    const direction = resolveSortDirection(filter.sortDir ?? 'desc');

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM audit_logs ${where}`,
      params,
      executor,
    );

    const rows = await query<AuditLogRow>(
      `SELECT ${AUDIT_COLUMNS} FROM audit_logs
        ${where}
        ORDER BY created_at ${direction}, id ${direction}
        ${limitOffsetClause(limit, offset)}`,
      [...params],
      executor,
    );

    return {
      items: rows.map(mapAuditLogRow),
      total: countRow?.total ?? 0,
      page,
      pageSize,
    };
  },

  // -------------------------------------------------------------------------
  // Search
  // -------------------------------------------------------------------------

  /**
   * Filterable search with actor, target, device and resource names resolved.
   *
   * The joins are all LEFT and all on primary keys. Resolving names in SQL
   * rather than having the client join on ids matters for a compliance trail:
   * the subject of an old row may have been deleted since, and a report that
   * renders `4f2a…` for a departed employee is not usable evidence. The
   * denormalised `actor_email` on the row itself is the fallback for exactly
   * that case.
   */
  async search(
    filter: AuditSearchFilter,
    executor?: SqlExecutor,
  ): Promise<{ items: AuditEntryView[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);
    const { where, params } = buildSearchWhere(filter);
    const direction = resolveSortDirection(filter.sortDir ?? 'desc');

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM audit_logs a ${where}`,
      params,
      executor,
    );

    const rows = await query<AuditViewRow>(
      `SELECT ${AUDIT_VIEW_COLUMNS} ${AUDIT_VIEW_SOURCE} ${where}
        ORDER BY a.created_at ${direction}, a.id ${direction}
        ${limitOffsetClause(limit, offset)}`,
      params,
      executor,
    );

    return {
      items: rows.map(mapAuditViewRow),
      total: countRow?.total ?? 0,
      page,
      pageSize,
    };
  },

  /**
   * Stream matching rows for an export, in chunks.
   *
   * Chunked rather than one query, because an export is the only place the trail
   * is read without a page size the user chose, and a tenant with a year of
   * history would otherwise materialise the whole table in memory. The caller
   * writes each chunk out and never holds more than one.
   */
  async *streamForExport(
    filter: AuditSearchFilter,
    chunkSize = 1000,
    maxRows = 100_000,
    executor?: SqlExecutor,
  ): AsyncGenerator<AuditEntryView[]> {
    const { where, params } = buildSearchWhere(filter);
    const safeChunk = Math.min(Math.max(Math.trunc(chunkSize), 1), 5000);

    let offset = 0;

    while (offset < maxRows) {
      const rows = await query<AuditViewRow>(
        `SELECT ${AUDIT_VIEW_COLUMNS} ${AUDIT_VIEW_SOURCE} ${where}
          ORDER BY a.created_at DESC, a.id DESC
          ${limitOffsetClause(safeChunk, offset)}`,
        params,
        executor,
      );

      if (rows.length === 0) return;

      yield rows.map(mapAuditViewRow);

      if (rows.length < safeChunk) return;
      offset += safeChunk;
    }
  },

  /**
   * Distinct values for the search filters.
   *
   * Bounded and read from the trail itself, so the filter offers what is
   * actually present rather than every action the code can emit - a dropdown of
   * 60 actions where 12 have ever occurred is not a filter, it is a haystack.
   */
  async facets(
    windowDays: number,
    executor?: SqlExecutor,
  ): Promise<{
    actions: { action: string; count: number }[];
    addresses: { ipAddress: string; count: number }[];
    devices: { deviceId: string; name: string; count: number }[];
  }> {
    const days = Math.min(Math.max(Math.trunc(windowDays) || 30, 1), 365);

    const actions = await query<RowDataPacket & { action: string; total: number }>(
      `SELECT action, COUNT(*) AS total FROM audit_logs
        WHERE created_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
        GROUP BY action ORDER BY total DESC ${limitClause(100, 100)}`,
      [days],
      executor,
    );

    const addresses = await query<RowDataPacket & { ip_address: string; total: number }>(
      `SELECT ip_address, COUNT(*) AS total FROM audit_logs
        WHERE ip_address IS NOT NULL AND created_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
        GROUP BY ip_address ORDER BY total DESC ${limitClause(50, 50)}`,
      [days],
      executor,
    );

    const devices = await query<
      RowDataPacket & { device_id: string; name: string | null; total: number }
    >(
      `SELECT a.device_id, d.name, COUNT(*) AS total
         FROM audit_logs a
         LEFT JOIN devices d ON d.id = a.device_id
        WHERE a.device_id IS NOT NULL
          AND a.created_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
        GROUP BY a.device_id, d.name ORDER BY total DESC ${limitClause(50, 50)}`,
      [days],
      executor,
    );

    return {
      actions: actions.map((row) => ({ action: row.action, count: Number(row.total) })),
      addresses: addresses.map((row) => ({
        ipAddress: row.ip_address,
        count: Number(row.total),
      })),
      devices: devices.map((row) => ({
        deviceId: row.device_id,
        name: row.name ?? 'Removed device',
        count: Number(row.total),
      })),
    };
  },
};

// ---------------------------------------------------------------------------
// Search internals
// ---------------------------------------------------------------------------

export interface AuditSearchFilter {
  page?: number;
  pageSize?: number;
  sortDir?: string;
  search?: string;
  action?: string;
  outcome?: AuditOutcome;
  actorUserId?: string;
  targetUserId?: string;
  ipAddress?: string;
  deviceId?: string;
  resourceId?: string;
  from?: string;
  to?: string;
  sharedOnly?: boolean;
  /**
   * Hide personal-vault item access from the results.
   *
   * Set by the service for callers without `audit:read:personal`. Applied here
   * rather than in the service so it cannot be forgotten by a future caller that
   * builds its own query.
   */
  excludePersonalItemAccess?: boolean;
}

interface AuditViewRow extends RowDataPacket {
  id: string;
  action: string;
  outcome: string;
  actor_user_id: string | null;
  actor_email: string | null;
  target_user_id: string | null;
  session_id: string | null;
  device_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  metadata: unknown;
  resource_type: string | null;
  resource_id: string | null;
  is_shared_resource: number;
  created_at: Date;
  actor_first_name: string | null;
  actor_last_name: string | null;
  target_first_name: string | null;
  target_last_name: string | null;
  target_email: string | null;
  device_name: string | null;
  resource_name: string | null;
}

const AUDIT_VIEW_COLUMNS = `
  a.id, a.action, a.outcome, a.actor_user_id, a.actor_email, a.target_user_id,
  a.session_id, a.device_id, a.ip_address, a.user_agent, a.request_id, a.metadata,
  a.resource_type, a.resource_id, a.is_shared_resource, a.created_at,
  au.first_name AS actor_first_name,
  au.last_name  AS actor_last_name,
  tu.first_name AS target_first_name,
  tu.last_name  AS target_last_name,
  tu.email      AS target_email,
  d.name        AS device_name,
  sv.name       AS resource_name
`;

const AUDIT_VIEW_SOURCE = `
  FROM audit_logs a
  LEFT JOIN users au ON au.id = a.actor_user_id
  LEFT JOIN users tu ON tu.id = a.target_user_id
  LEFT JOIN devices d ON d.id = a.device_id
  LEFT JOIN shared_vaults sv
    ON a.resource_type = 'shared_vault' AND sv.id = a.resource_id
`;

/** Item-access actions, which are the ones that can concern a personal vault. */
const ITEM_ACCESS_ACTIONS = [
  'item.viewed',
  'item.copied',
  'item.filled',
  'item.created',
  'item.edited',
  'item.deleted',
  'item.restored',
  'item.reveal.blocked',
];

function buildSearchWhere(filter: AuditSearchFilter): { where: string; params: SqlParam[] } {
  const conditions: string[] = ['1 = 1'];
  const params: SqlParam[] = [];

  if (filter.action) {
    // A trailing dot means "this category": `shared_vault.` matches every action
    // in it, which is what the console's grouped filter sends.
    if (filter.action.endsWith('.')) {
      conditions.push('a.action LIKE ?');
      params.push(`${filter.action.replace(/[\\%_]/g, (m) => `\\${m}`)}%`);
    } else {
      conditions.push('a.action = ?');
      params.push(filter.action);
    }
  }
  if (filter.outcome) {
    conditions.push('a.outcome = ?');
    params.push(filter.outcome);
  }
  if (filter.actorUserId) {
    conditions.push('a.actor_user_id = ?');
    params.push(filter.actorUserId);
  }
  if (filter.targetUserId) {
    conditions.push('a.target_user_id = ?');
    params.push(filter.targetUserId);
  }
  if (filter.ipAddress) {
    conditions.push('a.ip_address = ?');
    params.push(filter.ipAddress);
  }
  if (filter.deviceId) {
    conditions.push('a.device_id = ?');
    params.push(filter.deviceId);
  }
  if (filter.resourceId) {
    conditions.push('a.resource_id = ?');
    params.push(filter.resourceId);
  }
  if (filter.from) {
    conditions.push('a.created_at >= ?');
    params.push(new Date(filter.from));
  }
  if (filter.to) {
    conditions.push('a.created_at <= ?');
    params.push(new Date(filter.to));
  }
  if (filter.sharedOnly) {
    conditions.push('a.is_shared_resource = 1');
  }
  if (filter.search) {
    // Actor email is denormalised onto the row so this still matches after the
    // account is gone - which is when an investigator most needs it to.
    conditions.push('(a.actor_email LIKE ? OR a.ip_address LIKE ?)');
    const pattern = likePattern(filter.search);
    params.push(pattern, pattern);
  }
  if (filter.excludePersonalItemAccess) {
    conditions.push(
      `(a.is_shared_resource = 1 OR a.action NOT IN (${ITEM_ACCESS_ACTIONS.map(() => '?').join(', ')}))`,
    );
    params.push(...ITEM_ACCESS_ACTIONS);
  }

  return { where: `WHERE ${conditions.join(' AND ')}`, params };
}

function mapAuditViewRow(row: AuditViewRow): AuditEntryView {
  const name = (first: string | null, last: string | null): string | null =>
    !first && !last ? null : `${first ?? ''} ${last ?? ''}`.trim();

  let metadata: Record<string, unknown> | null = null;
  if (row.metadata !== null && row.metadata !== undefined) {
    metadata =
      typeof row.metadata === 'string'
        ? (JSON.parse(row.metadata) as Record<string, unknown>)
        : (row.metadata as Record<string, unknown>);
  }

  return {
    id: row.id,
    action: row.action as AuditAction,
    outcome: row.outcome as AuditOutcome,
    actorUserId: row.actor_user_id,
    actorEmail: row.actor_email,
    actorName: name(row.actor_first_name, row.actor_last_name),
    targetUserId: row.target_user_id,
    targetEmail: row.target_email,
    targetName: name(row.target_first_name, row.target_last_name),
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    resourceName: row.resource_name,
    isSharedResource: row.is_shared_resource === 1,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    deviceId: row.device_id,
    deviceName: row.device_name,
    sessionId: row.session_id,
    requestId: row.request_id,
    metadata,
    createdAt: row.created_at.toISOString(),
  };
}

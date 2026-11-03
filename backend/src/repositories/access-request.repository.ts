/**
 * Access request repository - the approval workflow's store.
 *
 * A request is a durable record of somebody asking for something they cannot
 * take for themselves. Rows are never deleted: a denied request is as much a
 * compliance artefact as an approved one, and "who asked for the production
 * vault and was refused" is a question worth being able to answer.
 */

import type { AccessRequest, RequestStatus, RequestType, VaultRole } from '@passm/shared';
import { REQUEST_STATUS } from '@passm/shared';

import {
  execute,
  query,
  queryOne,
  type RowDataPacket,
  type SqlExecutor,
  type SqlParam,
} from '../config/database';
import { toIso, toIsoRequired } from '../utils/date';
import { limitOffsetClause, resolvePagination, resolveSortDirection } from '../utils/sql';

interface RequestRow extends RowDataPacket {
  id: string;
  shared_vault_id: string;
  requester_user_id: string;
  request_type: string;
  requested_role: string | null;
  item_id: string | null;
  reason: string;
  status: string;
  decided_by: string | null;
  decided_at: Date | null;
  decision_note: string | null;
  expires_at: Date;
  created_at: Date;
  /** Joined. */
  vault_name: string;
  requester_first_name: string;
  requester_last_name: string;
  requester_email: string;
  decider_first_name: string | null;
  decider_last_name: string | null;
}

function fullName(first: string | null, last: string | null): string | null {
  if (!first && !last) return null;
  return `${first ?? ''} ${last ?? ''}`.trim();
}

function mapRequestRow(row: RequestRow): AccessRequest {
  return {
    id: row.id,
    sharedVaultId: row.shared_vault_id,
    vaultName: row.vault_name,
    requesterUserId: row.requester_user_id,
    requesterName: `${row.requester_first_name} ${row.requester_last_name}`.trim(),
    requesterEmail: row.requester_email,
    requestType: row.request_type as RequestType,
    requestedRole: (row.requested_role as VaultRole | null) ?? null,
    itemId: row.item_id,
    reason: row.reason,
    status: row.status as RequestStatus,
    decidedByUserId: row.decided_by,
    decidedByName: fullName(row.decider_first_name, row.decider_last_name),
    decidedAt: toIso(row.decided_at),
    decisionNote: row.decision_note,
    expiresAt: toIsoRequired(row.expires_at),
    createdAt: toIsoRequired(row.created_at),
  };
}

const REQUEST_COLUMNS = `
  r.id, r.shared_vault_id, r.requester_user_id, r.request_type, r.requested_role,
  r.item_id, r.reason, r.status, r.decided_by, r.decided_at, r.decision_note,
  r.expires_at, r.created_at,
  sv.name AS vault_name,
  ru.first_name AS requester_first_name,
  ru.last_name  AS requester_last_name,
  ru.email      AS requester_email,
  du.first_name AS decider_first_name,
  du.last_name  AS decider_last_name
`;

const REQUEST_SOURCE = `
  FROM access_requests r
  INNER JOIN shared_vaults sv ON sv.id = r.shared_vault_id
  INNER JOIN users ru ON ru.id = r.requester_user_id
  LEFT JOIN users du ON du.id = r.decided_by
`;

export interface CreateRequestInput {
  id: string;
  sharedVaultId: string;
  requesterUserId: string;
  requestType: RequestType;
  requestedRole?: VaultRole | null;
  itemId?: string | null;
  reason: string;
  expiresAt: Date;
}

export interface ListRequestsFilter {
  page?: number;
  pageSize?: number;
  sortDir?: string;
  status?: RequestStatus;
  sharedVaultId?: string;
  requesterUserId?: string;
  /** Restrict to vaults in this list. Empty array means "none". */
  vaultIds?: readonly string[];
}

interface CountRow extends RowDataPacket {
  total: number;
}

export const accessRequestRepository = {
  async create(input: CreateRequestInput, executor?: SqlExecutor): Promise<void> {
    await execute(
      `INSERT INTO access_requests
         (id, shared_vault_id, requester_user_id, request_type, requested_role,
          item_id, reason, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        input.id,
        input.sharedVaultId,
        input.requesterUserId,
        input.requestType,
        input.requestedRole ?? null,
        input.itemId ?? null,
        input.reason,
        input.expiresAt,
      ],
      executor,
    );
  },

  async findById(id: string, executor?: SqlExecutor): Promise<AccessRequest | null> {
    const row = await queryOne<RequestRow>(
      `SELECT ${REQUEST_COLUMNS} ${REQUEST_SOURCE} WHERE r.id = ? LIMIT 1`,
      [id],
      executor,
    );
    return row ? mapRequestRow(row) : null;
  },

  /**
   * An existing pending request for the same thing.
   *
   * Checked before creating one so a user who clicks twice does not put two
   * identical requests in front of an approver.
   */
  async findPendingDuplicate(
    sharedVaultId: string,
    requesterUserId: string,
    requestType: RequestType,
    executor?: SqlExecutor,
  ): Promise<AccessRequest | null> {
    const row = await queryOne<RequestRow>(
      `SELECT ${REQUEST_COLUMNS} ${REQUEST_SOURCE}
        WHERE r.shared_vault_id = ? AND r.requester_user_id = ?
          AND r.request_type = ? AND r.status = ?
          AND r.expires_at > NOW(3)
        LIMIT 1`,
      [sharedVaultId, requesterUserId, requestType, REQUEST_STATUS.PENDING],
      executor,
    );
    return row ? mapRequestRow(row) : null;
  },

  async list(
    filter: ListRequestsFilter = {},
    executor?: SqlExecutor,
  ): Promise<{ items: AccessRequest[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['1 = 1'];
    const params: SqlParam[] = [];

    if (filter.status) {
      conditions.push('r.status = ?');
      params.push(filter.status);
    }
    if (filter.sharedVaultId) {
      conditions.push('r.shared_vault_id = ?');
      params.push(filter.sharedVaultId);
    }
    if (filter.requesterUserId) {
      conditions.push('r.requester_user_id = ?');
      params.push(filter.requesterUserId);
    }
    if (filter.vaultIds) {
      if (filter.vaultIds.length === 0) {
        // An approver who administers no vault sees an empty queue, not
        // everything. `IN ()` is a syntax error, so short-circuit instead.
        conditions.push('1 = 0');
      } else {
        conditions.push(`r.shared_vault_id IN (${filter.vaultIds.map(() => '?').join(', ')})`);
        params.push(...filter.vaultIds);
      }
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const direction = resolveSortDirection(filter.sortDir);

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total ${REQUEST_SOURCE} ${where}`,
      params,
      executor,
    );

    const rows = await query<RequestRow>(
      `SELECT ${REQUEST_COLUMNS} ${REQUEST_SOURCE} ${where}
        ORDER BY r.created_at ${direction}, r.id ASC
        ${limitOffsetClause(limit, offset)}`,
      params,
      executor,
    );

    return { items: rows.map(mapRequestRow), total: countRow?.total ?? 0, page, pageSize };
  },

  /**
   * Record a decision, guarded by the current status.
   *
   * The `status = 'pending'` predicate is what makes two approvers clicking at
   * the same moment safe: the second UPDATE matches nothing and the service
   * reports that somebody else decided first, rather than overwriting their
   * decision and their name on it.
   */
  async decide(
    id: string,
    status: RequestStatus,
    decidedBy: string,
    note: string | null,
    executor?: SqlExecutor,
  ): Promise<number> {
    const result = await execute(
      `UPDATE access_requests
          SET status = ?, decided_by = ?, decided_at = NOW(3), decision_note = ?
        WHERE id = ? AND status = ?`,
      [status, decidedBy, note, id, REQUEST_STATUS.PENDING],
      executor,
    );
    return result.affectedRows;
  },

  /** Cancel one's own request. Same conditional-update guard. */
  async cancel(id: string, requesterUserId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE access_requests
          SET status = ?, decided_at = NOW(3)
        WHERE id = ? AND requester_user_id = ? AND status = ?`,
      [REQUEST_STATUS.CANCELLED, id, requesterUserId, REQUEST_STATUS.PENDING],
      executor,
    );
    return result.affectedRows;
  },

  /**
   * Lapse requests nobody acted on.
   *
   * Run by the maintenance job. Without it a request raised for a reason that
   * expired months ago stays approvable, and somebody eventually approves it.
   */
  async expireStale(executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE access_requests
          SET status = ?
        WHERE status = ? AND expires_at <= NOW(3)`,
      [REQUEST_STATUS.EXPIRED, REQUEST_STATUS.PENDING],
      executor,
    );
    return result.affectedRows;
  },

  /** Pending count, for the console's navigation badge. */
  async countPending(vaultIds: readonly string[] | null, executor?: SqlExecutor): Promise<number> {
    if (vaultIds && vaultIds.length === 0) return 0;

    const scope = vaultIds ? `AND shared_vault_id IN (${vaultIds.map(() => '?').join(', ')})` : '';

    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM access_requests
        WHERE status = ? AND expires_at > NOW(3) ${scope}`,
      [REQUEST_STATUS.PENDING, ...(vaultIds ?? [])],
      executor,
    );
    return row?.total ?? 0;
  },

  /**
   * Has this user an approved, unexpired reveal for this vault?
   *
   * Consulted before a key holder is allowed to deliver the secret key to
   * somebody whose grant hides passwords - the approval is the authorisation,
   * and it has to be checked at delivery time rather than trusted from the UI.
   */
  async hasApprovedReveal(
    sharedVaultId: string,
    userId: string,
    executor?: SqlExecutor,
  ): Promise<boolean> {
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM access_requests
        WHERE shared_vault_id = ? AND requester_user_id = ?
          AND request_type = 'reveal' AND status = ?
          AND expires_at > NOW(3)`,
      [sharedVaultId, userId, REQUEST_STATUS.APPROVED],
      executor,
    );
    return (row?.total ?? 0) > 0;
  },
};

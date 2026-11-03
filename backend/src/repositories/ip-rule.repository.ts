/**
 * IP allow-list repository.
 *
 * The list is small - tens of rows even in a large deployment - and is read on
 * every request, so the service caches it wholesale rather than querying per
 * check. This repository therefore optimises for "give me everything" rather
 * than for filtered reads.
 */

import type { IpRule, IpRuleScope } from '@passm/shared';

import { execute, query, queryOne, type RowDataPacket, type SqlExecutor } from '../config/database';
import { newId } from '../utils/ids';

interface IpRuleRow extends RowDataPacket {
  id: string;
  cidr: string;
  label: string;
  scope: IpRuleScope;
  user_id: string | null;
  role_name: string | null;
  enabled: number;
  match_count: number;
  last_matched_at: Date | null;
  created_at: Date;
  created_by_first_name: string | null;
  created_by_last_name: string | null;
  user_first_name: string | null;
  user_last_name: string | null;
}

const SELECT_COLUMNS = `
  r.id, r.cidr, r.label, r.scope, r.user_id, r.role_name, r.enabled,
  r.match_count, r.last_matched_at, r.created_at,
  creator.first_name AS created_by_first_name,
  creator.last_name  AS created_by_last_name,
  subject.first_name AS user_first_name,
  subject.last_name  AS user_last_name
  FROM ip_rules r
  LEFT JOIN users creator ON creator.id = r.created_by_user_id
  LEFT JOIN users subject ON subject.id = r.user_id
`;

function fullName(first: string | null, last: string | null): string | null {
  const name = [first, last].filter((part): part is string => Boolean(part)).join(' ');
  return name.length > 0 ? name : null;
}

function mapRow(row: IpRuleRow): IpRule {
  return {
    id: row.id,
    cidr: row.cidr,
    label: row.label,
    scope: row.scope,
    userId: row.user_id,
    userName: fullName(row.user_first_name, row.user_last_name),
    roleName: row.role_name,
    enabled: row.enabled === 1,
    matchCount: Number(row.match_count),
    lastMatchedAt: row.last_matched_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
    createdByName: fullName(row.created_by_first_name, row.created_by_last_name),
  };
}

export interface CreateIpRuleInput {
  cidr: string;
  label: string;
  scope: IpRuleScope;
  userId: string | null;
  roleName: string | null;
  createdByUserId: string | null;
}

export const ipRuleRepository = {
  /** Every rule, newest first. Small enough that pagination would be noise. */
  async findAll(executor?: SqlExecutor): Promise<IpRule[]> {
    const rows = await query<IpRuleRow>(
      `SELECT ${SELECT_COLUMNS} ORDER BY r.scope, r.created_at DESC`,
      [],
      executor,
    );
    return rows.map(mapRow);
  },

  /** Only the enabled rules, for the matcher. */
  async findEnabled(executor?: SqlExecutor): Promise<IpRule[]> {
    const rows = await query<IpRuleRow>(
      `SELECT ${SELECT_COLUMNS} WHERE r.enabled = 1`,
      [],
      executor,
    );
    return rows.map(mapRow);
  },

  async findById(id: string, executor?: SqlExecutor): Promise<IpRule | null> {
    const row = await queryOne<IpRuleRow>(`SELECT ${SELECT_COLUMNS} WHERE r.id = ?`, [id], executor);
    return row ? mapRow(row) : null;
  },

  async create(input: CreateIpRuleInput, executor?: SqlExecutor): Promise<string> {
    const id = newId();
    await execute(
      `INSERT INTO ip_rules
         (id, cidr, label, scope, user_id, role_name, created_by_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, input.cidr, input.label, input.scope, input.userId, input.roleName, input.createdByUserId],
      executor,
    );
    return id;
  },

  async setEnabled(id: string, enabled: boolean, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute(
      'UPDATE ip_rules SET enabled = ? WHERE id = ?',
      [enabled ? 1 : 0, id],
      executor,
    );
    return result.affectedRows > 0;
  },

  async remove(id: string, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute('DELETE FROM ip_rules WHERE id = ?', [id], executor);
    return result.affectedRows > 0;
  },

  /**
   * Record that a rule matched.
   *
   * Deliberately fire-and-forget at the call site and deliberately *not*
   * awaited on the request path: this is telemetry for spotting dead rules, and
   * a write per request would put the allow list on the critical path of every
   * single call. Losing a few counts under load is fine.
   */
  async recordMatch(id: string, executor?: SqlExecutor): Promise<void> {
    await execute(
      `UPDATE ip_rules
          SET match_count = match_count + 1,
              last_matched_at = CURRENT_TIMESTAMP(3)
        WHERE id = ?`,
      [id],
      executor,
    );
  },

  /** Does an identical rule already exist? Guards the unique key with a clear error. */
  async existsForTarget(
    cidr: string,
    scope: IpRuleScope,
    userId: string | null,
    roleName: string | null,
    executor?: SqlExecutor,
  ): Promise<boolean> {
    const row = await queryOne<RowDataPacket & { found: number }>(
      `SELECT 1 AS found FROM ip_rules
        WHERE cidr = ? AND scope = ?
          AND (user_id <=> ?) AND (role_name <=> ?)
        LIMIT 1`,
      [cidr, scope, userId, roleName],
      executor,
    );
    return row !== null;
  },
};

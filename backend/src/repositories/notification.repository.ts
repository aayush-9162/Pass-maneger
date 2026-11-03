/**
 * Security notification repository.
 *
 * A user's alert inbox. Kept separate from `audit_logs` because the two have
 * opposite properties: the audit log is append-only and immutable for
 * compliance, this is mutable and user-owned. Merging them would mean either a
 * read receipt mutating an audit row, or users able to delete audit history.
 */

import type {
  NotificationSeverity,
  NotificationType,
  SecurityNotification,
} from '@passm/shared';

import { execute, query, queryOne, type RowDataPacket, type SqlExecutor } from '../config/database';
import { newId } from '../utils/ids';
import { limitOffsetClause } from '../utils/sql';

interface NotificationRow extends RowDataPacket {
  id: string;
  type: NotificationType;
  severity: NotificationSeverity;
  title: string;
  body: string;
  metadata: unknown;
  action_url: string | null;
  action_label: string | null;
  read_at: Date | null;
  created_at: Date;
}

/** mysql2 parses JSON columns; older drivers hand back text. Tolerate both. */
function parseMetadata(raw: unknown): Record<string, string | number | boolean> | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'object') return raw as Record<string, string | number | boolean>;
  if (typeof raw !== 'string') return null;
  try {
    return JSON.parse(raw) as Record<string, string | number | boolean>;
  } catch {
    return null;
  }
}

function mapRow(row: NotificationRow): SecurityNotification {
  return {
    id: row.id,
    type: row.type,
    severity: row.severity,
    title: row.title,
    body: row.body,
    metadata: parseMetadata(row.metadata),
    actionUrl: row.action_url,
    actionLabel: row.action_label,
    readAt: row.read_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
  };
}

export interface CreateNotificationInput {
  userId: string;
  type: NotificationType;
  severity: NotificationSeverity;
  title: string;
  body: string;
  metadata?: Record<string, string | number | boolean> | null;
  actionUrl?: string | null;
  actionLabel?: string | null;
}

export const notificationRepository = {
  async create(input: CreateNotificationInput, executor?: SqlExecutor): Promise<string> {
    const id = newId();
    await execute(
      `INSERT INTO security_notifications
         (id, user_id, type, severity, title, body, metadata, action_url, action_label)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        input.userId,
        input.type,
        input.severity,
        input.title,
        input.body,
        input.metadata ? JSON.stringify(input.metadata) : null,
        input.actionUrl ?? null,
        input.actionLabel ?? null,
      ],
      executor,
    );
    return id;
  },

  /**
   * A user's notifications, newest first.
   *
   * `LIMIT` is interpolated as a validated integer literal rather than bound as
   * a parameter: MySQL's binary protocol rejects a placeholder there, which
   * bit every paginated query in this codebase once already. See `utils/sql.ts`.
   */
  async findForUser(
    userId: string,
    options: { limit: number; offset: number; unreadOnly: boolean },
    executor?: SqlExecutor,
  ): Promise<SecurityNotification[]> {
    const unreadClause = options.unreadOnly ? 'AND read_at IS NULL' : '';

    const rows = await query<NotificationRow>(
      `SELECT id, type, severity, title, body, metadata, action_url, action_label,
              read_at, created_at
         FROM security_notifications
        WHERE user_id = ? ${unreadClause}
        ORDER BY created_at DESC
        ${limitOffsetClause(options.limit, options.offset)}`,
      [userId],
      executor,
    );

    return rows.map(mapRow);
  },

  async countForUser(
    userId: string,
    unreadOnly: boolean,
    executor?: SqlExecutor,
  ): Promise<number> {
    const unreadClause = unreadOnly ? 'AND read_at IS NULL' : '';
    const row = await queryOne<RowDataPacket & { total: number }>(
      `SELECT COUNT(*) AS total FROM security_notifications
        WHERE user_id = ? ${unreadClause}`,
      [userId],
      executor,
    );
    return Number(row?.total ?? 0);
  },

  /**
   * Mark specific notifications read, or all of them when `ids` is empty.
   *
   * Scoped by `user_id` in both branches so an id belonging to somebody else
   * cannot be marked - the id alone is not authorisation.
   */
  async markRead(userId: string, ids: readonly string[], executor?: SqlExecutor): Promise<number> {
    if (ids.length === 0) {
      const result = await execute(
        `UPDATE security_notifications
            SET read_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND read_at IS NULL`,
        [userId],
        executor,
      );
      return result.affectedRows;
    }

    const placeholders = ids.map(() => '?').join(', ');
    const result = await execute(
      `UPDATE security_notifications
          SET read_at = CURRENT_TIMESTAMP(3)
        WHERE user_id = ? AND read_at IS NULL AND id IN (${placeholders})`,
      [userId, ...ids],
      executor,
    );
    return result.affectedRows;
  },

  async remove(userId: string, id: string, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute(
      'DELETE FROM security_notifications WHERE user_id = ? AND id = ?',
      [userId, id],
      executor,
    );
    return result.affectedRows > 0;
  },

  /**
   * Was an equivalent notification raised recently?
   *
   * Deduplication window for repeating events. Without it, five failed logins in
   * a minute produce five identical alerts and the user learns to ignore the
   * bell - which defeats the purpose of having one.
   */
  async existsRecent(
    userId: string,
    type: NotificationType,
    withinMinutes: number,
    executor?: SqlExecutor,
  ): Promise<boolean> {
    const row = await queryOne<RowDataPacket & { found: number }>(
      `SELECT 1 AS found FROM security_notifications
        WHERE user_id = ? AND type = ?
          AND created_at > DATE_SUB(CURRENT_TIMESTAMP(3), INTERVAL ? MINUTE)
        LIMIT 1`,
      [userId, type, withinMinutes],
      executor,
    );
    return row !== null;
  },

  /** Prune read notifications older than `days`, for the maintenance job. */
  async pruneOlderThan(days: number, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `DELETE FROM security_notifications
        WHERE read_at IS NOT NULL
          AND created_at < DATE_SUB(CURRENT_TIMESTAMP(3), INTERVAL ? DAY)`,
      [days],
      executor,
    );
    return result.affectedRows;
  },
};

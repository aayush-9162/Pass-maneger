/**
 * Session repository.
 *
 * The interesting method is {@link sessionRepository.rotate}: refresh-token
 * rotation is expressed as a single conditional UPDATE that also matches on the
 * *current* token hash. If two requests race with the same refresh token, MySQL
 * lets exactly one of them win and the loser sees `affectedRows === 0`, which the
 * service treats as token reuse. Doing the check with a SELECT followed by an
 * UPDATE would leave a window in which both requests succeed.
 */

import { SESSION_STATUS, type SessionRevokeReason } from '@passm/shared';

import {
  execute,
  query,
  queryOne,
  type RowDataPacket,
  type SqlExecutor,
  type SqlParam,
} from '../config/database';
import { mapSessionRow, type SessionRecord, type SessionRow } from '../models/session.model';
import { newId } from '../utils/ids';
import { limitClause, limitOffsetClause } from '../utils/sql';

const SESSION_COLUMNS = `
  s.id, s.user_id, s.device_id,
  s.refresh_token_hash, s.previous_refresh_token_hash, s.refresh_token_generation,
  s.status, s.ip_address, s.user_agent,
  s.created_at, s.last_activity_at, s.expires_at, s.revoked_at, s.revoked_reason
`;

/** Session plus the device labels needed by the "where am I signed in" view. */
const SESSION_COLUMNS_WITH_DEVICE = `
  ${SESSION_COLUMNS},
  d.name AS device_name,
  d.device_id AS device_client_id
`;

const SESSION_SOURCE_WITH_DEVICE = `
  FROM sessions s
  LEFT JOIN devices d ON d.id = s.device_id
`;

export interface CreateSessionInput {
  /**
   * Caller-supplied primary key.
   *
   * The session id has to exist *before* the row is written, because it is a
   * claim inside the refresh token whose hash the row stores. Generating it in
   * the service breaks that circular dependency without a second UPDATE.
   */
  id?: string;
  userId: string;
  deviceRowId: string | null;
  refreshTokenHash: string;
  expiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
}

interface CountRow extends RowDataPacket {
  total: number;
}

interface IdRow extends RowDataPacket {
  id: string;
}

export const sessionRepository = {
  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  async findById(id: string, executor?: SqlExecutor): Promise<SessionRecord | null> {
    const row = await queryOne<SessionRow>(
      `SELECT ${SESSION_COLUMNS_WITH_DEVICE} ${SESSION_SOURCE_WITH_DEVICE} WHERE s.id = ? LIMIT 1`,
      [id],
      executor,
    );
    return row ? mapSessionRow(row) : null;
  },

  /** Look up a session by the hash of its *current* refresh token. */
  async findByRefreshTokenHash(
    tokenHash: string,
    executor?: SqlExecutor,
  ): Promise<SessionRecord | null> {
    const row = await queryOne<SessionRow>(
      `SELECT ${SESSION_COLUMNS} FROM sessions s WHERE s.refresh_token_hash = ? LIMIT 1`,
      [tokenHash],
      executor,
    );
    return row ? mapSessionRow(row) : null;
  },

  /**
   * Look up a session by the hash of a *superseded* refresh token.
   *
   * A hit means an already-redeemed token was presented again: either the token
   * leaked, or a client is retrying. Both are handled as compromise, because the
   * two cannot be distinguished server-side.
   */
  async findByPreviousRefreshTokenHash(
    tokenHash: string,
    executor?: SqlExecutor,
  ): Promise<SessionRecord | null> {
    const row = await queryOne<SessionRow>(
      `SELECT ${SESSION_COLUMNS} FROM sessions s
        WHERE s.previous_refresh_token_hash = ? LIMIT 1`,
      [tokenHash],
      executor,
    );
    return row ? mapSessionRow(row) : null;
  },

  /** Sessions for a user, newest first. */
  async listByUser(
    userId: string,
    options: { activeOnly?: boolean; limit?: number } = {},
    executor?: SqlExecutor,
  ): Promise<SessionRecord[]> {
    const activeOnly = options.activeOnly ?? true;
    const limit = Math.min(Math.max(Math.floor(options.limit ?? 100), 1), 200);

    const conditions = ['s.user_id = ?'];
    const params: SqlParam[] = [userId];

    if (activeOnly) {
      conditions.push('s.status = ?');
      conditions.push('s.expires_at > NOW(3)');
      params.push(SESSION_STATUS.ACTIVE);
    }

    const rows = await query<SessionRow>(
      `SELECT ${SESSION_COLUMNS_WITH_DEVICE}
         ${SESSION_SOURCE_WITH_DEVICE}
        WHERE ${conditions.join(' AND ')}
        ORDER BY s.last_activity_at DESC
        ${limitClause(limit, 200)}`,
      [...params],
      executor,
    );

    return rows.map(mapSessionRow);
  },

  async countActiveForUser(userId: string, executor?: SqlExecutor): Promise<number> {
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM sessions
        WHERE user_id = ? AND status = ? AND expires_at > NOW(3)`,
      [userId, SESSION_STATUS.ACTIVE],
      executor,
    );
    return row?.total ?? 0;
  },

  /**
   * Ids of the oldest active sessions beyond `keep`.
   * Used to enforce MAX_ACTIVE_SESSIONS_PER_USER by evicting least-recently-used.
   */
  async findOldestActiveSessionIds(
    userId: string,
    keep: number,
    executor?: SqlExecutor,
  ): Promise<string[]> {
    /**
     * `OFFSET` is interpolated as a validated literal, not bound.
     *
     * MySQL's binary protocol rejects a placeholder in `LIMIT`/`OFFSET` -
     * `execute()` fails with "Incorrect arguments to mysqld_stmt_execute". The
     * rest of the codebase was swept for this in Phase 4; this call site
     * survived because it only runs once a user exceeds the concurrent-session
     * limit, which no test had done until now. See `utils/sql.ts`.
     */
    const safeKeep = Math.min(Math.max(Math.floor(keep) || 0, 0), 100);
    const rows = await query<IdRow>(
      `SELECT id FROM sessions
        WHERE user_id = ? AND status = ? AND expires_at > NOW(3)
        ORDER BY last_activity_at ASC
        ${limitOffsetClause(100, safeKeep)}`,
      [userId, SESSION_STATUS.ACTIVE],
      executor,
    );
    return rows.map((row) => row.id);
  },

  // -------------------------------------------------------------------------
  // Writes
  // -------------------------------------------------------------------------

  async create(input: CreateSessionInput, executor?: SqlExecutor): Promise<string> {
    const id = input.id ?? newId();
    await execute(
      `INSERT INTO sessions (
         id, user_id, device_id, refresh_token_hash, refresh_token_generation,
         status, ip_address, user_agent, expires_at
       ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)`,
      [
        id,
        input.userId,
        input.deviceRowId,
        input.refreshTokenHash,
        SESSION_STATUS.ACTIVE,
        input.ipAddress,
        input.userAgent,
        input.expiresAt,
      ],
      executor,
    );
    return id;
  },

  /**
   * Atomically rotate the refresh token.
   *
   * @returns `true` when this caller won the rotation. `false` means the session
   *   was not active, or the presented token was no longer current - the service
   *   must treat that as replay.
   */
  async rotate(
    sessionId: string,
    expectedCurrentHash: string,
    newHash: string,
    expiresAt: Date,
    ipAddress: string | null,
    userAgent: string | null,
    executor?: SqlExecutor,
  ): Promise<boolean> {
    const result = await execute(
      `UPDATE sessions
          SET previous_refresh_token_hash = refresh_token_hash,
              refresh_token_hash = ?,
              refresh_token_generation = refresh_token_generation + 1,
              last_activity_at = NOW(3),
              expires_at = ?,
              ip_address = ?,
              user_agent = ?
        WHERE id = ?
          AND status = ?
          AND refresh_token_hash = ?
          AND expires_at > NOW(3)`,
      [
        newHash,
        expiresAt,
        ipAddress,
        userAgent,
        sessionId,
        SESSION_STATUS.ACTIVE,
        expectedCurrentHash,
      ],
      executor,
    );
    return result.affectedRows === 1;
  },

  /** Bump `last_activity_at` (drives the idle-timeout policy). */
  async touch(sessionId: string, executor?: SqlExecutor): Promise<void> {
    await execute(
      'UPDATE sessions SET last_activity_at = NOW(3) WHERE id = ? AND status = ?',
      [sessionId, SESSION_STATUS.ACTIVE],
      executor,
    );
  },

  /** Revoke one session. Idempotent: re-revoking is a no-op. */
  async revoke(
    sessionId: string,
    reason: SessionRevokeReason,
    executor?: SqlExecutor,
  ): Promise<boolean> {
    const result = await execute(
      `UPDATE sessions
          SET status = ?, revoked_at = NOW(3), revoked_reason = ?
        WHERE id = ? AND status = ?`,
      [SESSION_STATUS.REVOKED, reason, sessionId, SESSION_STATUS.ACTIVE],
      executor,
    );
    return result.affectedRows === 1;
  },

  /**
   * Revoke every active session for a user.
   * @param exceptSessionId Keep this session alive (used by "sign out everywhere
   *   else" and by password change, where the current session stays valid).
   * @returns number of sessions revoked.
   */
  async revokeAllForUser(
    userId: string,
    reason: SessionRevokeReason,
    exceptSessionId?: string,
    executor?: SqlExecutor,
  ): Promise<number> {
    const params: SqlParam[] = [SESSION_STATUS.REVOKED, reason, userId, SESSION_STATUS.ACTIVE];
    let extra = '';

    if (exceptSessionId) {
      extra = ' AND id <> ?';
      params.push(exceptSessionId);
    }

    const result = await execute(
      `UPDATE sessions
          SET status = ?, revoked_at = NOW(3), revoked_reason = ?
        WHERE user_id = ? AND status = ?${extra}`,
      params,
      executor,
    );
    return result.affectedRows;
  },

  /**
   * Active sessions not held by members of `exemptRole`.
   *
   * Ids only - the caller revokes them one at a time so each cache entry is
   * dropped individually, and a bulk UPDATE would leave stale entries behind.
   * Capped so an emergency lock on a large tenant cannot exhaust memory.
   */
  async listActiveExceptRole(
    exemptRole: string,
    executor?: SqlExecutor,
  ): Promise<{ id: string }[]> {
    return query<RowDataPacket & { id: string }>(
      `SELECT s.id
         FROM sessions s
         INNER JOIN users u ON u.id = s.user_id
         INNER JOIN roles r ON r.id = u.role_id
        WHERE s.status = ?
          AND r.name <> ?
        ${limitClause(10000, 10000)}`,
      [SESSION_STATUS.ACTIVE, exemptRole],
      executor,
    );
  },

  /** Revoke every active session bound to a device (device trust withdrawn). */
  async revokeAllForDevice(
    deviceRowId: string,
    reason: SessionRevokeReason,
    executor?: SqlExecutor,
  ): Promise<number> {
    const result = await execute(
      `UPDATE sessions
          SET status = ?, revoked_at = NOW(3), revoked_reason = ?
        WHERE device_id = ? AND status = ?`,
      [SESSION_STATUS.REVOKED, reason, deviceRowId, SESSION_STATUS.ACTIVE],
      executor,
    );
    return result.affectedRows;
  },

  // -------------------------------------------------------------------------
  // Maintenance
  // -------------------------------------------------------------------------

  /** Flip absolutely-expired sessions to `expired` so listings stay truthful. */
  async markExpiredSessions(executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE sessions
          SET status = ?
        WHERE status = ? AND expires_at <= NOW(3)`,
      [SESSION_STATUS.EXPIRED, SESSION_STATUS.ACTIVE],
      executor,
    );
    return result.affectedRows;
  },

  /**
   * Delete terminated sessions older than `days`.
   *
   * Active sessions are never deleted here regardless of age; audit history lives
   * in `audit_logs`, so pruning this table loses no compliance data.
   */
  async deleteTerminatedOlderThan(days: number, executor?: SqlExecutor): Promise<number> {
    const safeDays = Math.min(Math.max(Math.floor(days), 1), 3650);
    const result = await execute(
      `DELETE FROM sessions
        WHERE status <> ?
          AND COALESCE(revoked_at, expires_at) < DATE_SUB(NOW(3), INTERVAL ? DAY)
        LIMIT 5000`,
      [SESSION_STATUS.ACTIVE, safeDays],
      executor,
    );
    return result.affectedRows;
  },
};

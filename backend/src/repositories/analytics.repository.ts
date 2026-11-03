/**
 * Read-only aggregates for the administrative and security dashboards.
 *
 * Kept apart from the entity repositories because the queries have a different
 * shape and a different risk profile: they are wide GROUP BYs over the two
 * highest-volume tables in the schema (`audit_logs`, `login_attempts`), every
 * one is bounded by a date window, and none of them is on a request path a user
 * can trigger without holding `analytics:read`.
 *
 * Every series is generated with a calendar join so that a day with no activity
 * appears as a zero rather than being missing. A chart that silently omits empty
 * days compresses the x-axis and makes a quiet weekend look like a busy one.
 */

import type {
  AdminDeviceRow,
  AdminSessionRow,
  RoleName,
  TimeSeriesPoint,
} from '@passm/shared';
import { AUDIT_ACTIONS, ROLES, isRoleName } from '@passm/shared';

import {
  query,
  queryOne,
  type RowDataPacket,
  type SqlExecutor,
  type SqlParam,
} from '../config/database';
import { toIso, toIsoRequired } from '../utils/date';
import { likePattern, limitClause, limitOffsetClause, resolvePagination, resolveSortColumn, resolveSortDirection } from '../utils/sql';

/** Longest window the dashboard will aggregate over, in days. */
const MAX_WINDOW_DAYS = 90;

function clampWindow(days: number): number {
  if (!Number.isFinite(days)) return 30;
  return Math.min(Math.max(Math.floor(days), 1), MAX_WINDOW_DAYS);
}

/**
 * Fill gaps in a sparse daily series.
 *
 * Done in JavaScript rather than with a recursive CTE: the calendar is at most
 * 90 rows, the code is obvious, and it keeps the SQL portable across the MySQL
 * versions this project supports.
 */
function densify(
  rows: readonly { day: string; total: number }[],
  windowDays: number,
  now: Date,
): TimeSeriesPoint[] {
  const byDay = new Map(rows.map((row) => [row.day, row.total]));
  const series: TimeSeriesPoint[] = [];

  for (let offset = windowDays - 1; offset >= 0; offset -= 1) {
    const date = new Date(now.getTime() - offset * 86_400_000);
    const key = date.toISOString().slice(0, 10);
    series.push({ date: key, value: byDay.get(key) ?? 0 });
  }

  return series;
}

interface DayCountRow extends RowDataPacket {
  day: string;
  total: number;
}

const SESSION_SORT_COLUMNS = {
  lastActivityAt: 's.last_activity_at',
  createdAt: 's.created_at',
  expiresAt: 's.expires_at',
  email: 'u.email',
} as const;

const DEVICE_SORT_COLUMNS = {
  lastUsedAt: 'd.last_used_at',
  createdAt: 'd.created_at',
  name: 'd.name',
  email: 'u.email',
} as const;

interface CountRow extends RowDataPacket {
  total: number;
}

export const analyticsRepository = {
  // -------------------------------------------------------------------------
  // Activity series
  // -------------------------------------------------------------------------

  /** Successful and failed sign-ins per day, from the login-attempt feed. */
  async loginSeries(
    windowDays: number,
    executor?: SqlExecutor,
  ): Promise<{ success: TimeSeriesPoint[]; failure: TimeSeriesPoint[] }> {
    const days = clampWindow(windowDays);
    const now = new Date();

    const rows = await query<RowDataPacket & { day: string; successful: number; total: number }>(
      `SELECT DATE_FORMAT(created_at, '%Y-%m-%d') AS day, successful, COUNT(*) AS total
         FROM login_attempts
        WHERE created_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
        GROUP BY day, successful`,
      [days],
      executor,
    );

    const success = rows
      .filter((row) => Number(row.successful) === 1)
      .map((row) => ({ day: row.day, total: Number(row.total) }));
    const failure = rows
      .filter((row) => Number(row.successful) === 0)
      .map((row) => ({ day: row.day, total: Number(row.total) }));

    return {
      success: densify(success, days, now),
      failure: densify(failure, days, now),
    };
  },

  /**
   * Vault writes per day.
   *
   * Counted from `vault_items.updated_at`, not from the audit trail: item-level
   * writes are deliberately not audited (see `AUDIT_ACTIONS`), because a trail
   * managers can read should not become a record of when each person opened
   * which credential. A daily count carries no such detail.
   */
  async vaultWriteSeries(windowDays: number, executor?: SqlExecutor): Promise<TimeSeriesPoint[]> {
    const days = clampWindow(windowDays);

    // Personal vaults are gone, so every write is a shared-vault write. The
    // merge below is kept rather than collapsed: it costs nothing, and it is the
    // shape this returns to callers.
    const personal: DayCountRow[] = [];

    const shared = await query<DayCountRow>(
      `SELECT DATE_FORMAT(updated_at, '%Y-%m-%d') AS day, COUNT(*) AS total
         FROM shared_vault_items
        WHERE updated_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
        GROUP BY day`,
      [days],
      executor,
    );

    const merged = new Map<string, number>();
    for (const row of [...personal, ...shared]) {
      merged.set(row.day, (merged.get(row.day) ?? 0) + Number(row.total));
    }

    return densify(
      [...merged].map(([day, total]) => ({ day, total })),
      days,
      new Date(),
    );
  },

  // -------------------------------------------------------------------------
  // Access counters
  // -------------------------------------------------------------------------

  async accessCounters(executor?: SqlExecutor): Promise<{
    activeSessions: number;
    trustedDevices: number;
    knownDevices: number;
  }> {
    const row = await queryOne<
      RowDataPacket & { active_sessions: number; trusted_devices: number; known_devices: number }
    >(
      `SELECT
         (SELECT COUNT(*) FROM sessions
           WHERE status = 'active' AND expires_at > NOW(3)) AS active_sessions,
         (SELECT COUNT(*) FROM devices
           WHERE status = 'trusted'
             AND (trust_expires_at IS NULL OR trust_expires_at > NOW(3))) AS trusted_devices,
         (SELECT COUNT(*) FROM devices WHERE status <> 'revoked') AS known_devices`,
      [],
      executor,
    );

    return {
      activeSessions: Number(row?.active_sessions ?? 0),
      trustedDevices: Number(row?.trusted_devices ?? 0),
      knownDevices: Number(row?.known_devices ?? 0),
    };
  },

  // -------------------------------------------------------------------------
  // Security signals
  // -------------------------------------------------------------------------

  /** Accounts attracting the most failed sign-ins - the credential-stuffing view. */
  async topFailedAccounts(
    windowDays: number,
    limit: number,
    executor?: SqlExecutor,
  ): Promise<{ email: string; attempts: number; lastAttemptAt: string }[]> {
    const days = clampWindow(windowDays);
    const safeLimit = Math.min(Math.max(Math.floor(limit), 1), 50);

    const rows = await query<
      RowDataPacket & { email: string; attempts: number; last_attempt: Date }
    >(
      `SELECT email, COUNT(*) AS attempts, MAX(created_at) AS last_attempt
         FROM login_attempts
        WHERE successful = 0 AND created_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
        GROUP BY email
        ORDER BY attempts DESC
        ${limitClause(safeLimit, 50)}`,
      [days],
      executor,
    );

    return rows.map((row) => ({
      email: row.email,
      attempts: Number(row.attempts),
      lastAttemptAt: toIsoRequired(row.last_attempt),
    }));
  },

  /**
   * Source addresses attracting the most failed sign-ins.
   *
   * `distinctAccounts` is the column that matters: 200 failures against one
   * account is someone who forgot their password, while 200 across 60 accounts
   * is an attack, and only the second number tells them apart.
   */
  async topFailedAddresses(
    windowDays: number,
    limit: number,
    executor?: SqlExecutor,
  ): Promise<{ ipAddress: string; attempts: number; distinctAccounts: number }[]> {
    const days = clampWindow(windowDays);
    const safeLimit = Math.min(Math.max(Math.floor(limit), 1), 50);

    const rows = await query<
      RowDataPacket & { ip_address: string; attempts: number; distinct_accounts: number }
    >(
      `SELECT ip_address, COUNT(*) AS attempts, COUNT(DISTINCT email) AS distinct_accounts
         FROM login_attempts
        WHERE successful = 0 AND created_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
        GROUP BY ip_address
        ORDER BY distinct_accounts DESC, attempts DESC
        ${limitClause(safeLimit, 50)}`,
      [days],
      executor,
    );

    return rows.map((row) => ({
      ipAddress: row.ip_address,
      attempts: Number(row.attempts),
      distinctAccounts: Number(row.distinct_accounts),
    }));
  },

  /** Accounts currently locked, by either the automatic policy or an administrator. */
  async lockedAccounts(
    executor?: SqlExecutor,
  ): Promise<
    {
      userId: string;
      email: string;
      fullName: string;
      status: string;
      lockedUntil: string | null;
    }[]
  > {
    const rows = await query<
      RowDataPacket & {
        id: string;
        email: string;
        first_name: string;
        last_name: string;
        status: string;
        locked_until: Date | null;
      }
    >(
      `SELECT id, email, first_name, last_name, status, locked_until
         FROM users
        WHERE deleted_at IS NULL
          AND (status = 'locked' OR (locked_until IS NOT NULL AND locked_until > NOW(3)))
        ORDER BY locked_until DESC
        LIMIT 100`,
      [],
      executor,
    );

    return rows.map((row) => ({
      userId: row.id,
      email: row.email,
      fullName: `${row.first_name} ${row.last_name}`.trim(),
      status: row.status,
      lockedUntil: toIso(row.locked_until),
    }));
  },

  /** Count of a given audit action within the window. */
  async countAuditAction(
    action: string,
    windowDays: number,
    executor?: SqlExecutor,
  ): Promise<number> {
    const days = clampWindow(windowDays);

    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM audit_logs
        WHERE action = ? AND created_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)`,
      [action, days],
      executor,
    );
    return row?.total ?? 0;
  },

  /** Refresh-token replays and fingerprint changes, in one pass over the window. */
  async securityEventCounts(
    windowDays: number,
    executor?: SqlExecutor,
  ): Promise<{ tokenReuse: number; fingerprintMismatch: number }> {
    const [tokenReuse, fingerprintMismatch] = await Promise.all([
      this.countAuditAction(AUDIT_ACTIONS.TOKEN_REUSE_DETECTED, windowDays, executor),
      this.countAuditAction(AUDIT_ACTIONS.DEVICE_FINGERPRINT_MISMATCH, windowDays, executor),
    ]);

    return { tokenReuse, fingerprintMismatch };
  },

  /**
   * Sessions still active well past the point anyone is using them, and trusted
   * devices nobody has touched in months.
   *
   * Both are housekeeping rather than alarms: a stale session is a token that
   * outlives its usefulness, and a dormant trusted device is standing
   * authorisation for hardware that may no longer exist.
   */
  async hygieneCounts(
    staleSessionDays: number,
    dormantDeviceDays: number,
    executor?: SqlExecutor,
  ): Promise<{ staleSessions: number; dormantTrustedDevices: number }> {
    const row = await queryOne<RowDataPacket & { stale_sessions: number; dormant_devices: number }>(
      `SELECT
         (SELECT COUNT(*) FROM sessions
           WHERE status = 'active'
             AND last_activity_at < DATE_SUB(NOW(3), INTERVAL ? DAY)) AS stale_sessions,
         (SELECT COUNT(*) FROM devices
           WHERE status = 'trusted'
             AND (last_used_at IS NULL OR last_used_at < DATE_SUB(NOW(3), INTERVAL ? DAY)))
           AS dormant_devices`,
      [clampWindow(staleSessionDays), Math.min(Math.max(dormantDeviceDays, 1), 365)],
      executor,
    );

    return {
      staleSessions: Number(row?.stale_sessions ?? 0),
      dormantTrustedDevices: Number(row?.dormant_devices ?? 0),
    };
  },

  // -------------------------------------------------------------------------
  // Tenant-wide session and device listings
  // -------------------------------------------------------------------------

  async listSessions(
    filter: {
      page?: number;
      pageSize?: number;
      sortBy?: string;
      sortDir?: string;
      search?: string;
      userId?: string;
      status?: string;
    } = {},
    executor?: SqlExecutor,
  ): Promise<{ items: AdminSessionRow[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['u.deleted_at IS NULL'];
    const params: SqlParam[] = [];

    // Default to live sessions: the table is an operational view, and expired
    // rows would bury the handful an administrator actually needs to act on.
    if (filter.status) {
      conditions.push('s.status = ?');
      params.push(filter.status);
    } else {
      conditions.push("s.status = 'active' AND s.expires_at > NOW(3)");
    }

    if (filter.userId) {
      conditions.push('s.user_id = ?');
      params.push(filter.userId);
    }
    if (filter.search) {
      conditions.push('(u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR s.ip_address LIKE ?)');
      const pattern = likePattern(filter.search);
      params.push(pattern, pattern, pattern, pattern);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const orderColumn = resolveSortColumn(filter.sortBy, SESSION_SORT_COLUMNS, 'lastActivityAt');
    const orderDirection = resolveSortDirection(filter.sortDir);

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total
         FROM sessions s
        INNER JOIN users u ON u.id = s.user_id
        ${where}`,
      params,
      executor,
    );

    const rows = await query<
      RowDataPacket & {
        id: string;
        user_id: string;
        email: string;
        first_name: string;
        last_name: string;
        role_name: string;
        device_row_id: string | null;
        device_name: string | null;
        platform: string | null;
        ip_address: string | null;
        user_agent: string | null;
        status: string;
        created_at: Date;
        last_activity_at: Date;
        expires_at: Date;
      }
    >(
      `SELECT s.id, s.user_id, u.email, u.first_name, u.last_name, r.name AS role_name,
              s.device_id AS device_row_id, d.name AS device_name, d.platform,
              s.ip_address, s.user_agent, s.status,
              s.created_at, s.last_activity_at, s.expires_at
         FROM sessions s
        INNER JOIN users u ON u.id = s.user_id
        INNER JOIN roles r ON r.id = u.role_id
         LEFT JOIN devices d ON d.id = s.device_id
        ${where}
        ORDER BY ${orderColumn} ${orderDirection}, s.id ASC
        ${limitOffsetClause(limit, offset)}`,
      [...params],
      executor,
    );

    return {
      items: rows.map((row) => ({
        id: row.id,
        userId: row.user_id,
        email: row.email,
        fullName: `${row.first_name} ${row.last_name}`.trim(),
        role: (isRoleName(row.role_name) ? row.role_name : ROLES.EMPLOYEE) as RoleName,
        deviceId: row.device_row_id,
        deviceName: row.device_name,
        platform: row.platform,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        status: row.status,
        createdAt: toIsoRequired(row.created_at),
        lastActivityAt: toIsoRequired(row.last_activity_at),
        expiresAt: toIsoRequired(row.expires_at),
      })),
      total: countRow?.total ?? 0,
      page,
      pageSize,
    };
  },

  async listDevices(
    filter: {
      page?: number;
      pageSize?: number;
      sortBy?: string;
      sortDir?: string;
      search?: string;
      userId?: string;
      status?: string;
      platform?: string;
    } = {},
    executor?: SqlExecutor,
  ): Promise<{ items: AdminDeviceRow[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['u.deleted_at IS NULL'];
    const params: SqlParam[] = [];

    if (filter.status) {
      conditions.push('d.status = ?');
      params.push(filter.status);
    }
    if (filter.platform) {
      conditions.push('d.platform = ?');
      params.push(filter.platform);
    }
    if (filter.userId) {
      conditions.push('d.user_id = ?');
      params.push(filter.userId);
    }
    if (filter.search) {
      conditions.push('(u.email LIKE ? OR d.name LIKE ? OR d.last_ip_address LIKE ?)');
      const pattern = likePattern(filter.search);
      params.push(pattern, pattern, pattern);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const orderColumn = resolveSortColumn(filter.sortBy, DEVICE_SORT_COLUMNS, 'lastUsedAt');
    const orderDirection = resolveSortDirection(filter.sortDir);

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total
         FROM devices d
        INNER JOIN users u ON u.id = d.user_id
        ${where}`,
      params,
      executor,
    );

    const rows = await query<
      RowDataPacket & {
        id: string;
        user_id: string;
        email: string;
        first_name: string;
        last_name: string;
        device_id: string;
        name: string;
        platform: string;
        status: string;
        trust_expires_at: Date | null;
        last_ip_address: string | null;
        last_used_at: Date | null;
        created_at: Date;
        active_session_count: number;
      }
    >(
      `SELECT d.id, d.user_id, u.email, u.first_name, u.last_name,
              d.device_id, d.name, d.platform, d.status, d.trust_expires_at,
              d.last_ip_address, d.last_used_at, d.created_at,
              (SELECT COUNT(*) FROM sessions s
                WHERE s.device_id = d.id AND s.status = 'active' AND s.expires_at > NOW(3))
                AS active_session_count
         FROM devices d
        INNER JOIN users u ON u.id = d.user_id
        ${where}
        ORDER BY ${orderColumn} ${orderDirection}, d.id ASC
        ${limitOffsetClause(limit, offset)}`,
      [...params],
      executor,
    );

    return {
      items: rows.map((row) => ({
        id: row.id,
        userId: row.user_id,
        email: row.email,
        fullName: `${row.first_name} ${row.last_name}`.trim(),
        deviceId: row.device_id,
        name: row.name,
        platform: row.platform,
        status: row.status,
        trusted:
          row.status === 'trusted' &&
          (row.trust_expires_at === null || row.trust_expires_at.getTime() > Date.now()),
        trustExpiresAt: toIso(row.trust_expires_at),
        lastIpAddress: row.last_ip_address,
        lastUsedAt: toIso(row.last_used_at),
        activeSessionCount: Number(row.active_session_count),
        createdAt: toIsoRequired(row.created_at),
      })),
      total: countRow?.total ?? 0,
      page,
      pageSize,
    };
  },
};

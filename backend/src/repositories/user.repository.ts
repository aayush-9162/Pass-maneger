/**
 * User repository.
 *
 * Every statement in this file uses `?` placeholders and is executed as a
 * prepared statement, so values are bound by MySQL and can never be parsed as
 * SQL. The two places where SQL text is assembled dynamically are:
 *
 *   1. `ORDER BY` in {@link userRepository.list} - resolved through
 *      `resolveSortColumn`, an explicit allow-list.
 *   2. The `SET` clause in {@link userRepository.updateProfile} - built from a
 *      fixed column map; only the *values* are dynamic.
 *
 * Nothing else concatenates caller input into a statement.
 */

import type { RoleName, UserStatus } from '@passm/shared';
import { USER_STATUS } from '@passm/shared';

import { execute, query, queryOne, type SqlExecutor, type SqlParam } from '../config/database';
import { mapUserRow, type UserRecord, type UserRow } from '../models/user.model';
import { newId } from '../utils/ids';
import { likePattern, limitClause, limitOffsetClause, resolvePagination, resolveSortColumn, resolveSortDirection } from '../utils/sql';
import type { RowDataPacket } from '../config/database';

/**
 * Column list, aliased for the `roles` join.
 *
 * Written out explicitly rather than `SELECT *`: an added column then cannot
 * silently start flowing into the application, and the mapper stays honest.
 */
const USER_COLUMNS = `
  u.id, u.email, u.google_subject,
  u.first_name, u.last_name, u.job_title,
  u.role_id, u.status,
  u.locked_until, u.lock_reason, u.locked_by_user_id,
  u.last_login_at, u.last_login_ip,
  u.created_by, u.created_at, u.updated_at, u.deleted_at,
  r.name AS role_name, r.level AS role_level
`;

/** Source clause. The roles join is a primary-key lookup against a three-row table. */
const USER_SOURCE = `
  FROM users u
  INNER JOIN roles r ON r.id = u.role_id
`;

/** Sortable columns for the admin listing - the allow-list for `ORDER BY`. */
const USER_SORT_COLUMNS = {
  createdAt: 'u.created_at',
  email: 'u.email',
  lastName: 'u.last_name',
  lastLoginAt: 'u.last_login_at',
  status: 'u.status',
  role: 'r.level',
} as const;

export interface CreateUserInput {
  email: string;
  firstName: string;
  lastName: string;
  roleId: string;
  status: UserStatus;
  jobTitle?: string | undefined;
  createdBy?: string | undefined;
}

export interface UpdateUserProfileInput {
  firstName?: string | undefined;
  lastName?: string | undefined;
  jobTitle?: string | undefined;
}

export interface ListUsersFilter {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortDir?: string;
  search?: string;
  role?: RoleName;
  status?: UserStatus;
  /** Restrict to people granted one password group. */
  groupId?: string;
}

/** Admin listing row: the user plus operational counters. */
interface AdminUserRow extends UserRow {
  active_session_count: number;
  trusted_device_count: number;
  shared_vault_count: number;
}

export interface AdminUserRecord extends UserRecord {
  activeSessionCount: number;
  trustedDeviceCount: number;
  sharedVaultCount: number;
}

interface CountRow extends RowDataPacket {
  total: number;
}

interface IdRow extends RowDataPacket {
  id: string;
}

export const userRepository = {
  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  /** Active (non-soft-deleted) user by id. */
  async findById(id: string, executor?: SqlExecutor): Promise<UserRecord | null> {
    const row = await queryOne<UserRow>(
      `SELECT ${USER_COLUMNS} ${USER_SOURCE} WHERE u.id = ? AND u.deleted_at IS NULL LIMIT 1`,
      [id],
      executor,
    );
    return row ? mapUserRow(row) : null;
  },

  /**
   * Active user by email.
   *
   * The caller must pass an already-lowercased address; the DTO layer guarantees
   * that, and `chk_users_email_lowercase` guarantees the stored side.
   */
  async findByEmail(email: string, executor?: SqlExecutor): Promise<UserRecord | null> {
    const row = await queryOne<UserRow>(
      `SELECT ${USER_COLUMNS} ${USER_SOURCE} WHERE u.email = ? AND u.deleted_at IS NULL LIMIT 1`,
      [email],
      executor,
    );
    return row ? mapUserRow(row) : null;
  },

  /** Active user by Google account id (`sub`). */
  async findByGoogleSubject(subject: string, executor?: SqlExecutor): Promise<UserRecord | null> {
    const row = await queryOne<UserRow>(
      `SELECT ${USER_COLUMNS} ${USER_SOURCE} WHERE u.google_subject = ? AND u.deleted_at IS NULL LIMIT 1`,
      [subject],
      executor,
    );
    return row ? mapUserRow(row) : null;
  },

  /**
   * Link a Google account to this user.
   *
   * Guarded by `IS NULL` so a link, once made, cannot be silently moved to a
   * different Google account. Returns false when the row was already linked.
   */
  async linkGoogleSubject(id: string, subject: string, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute(
      `UPDATE users SET google_subject = ?
        WHERE id = ? AND google_subject IS NULL AND deleted_at IS NULL`,
      [subject, id],
      executor,
    );
    return result.affectedRows > 0;
  },

  /**
   * Count users holding a role who can still sign in.
   *
   * Used to refuse the change that would remove the last usable administrator -
   * an account state nobody can recover from without direct database access.
   */
  async countUsableByRole(role: RoleName, executor?: SqlExecutor): Promise<number> {
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total
         FROM users u
         INNER JOIN roles r ON r.id = u.role_id
        WHERE r.name = ?
          AND u.deleted_at IS NULL
          AND u.status IN (?, ?, ?)`,
      [role, USER_STATUS.ACTIVE, USER_STATUS.PENDING, USER_STATUS.LOCKED],
      executor,
    );
    return row?.total ?? 0;
  },

  /**
   * Ids of everyone holding a role, for fanning an alert out to them.
   *
   * Active accounts only - unlike {@link countUsableByRole}, which counts
   * locked and pending administrators too because they can still be restored.
   * A notification for somebody who cannot sign in is just an unread row.
   */
  async listActiveIdsByRole(role: RoleName, executor?: SqlExecutor): Promise<string[]> {
    const rows = await query<IdRow>(
      `SELECT u.id
         FROM users u
         INNER JOIN roles r ON r.id = u.role_id
        WHERE r.name = ?
          AND u.deleted_at IS NULL
          AND u.status = ?`,
      [role, USER_STATUS.ACTIVE],
      executor,
    );
    return rows.map((row) => row.id);
  },

  /** Cheap existence check for provisioning. */
  async existsByEmail(email: string, executor?: SqlExecutor): Promise<boolean> {
    const row = await queryOne<CountRow>(
      'SELECT COUNT(*) AS total FROM users WHERE email = ? AND deleted_at IS NULL',
      [email],
      executor,
    );
    return (row?.total ?? 0) > 0;
  },

  /**
   * Paginated admin listing with per-user session/device counters.
   *
   * The counters are correlated subqueries rather than JOIN+GROUP BY: with
   * `idx_sessions_user_status` and `idx_devices_user_status` each is an index
   * lookup, and it avoids row multiplication across two one-to-many joins.
   */
  async list(
    filter: ListUsersFilter = {},
    executor?: SqlExecutor,
  ): Promise<{ items: AdminUserRecord[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['u.deleted_at IS NULL'];
    const params: SqlParam[] = [];

    if (filter.search) {
      conditions.push('(u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)');
      const pattern = likePattern(filter.search);
      params.push(pattern, pattern, pattern);
    }
    if (filter.role) {
      conditions.push('r.name = ?');
      params.push(filter.role);
    }
    if (filter.status) {
      conditions.push('u.status = ?');
      params.push(filter.status);
    }
    if (filter.groupId) {
      // "In this group" now means "granted this password group (vault)".
      conditions.push(
        `EXISTS (SELECT 1 FROM shared_vault_grants g
                  WHERE g.shared_vault_id = ? AND g.subject_type = 'user' AND g.subject_id = u.id)`,
      );
      params.push(filter.groupId);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const orderColumn = resolveSortColumn(filter.sortBy, USER_SORT_COLUMNS, 'createdAt');
    const orderDirection = resolveSortDirection(filter.sortDir);

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total ${USER_SOURCE} ${where}`,
      params,
      executor,
    );

    const rows = await query<AdminUserRow>(
      `SELECT ${USER_COLUMNS},
              (SELECT COUNT(*) FROM sessions s
                WHERE s.user_id = u.id AND s.status = 'active' AND s.expires_at > NOW(3))
                AS active_session_count,
              (SELECT COUNT(*) FROM devices d
                WHERE d.user_id = u.id AND d.status = 'trusted'
                  AND (d.trust_expires_at IS NULL OR d.trust_expires_at > NOW(3)))
                AS trusted_device_count,
              -- Password groups and individual items granted to this user.
              -- Grants name users directly, so one EXISTS-free subquery is the
              -- whole answer.
              (SELECT COUNT(*) FROM shared_vault_grants g
                WHERE g.subject_type = 'user' AND g.subject_id = u.id)
                AS shared_vault_count
         ${USER_SOURCE}
         ${where}
         ORDER BY ${orderColumn} ${orderDirection}, u.id ASC
         ${limitOffsetClause(limit, offset)}`,
      [...params],
      executor,
    );

    return {
      items: rows.map((row) => ({
        ...mapUserRow(row),
        activeSessionCount: Number(row.active_session_count),
        trustedDeviceCount: Number(row.trusted_device_count),
        sharedVaultCount: Number(row.shared_vault_count),
      })),
      total: countRow?.total ?? 0,
      page,
      pageSize,
    };
  },

  /** Counts by status, for the dashboard. One pass rather than four queries. */
  async countByStatus(executor?: SqlExecutor): Promise<Record<string, number>> {
    const rows = await query<RowDataPacket & { status: string; total: number }>(
      `SELECT u.status, COUNT(*) AS total
         FROM users u
        WHERE u.deleted_at IS NULL
        GROUP BY u.status`,
      [],
      executor,
    );

    return Object.fromEntries(rows.map((row) => [row.status, Number(row.total)]));
  },

  /**
   * Active non-administrator ids, for the emergency-lock announcement.
   *
   * Ids only, and capped: during an incident this must not become a full table
   * scan materialising every user row into memory.
   */
  async findActiveNonAdminIds(executor?: SqlExecutor): Promise<string[]> {
    const rows = await query<RowDataPacket & { id: string }>(
      `SELECT u.id
         FROM users u
         INNER JOIN roles r ON r.id = u.role_id
        WHERE u.deleted_at IS NULL
          AND u.status = ?
          AND r.name <> 'admin'
        ${limitClause(5000, 5000)}`,
      [USER_STATUS.ACTIVE],
      executor,
    );
    return rows.map((row) => row.id);
  },

  /** Counts by role name, for the dashboard. */
  async countByRole(executor?: SqlExecutor): Promise<Record<string, number>> {
    const rows = await query<RowDataPacket & { role_name: string; total: number }>(
      `SELECT r.name AS role_name, COUNT(*) AS total
         FROM users u
        INNER JOIN roles r ON r.id = u.role_id
        WHERE u.deleted_at IS NULL
        GROUP BY r.name`,
      [],
      executor,
    );

    return Object.fromEntries(rows.map((row) => [row.role_name, Number(row.total)]));
  },

  /**
   * Headline counts for the dashboard, in one statement.
   */
  async dashboardCounters(executor?: SqlExecutor): Promise<{
    activeLast30Days: number;
    newLast30Days: number;
  }> {
    const row = await queryOne<
      RowDataPacket & {
        active_last_30: number;
        new_last_30: number;
      }
    >(
      `SELECT
         SUM(CASE WHEN u.last_login_at >= DATE_SUB(NOW(3), INTERVAL 30 DAY) THEN 1 ELSE 0 END)
           AS active_last_30,
         SUM(CASE WHEN u.created_at >= DATE_SUB(NOW(3), INTERVAL 30 DAY) THEN 1 ELSE 0 END)
           AS new_last_30
       FROM users u
       WHERE u.deleted_at IS NULL`,
      [],
      executor,
    );

    return {
      activeLast30Days: Number(row?.active_last_30 ?? 0),
      newLast30Days: Number(row?.new_last_30 ?? 0),
    };
  },

  // -------------------------------------------------------------------------
  // Writes
  // -------------------------------------------------------------------------

  /**
   * Insert a user and return the generated id.
   *
   * A duplicate email surfaces as `ER_DUP_ENTRY`; the service translates that
   * into a 409 rather than pre-checking, which would leave a race window.
   */
  async create(input: CreateUserInput, executor?: SqlExecutor): Promise<string> {
    const id = newId();

    await execute(
      `INSERT INTO users (id, email, first_name, last_name, job_title, role_id, status, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        input.email,
        input.firstName,
        input.lastName,
        input.jobTitle ?? null,
        input.roleId,
        input.status,
        input.createdBy ?? null,
      ],
      executor,
    );

    return id;
  },

  /**
   * Update profile fields.
   *
   * The SET clause is assembled from a fixed column map, so no caller string
   * ever becomes SQL - only bound values change.
   *
   * @returns number of rows affected (0 when nothing was supplied).
   */
  async updateProfile(
    id: string,
    input: UpdateUserProfileInput,
    executor?: SqlExecutor,
  ): Promise<number> {
    const columnMap: Record<keyof UpdateUserProfileInput, string> = {
      firstName: 'first_name',
      lastName: 'last_name',
      jobTitle: 'job_title',
    };

    const assignments: string[] = [];
    const params: SqlParam[] = [];

    for (const [key, column] of Object.entries(columnMap) as [
      keyof UpdateUserProfileInput,
      string,
    ][]) {
      const value = input[key];
      if (value === undefined) continue;
      assignments.push(`${column} = ?`);
      params.push(value);
    }

    if (assignments.length === 0) return 0;

    const result = await execute(
      `UPDATE users SET ${assignments.join(', ')} WHERE id = ? AND deleted_at IS NULL`,
      [...params, id],
      executor,
    );
    return result.affectedRows;
  },

  async updateRole(id: string, roleId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      'UPDATE users SET role_id = ? WHERE id = ? AND deleted_at IS NULL',
      [roleId, id],
      executor,
    );
    return result.affectedRows;
  },

  async updateStatus(id: string, status: UserStatus, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      'UPDATE users SET status = ? WHERE id = ? AND deleted_at IS NULL',
      [status, id],
      executor,
    );
    return result.affectedRows;
  },

  /**
   * Apply an administrative lock.
   *
   * `locked_until` is set far in the future for an open-ended lock rather than
   * left null, so the sign-in path has exactly one check: a lock in the future.
   */
  async applyAdministrativeLock(
    id: string,
    until: Date,
    reason: string | null,
    actorUserId: string,
    executor?: SqlExecutor,
  ): Promise<number> {
    const result = await execute(
      `UPDATE users
          SET status = ?, locked_until = ?, lock_reason = ?, locked_by_user_id = ?
        WHERE id = ? AND deleted_at IS NULL`,
      [USER_STATUS.LOCKED, until, reason, actorUserId, id],
      executor,
    );
    return result.affectedRows;
  },

  /**
   * Lift a lock and clear its annotation.
   *
   * `status` only returns to `active` when it is currently `locked`: a
   * suspended account must never be reactivated by a lock being lifted.
   */
  async releaseLock(id: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE users
          SET locked_until = NULL,
              lock_reason = NULL,
              locked_by_user_id = NULL,
              status = CASE WHEN status = ? THEN ? ELSE status END
        WHERE id = ? AND deleted_at IS NULL`,
      [USER_STATUS.LOCKED, USER_STATUS.ACTIVE, id],
      executor,
    );
    return result.affectedRows;
  },

  /** Record a successful sign-in; a first one moves the account out of `pending`. */
  async recordSuccessfulLogin(
    id: string,
    ipAddress: string,
    executor?: SqlExecutor,
  ): Promise<void> {
    await execute(
      `UPDATE users
          SET last_login_at = NOW(3),
              last_login_ip = ?,
              status = CASE WHEN status = ? THEN ? ELSE status END
        WHERE id = ? AND deleted_at IS NULL`,
      [ipAddress, USER_STATUS.PENDING, USER_STATUS.ACTIVE, id],
      executor,
    );
  },

  // -------------------------------------------------------------------------
  // Soft delete
  // -------------------------------------------------------------------------

  /**
   * Soft-delete a user.
   *
   * `uq_users_email` is a plain UNIQUE index, so the address is rewritten to
   * `deleted:<epoch-ms>:<email>` to free it for re-provisioning while keeping
   * the original readable in the audit trail. The Google link is cleared for the
   * same reason - the same person signing in again gets a fresh account.
   */
  async softDelete(id: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE users
          SET deleted_at = NOW(3),
              status = ?,
              google_subject = NULL,
              email = CONCAT('deleted:', UNIX_TIMESTAMP(NOW(3)), ':', email)
        WHERE id = ? AND deleted_at IS NULL`,
      [USER_STATUS.SUSPENDED, id],
      executor,
    );
    return result.affectedRows;
  },
};

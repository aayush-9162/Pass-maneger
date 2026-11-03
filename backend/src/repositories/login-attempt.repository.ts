/**
 * Login attempt repository.
 *
 * Separate from `audit_logs` on purpose: this table is high-volume, short-lived
 * and queried on the login hot path, so it is indexed and pruned for that access
 * pattern. It backs two independent defences:
 *
 *  - Per-account lockout (counter on `users`, corroborated here).
 *  - Per-IP throttling, which catches an attacker spraying one password across
 *    many accounts - a pattern per-account counters miss entirely.
 */

import { execute, queryOne, type RowDataPacket, type SqlExecutor } from '../config/database';

export interface CreateLoginAttemptInput {
  email: string;
  ipAddress: string;
  userId?: string | null;
  successful: boolean;
  failureReason?: string | null;
  userAgent?: string | null;
}

interface CountRow extends RowDataPacket {
  total: number;
}

export const loginAttemptRepository = {
  async insert(input: CreateLoginAttemptInput, executor?: SqlExecutor): Promise<void> {
    await execute(
      `INSERT INTO login_attempts (email, ip_address, user_id, successful, failure_reason, user_agent)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        input.email,
        input.ipAddress,
        input.userId ?? null,
        input.successful ? 1 : 0,
        input.failureReason ?? null,
        input.userAgent ?? null,
      ],
      executor,
    );
  },

  /** Failed attempts for an email within the last `minutes`. */
  async countRecentFailuresByEmail(
    email: string,
    minutes: number,
    executor?: SqlExecutor,
  ): Promise<number> {
    const safeMinutes = Math.min(Math.max(Math.floor(minutes), 1), 1440);
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM login_attempts
        WHERE email = ? AND successful = 0
          AND created_at > DATE_SUB(NOW(3), INTERVAL ? MINUTE)`,
      [email, safeMinutes],
      executor,
    );
    return row?.total ?? 0;
  },

  /** Failed attempts from an IP within the last `minutes`, across all accounts. */
  async countRecentFailuresByIp(
    ipAddress: string,
    minutes: number,
    executor?: SqlExecutor,
  ): Promise<number> {
    const safeMinutes = Math.min(Math.max(Math.floor(minutes), 1), 1440);
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM login_attempts
        WHERE ip_address = ? AND successful = 0
          AND created_at > DATE_SUB(NOW(3), INTERVAL ? MINUTE)`,
      [ipAddress, safeMinutes],
      executor,
    );
    return row?.total ?? 0;
  },

  /**
   * Prune old rows.
   *
   * `LIMIT` keeps each maintenance pass short so a large backlog is worked down
   * over several runs instead of holding locks for minutes at a time.
   */
  async deleteOlderThan(days: number, executor?: SqlExecutor): Promise<number> {
    const safeDays = Math.min(Math.max(Math.floor(days), 1), 3650);
    const result = await execute(
      `DELETE FROM login_attempts
        WHERE created_at < DATE_SUB(NOW(3), INTERVAL ? DAY)
        LIMIT 10000`,
      [safeDays],
      executor,
    );
    return result.affectedRows;
  },
};

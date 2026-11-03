/**
 * Step-up challenge repository.
 *
 * A challenge row has two lives: first as a pending nonce awaiting an answer,
 * then - once answered correctly - as the record that this user verified
 * recently. Keeping both in one row means the "is a verification in force?"
 * lookup is a single indexed read rather than a join.
 */

import type { StepUpAction } from '@passm/shared';

import { execute, queryOne, type RowDataPacket, type SqlExecutor } from '../config/database';
import { newId } from '../utils/ids';

interface ChallengeRow extends RowDataPacket {
  id: string;
  user_id: string;
  session_id: string | null;
  action: string;
  nonce: string;
  attempts: number;
  verified_at: Date | null;
  verified_until: Date | null;
  expires_at: Date;
}

export interface StepUpChallengeRecord {
  id: string;
  userId: string;
  sessionId: string | null;
  action: string;
  nonce: string;
  attempts: number;
  verifiedAt: Date | null;
  verifiedUntil: Date | null;
  expiresAt: Date;
}

function mapRow(row: ChallengeRow): StepUpChallengeRecord {
  return {
    id: row.id,
    userId: row.user_id,
    sessionId: row.session_id,
    action: row.action,
    nonce: row.nonce,
    attempts: row.attempts,
    verifiedAt: row.verified_at,
    verifiedUntil: row.verified_until,
    expiresAt: row.expires_at,
  };
}

export interface CreateChallengeInput {
  userId: string;
  sessionId: string | null;
  action: StepUpAction;
  nonce: string;
  expiresAt: Date;
}

export const stepUpRepository = {
  async create(input: CreateChallengeInput, executor?: SqlExecutor): Promise<string> {
    const id = newId();
    await execute(
      `INSERT INTO step_up_challenges (id, user_id, session_id, action, nonce, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [id, input.userId, input.sessionId, input.action, input.nonce, input.expiresAt],
      executor,
    );
    return id;
  },

  async findById(id: string, executor?: SqlExecutor): Promise<StepUpChallengeRecord | null> {
    const row = await queryOne<ChallengeRow>(
      `SELECT id, user_id, session_id, action, nonce, attempts,
              verified_at, verified_until, expires_at
         FROM step_up_challenges WHERE id = ?`,
      [id],
      executor,
    );
    return row ? mapRow(row) : null;
  },

  /**
   * A verification still in force for this user and action.
   *
   * `verified_until > NOW()` is evaluated by the database rather than in
   * JavaScript so a clock skew between application hosts cannot extend a
   * verification past its deadline.
   */
  async findActiveVerification(
    userId: string,
    action: StepUpAction,
    executor?: SqlExecutor,
  ): Promise<StepUpChallengeRecord | null> {
    const row = await queryOne<ChallengeRow>(
      `SELECT id, user_id, session_id, action, nonce, attempts,
              verified_at, verified_until, expires_at
         FROM step_up_challenges
        WHERE user_id = ?
          AND action = ?
          AND verified_until IS NOT NULL
          AND verified_until > CURRENT_TIMESTAMP(3)
        ORDER BY verified_until DESC
        LIMIT 1`,
      [userId, action],
      executor,
    );
    return row ? mapRow(row) : null;
  },

  async incrementAttempts(id: string, executor?: SqlExecutor): Promise<void> {
    await execute(
      'UPDATE step_up_challenges SET attempts = attempts + 1 WHERE id = ?',
      [id],
      executor,
    );
  },

  /**
   * Promote an answered challenge to a live verification.
   *
   * `verified_at IS NULL` in the WHERE clause makes this single-use: two
   * concurrent verifications of the same challenge cannot both succeed.
   */
  async markVerified(id: string, verifiedUntil: Date, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute(
      `UPDATE step_up_challenges
          SET verified_at = CURRENT_TIMESTAMP(3), verified_until = ?
        WHERE id = ? AND verified_at IS NULL`,
      [verifiedUntil, id],
      executor,
    );
    return result.affectedRows > 0;
  },

  /**
   * Remove spent rows for one user.
   *
   * A row is spent when its challenge window has passed *and* any verification
   * it granted has also lapsed - deleting on `expires_at` alone would revoke
   * live verifications after five minutes.
   */
  async deleteExpired(userId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `DELETE FROM step_up_challenges
        WHERE user_id = ?
          AND expires_at < CURRENT_TIMESTAMP(3)
          AND (verified_until IS NULL OR verified_until < CURRENT_TIMESTAMP(3))`,
      [userId],
      executor,
    );
    return result.affectedRows;
  },

  /** Drop everything for a user - password change, forced sign-out, lockout. */
  async deleteForUser(userId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      'DELETE FROM step_up_challenges WHERE user_id = ?',
      [userId],
      executor,
    );
    return result.affectedRows;
  },

  /** Global sweep for the maintenance job. */
  async pruneExpired(executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `DELETE FROM step_up_challenges
        WHERE expires_at < CURRENT_TIMESTAMP(3)
          AND (verified_until IS NULL OR verified_until < CURRENT_TIMESTAMP(3))`,
      [],
      executor,
    );
    return result.affectedRows;
  },
};

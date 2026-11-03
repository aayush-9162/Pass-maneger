/**
 * Security score history.
 *
 * Write-mostly and read rarely: one row per computation, read only to draw a
 * trend. Deliberately not deduplicated - two identical consecutive scores are
 * still two data points, and collapsing them would make a flat period look like
 * missing data.
 */

import type { AreaScore } from '@passm/shared';

import { execute, query, queryOne, type RowDataPacket, type SqlExecutor } from '../config/database';
import { limitClause } from '../utils/sql';

interface ScoreRow extends RowDataPacket {
  score: number;
  grade: string;
  computed_at: Date;
}

export interface RecordScoreInput {
  score: number;
  grade: string;
  areas: readonly AreaScore[];
  findingCount: number;
}

export const securityScoreRepository = {
  async record(input: RecordScoreInput, executor?: SqlExecutor): Promise<void> {
    await execute(
      `INSERT INTO security_score_history (score, grade, areas, finding_count)
       VALUES (?, ?, CAST(? AS JSON), ?)`,
      [input.score, input.grade, JSON.stringify(input.areas), input.findingCount],
      executor,
    );
  },

  /**
   * The score before the one being computed now.
   *
   * `OFFSET 0 LIMIT 1` after ordering by recency gives the most recent *stored*
   * score, which at call time is the previous one because the current
   * computation has not been written yet.
   */
  async latestScore(executor?: SqlExecutor): Promise<number | null> {
    const row = await queryOne<ScoreRow>(
      `SELECT score, grade, computed_at
         FROM security_score_history
        ORDER BY computed_at DESC
        ${limitClause(1, 1)}`,
      [],
      executor,
    );
    return row ? Number(row.score) : null;
  },

  /**
   * Daily history.
   *
   * One row per day - the last computation of each day - rather than every
   * computation, so a dashboard refreshed fifty times does not produce fifty
   * points on the chart.
   */
  async history(
    days: number,
    executor?: SqlExecutor,
  ): Promise<{ score: number; grade: string; computedAt: string }[]> {
    const safeDays = Math.min(Math.max(Math.trunc(days) || 30, 1), 365);

    const rows = await query<ScoreRow>(
      `SELECT h.score, h.grade, h.computed_at
         FROM security_score_history h
         INNER JOIN (
           SELECT DATE(computed_at) AS day, MAX(computed_at) AS latest
             FROM security_score_history
            WHERE computed_at >= DATE_SUB(NOW(3), INTERVAL ? DAY)
            GROUP BY DATE(computed_at)
         ) latest_per_day ON latest_per_day.latest = h.computed_at
        ORDER BY h.computed_at ASC`,
      [safeDays],
      executor,
    );

    return rows.map((row) => ({
      score: Number(row.score),
      grade: row.grade,
      computedAt: row.computed_at.toISOString(),
    }));
  },

  /** Prune old history for the maintenance job. */
  async pruneOlderThan(days: number, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `DELETE FROM security_score_history
        WHERE computed_at < DATE_SUB(NOW(3), INTERVAL ? DAY)`,
      [days],
      executor,
    );
    return result.affectedRows;
  },
};

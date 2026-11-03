/**
 * Password health repository.
 *
 * Stores findings uploaded by clients. Everything written here is derived data:
 * counts, scores, flags and item ids. There is no password and no hash of one in
 * any column, so this table can be read by an administrator - and could be
 * stolen wholesale - without any credential being recoverable from it.
 */

import type {
  HealthIssue,
  HealthSeverity,
  PasswordHealthFinding,
  PasswordHealthReport,
  PasswordHealthSummary,
} from '@passm/shared';
import { HEALTH_ISSUE } from '@passm/shared';

import {
  execute,
  query,
  queryOne,
  type RowDataPacket,
  type SqlExecutor,
  type SqlParam,
} from '../config/database';
import { toIsoRequired } from '../utils/date';
import { likePattern, limitOffsetClause, resolvePagination, resolveSortColumn, resolveSortDirection } from '../utils/sql';

const REPORT_SORT_COLUMNS = {
  healthScore: 'h.health_score',
  weakCount: 'h.weak_count',
  reusedCount: 'h.reused_count',
  compromisedCount: 'h.compromised_count',
  generatedAt: 'h.generated_at',
  lastName: 'u.last_name',
} as const;

interface ReportRow extends RowDataPacket {
  user_id: string;
  email: string;
  first_name: string;
  last_name: string;
  total_items: number;
  assessed_items: number;
  weak_count: number;
  reused_count: number;
  old_count: number;
  compromised_count: number;
  health_score: number;
  breach_check_performed: number;
  generated_at: Date;
  created_at: Date;
}

function mapReportRow(row: ReportRow): PasswordHealthReport {
  return {
    userId: row.user_id,
    email: row.email,
    fullName: `${row.first_name} ${row.last_name}`.trim(),
    totalItems: Number(row.total_items),
    assessedItems: Number(row.assessed_items),
    weakCount: Number(row.weak_count),
    reusedCount: Number(row.reused_count),
    oldCount: Number(row.old_count),
    compromisedCount: Number(row.compromised_count),
    healthScore: Number(row.health_score),
    breachCheckPerformed: row.breach_check_performed === 1,
    generatedAt: toIsoRequired(row.generated_at),
    createdAt: toIsoRequired(row.created_at),
  };
}

const REPORT_COLUMNS = `
  h.user_id, u.email, u.first_name, u.last_name,
  h.total_items, h.assessed_items, h.weak_count, h.reused_count, h.old_count,
  h.compromised_count, h.health_score, h.breach_check_performed,
  h.generated_at, h.created_at
`;

const REPORT_SOURCE = `
  FROM password_health_reports h
  INNER JOIN users u ON u.id = h.user_id AND u.deleted_at IS NULL
`;

export interface UpsertReportInput {
  userId: string;
  totalItems: number;
  assessedItems: number;
  weakCount: number;
  reusedCount: number;
  oldCount: number;
  compromisedCount: number;
  healthScore: number;
  breachCheckPerformed: boolean;
  generatedAt: Date;
}

export interface ListReportsFilter {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortDir?: string;
  search?: string;
  maxScore?: number;
  issue?: HealthIssue;
}

interface CountRow extends RowDataPacket {
  total: number;
}

/** The column backing each issue filter, so a filter cannot name a free column. */
const ISSUE_COLUMN: Readonly<Record<HealthIssue, string | null>> = {
  [HEALTH_ISSUE.WEAK]: 'h.weak_count',
  [HEALTH_ISSUE.REUSED]: 'h.reused_count',
  [HEALTH_ISSUE.OLD]: 'h.old_count',
  [HEALTH_ISSUE.COMPROMISED]: 'h.compromised_count',
  // Not rolled up at report level; filtering on them means reading findings.
  [HEALTH_ISSUE.SHORT]: null,
  [HEALTH_ISSUE.MISSING]: null,
};

export const passwordHealthRepository = {
  /**
   * Replace a user's report and its findings.
   *
   * The findings are deleted and re-inserted rather than merged: a report is a
   * snapshot, and merging would leave findings for items the user has since
   * deleted, which reads as an unfixable problem in the console. Must run inside
   * a transaction - the caller supplies the executor.
   */
  async replaceReport(
    input: UpsertReportInput,
    findings: readonly PasswordHealthFinding[],
    executor: SqlExecutor,
  ): Promise<void> {
    await execute(
      `INSERT INTO password_health_reports
         (user_id, total_items, assessed_items, weak_count, reused_count, old_count,
          compromised_count, health_score, breach_check_performed, generated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AS new_report
       ON DUPLICATE KEY UPDATE
         total_items            = new_report.total_items,
         assessed_items         = new_report.assessed_items,
         weak_count             = new_report.weak_count,
         reused_count           = new_report.reused_count,
         old_count              = new_report.old_count,
         compromised_count      = new_report.compromised_count,
         health_score           = new_report.health_score,
         breach_check_performed = new_report.breach_check_performed,
         generated_at           = new_report.generated_at`,
      [
        input.userId,
        input.totalItems,
        input.assessedItems,
        input.weakCount,
        input.reusedCount,
        input.oldCount,
        input.compromisedCount,
        input.healthScore,
        input.breachCheckPerformed ? 1 : 0,
        input.generatedAt,
      ],
      executor,
    );

    await execute(
      'DELETE FROM password_health_findings WHERE user_id = ?',
      [input.userId],
      executor,
    );

    // Chunked multi-row inserts: a 500-item vault would otherwise be 500 round
    // trips inside one transaction, holding locks far longer than necessary.
    const CHUNK = 100;
    for (let offset = 0; offset < findings.length; offset += CHUNK) {
      const chunk = findings.slice(offset, offset + CHUNK);
      if (chunk.length === 0) continue;

      const valuesClause = chunk.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
      const params: SqlParam[] = [];

      for (const finding of chunk) {
        params.push(
          input.userId,
          finding.itemId,
          finding.vaultId || null,
          finding.sharedVaultId,
          finding.severity,
          finding.issues.join(','),
          finding.strengthScore,
          finding.entropyBits,
          finding.passwordLength,
          finding.ageDays,
          finding.duplicateCount,
        );
      }

      await execute(
        `INSERT INTO password_health_findings
           (user_id, item_id, vault_id, shared_vault_id, severity, issues,
            strength_score, entropy_bits, password_length, age_days, duplicate_count)
         VALUES ${valuesClause}`,
        params,
        executor,
      );
    }
  },

  async findForUser(userId: string, executor?: SqlExecutor): Promise<PasswordHealthReport | null> {
    const row = await queryOne<ReportRow>(
      `SELECT ${REPORT_COLUMNS} ${REPORT_SOURCE} WHERE h.user_id = ? LIMIT 1`,
      [userId],
      executor,
    );
    return row ? mapReportRow(row) : null;
  },

  async findingsForUser(
    userId: string,
    executor?: SqlExecutor,
  ): Promise<PasswordHealthFinding[]> {
    const rows = await query<
      RowDataPacket & {
        item_id: string;
        vault_id: string | null;
        shared_vault_id: string | null;
        severity: string;
        issues: string;
        strength_score: number;
        entropy_bits: number;
        password_length: number;
        age_days: number | null;
        duplicate_count: number;
      }
    >(
      `SELECT item_id, vault_id, shared_vault_id, severity, issues,
              strength_score, entropy_bits, password_length, age_days, duplicate_count
         FROM password_health_findings
        WHERE user_id = ?
        ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'ok'), item_id`,
      [userId],
      executor,
    );

    return rows.map((row) => ({
      itemId: row.item_id,
      vaultId: row.vault_id ?? '',
      sharedVaultId: row.shared_vault_id,
      severity: row.severity as HealthSeverity,
      issues: row.issues.split(',').filter(Boolean) as HealthIssue[],
      strengthScore: Number(row.strength_score),
      entropyBits: Number(row.entropy_bits),
      passwordLength: Number(row.password_length),
      ageDays: row.age_days === null ? null : Number(row.age_days),
      duplicateCount: Number(row.duplicate_count),
    }));
  },

  async list(
    filter: ListReportsFilter = {},
    executor?: SqlExecutor,
  ): Promise<{ items: PasswordHealthReport[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['1 = 1'];
    const params: SqlParam[] = [];

    if (filter.search) {
      conditions.push('(u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)');
      const pattern = likePattern(filter.search);
      params.push(pattern, pattern, pattern);
    }
    if (filter.maxScore !== undefined) {
      conditions.push('h.health_score <= ?');
      params.push(filter.maxScore);
    }
    if (filter.issue) {
      const column = ISSUE_COLUMN[filter.issue];
      if (column) {
        // Column comes from a fixed map, never from the request string.
        conditions.push(`${column} > 0`);
      } else {
        conditions.push(
          `EXISTS (SELECT 1 FROM password_health_findings f
                    WHERE f.user_id = h.user_id AND FIND_IN_SET(?, f.issues))`,
        );
        params.push(filter.issue);
      }
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const orderColumn = resolveSortColumn(filter.sortBy, REPORT_SORT_COLUMNS, 'healthScore');
    const orderDirection = resolveSortDirection(filter.sortDir);

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total ${REPORT_SOURCE} ${where}`,
      params,
      executor,
    );

    const rows = await query<ReportRow>(
      `SELECT ${REPORT_COLUMNS} ${REPORT_SOURCE} ${where}
        ORDER BY ${orderColumn} ${orderDirection}, h.user_id ASC
        ${limitOffsetClause(limit, offset)}`,
      [...params],
      executor,
    );

    return { items: rows.map(mapReportRow), total: countRow?.total ?? 0, page, pageSize };
  },

  /**
   * Org-wide rollup.
   *
   * `unreportedUsers` is deliberately part of the summary. A console that showed
   * only the users who uploaded a report would improve every time somebody
   * stopped running one, which is the wrong incentive: silence is not health.
   */
  async summary(staleDays: number, executor?: SqlExecutor): Promise<PasswordHealthSummary> {
    const totals = await queryOne<
      RowDataPacket & {
        reported_users: number;
        stale_reports: number;
        assessed: number;
        weak: number;
        reused: number;
        old_items: number;
        compromised: number;
        average_score: number | null;
      }
    >(
      `SELECT COUNT(*) AS reported_users,
              SUM(CASE WHEN h.generated_at < DATE_SUB(NOW(3), INTERVAL ? DAY) THEN 1 ELSE 0 END)
                AS stale_reports,
              COALESCE(SUM(h.assessed_items), 0)    AS assessed,
              COALESCE(SUM(h.weak_count), 0)        AS weak,
              COALESCE(SUM(h.reused_count), 0)      AS reused,
              COALESCE(SUM(h.old_count), 0)         AS old_items,
              COALESCE(SUM(h.compromised_count), 0) AS compromised,
              AVG(h.health_score)                   AS average_score
         ${REPORT_SOURCE}`,
      [staleDays],
      executor,
    );

    const totalUsers = await queryOne<CountRow>(
      'SELECT COUNT(*) AS total FROM users WHERE deleted_at IS NULL',
      [],
      executor,
    );

    const distribution = await query<RowDataPacket & { bucket: string; users: number }>(
      `SELECT CASE
                WHEN h.health_score >= 90 THEN '90-100'
                WHEN h.health_score >= 75 THEN '75-89'
                WHEN h.health_score >= 50 THEN '50-74'
                WHEN h.health_score >= 25 THEN '25-49'
                ELSE '0-24'
              END AS bucket,
              COUNT(*) AS users
         ${REPORT_SOURCE}
        GROUP BY bucket`,
      [],
      executor,
    );

    const reportedUsers = Number(totals?.reported_users ?? 0);

    // Buckets are ordered worst-first so the chart reads left to right as a
    // problem getting smaller.
    const BUCKET_ORDER = ['0-24', '25-49', '50-74', '75-89', '90-100'];
    const bucketMap = new Map(distribution.map((row) => [row.bucket, Number(row.users)]));

    return {
      reportedUsers,
      unreportedUsers: Math.max(0, Number(totalUsers?.total ?? 0) - reportedUsers),
      staleReports: Number(totals?.stale_reports ?? 0),
      totalAssessedItems: Number(totals?.assessed ?? 0),
      weakCount: Number(totals?.weak ?? 0),
      reusedCount: Number(totals?.reused ?? 0),
      oldCount: Number(totals?.old_items ?? 0),
      compromisedCount: Number(totals?.compromised ?? 0),
      averageHealthScore: Math.round(Number(totals?.average_score ?? 0)),
      scoreDistribution: BUCKET_ORDER.map((bucket) => ({
        bucket,
        users: bucketMap.get(bucket) ?? 0,
      })),
    };
  },

  /** Remove a user's report, e.g. after their master password is reset. */
  async removeForUser(userId: string, executor?: SqlExecutor): Promise<void> {
    await execute('DELETE FROM password_health_findings WHERE user_id = ?', [userId], executor);
    await execute('DELETE FROM password_health_reports WHERE user_id = ?', [userId], executor);
  },
};

/**
 * Password health reporting.
 *
 * The server's entire role here is to receive findings it cannot compute, store
 * them, and aggregate them. It never sees a password, so it has no way to
 * validate that a report is honest - a client could upload "everything is fine"
 * for a vault full of `password1`.
 *
 * That is worth being explicit about rather than papering over. The threat it
 * matters against is a user hiding their own bad hygiene from their own
 * employer, and the mitigations are organisational: reports are attributed and
 * timestamped, the console shows staleness prominently, and a user who never
 * uploads one is counted as *unassessed* rather than healthy. What it is not is
 * a control against an attacker - an attacker who can forge a health report has
 * already compromised a client that holds the vault key, and is not going to
 * spend the access on falsifying a hygiene metric.
 */

import {
  AUDIT_ACTIONS,
  HEALTH_ISSUE,
  type PaginatedResult,
  type PasswordHealthFinding,
  type PasswordHealthReport,
  type PasswordHealthSummary,
} from '@passm/shared';

import { withTransaction } from '../config/database';
import type { SubmitHealthReportDto } from '../dto/admin.dto';
import {
  passwordHealthRepository,
  type ListReportsFilter,
} from '../repositories/password-health.repository';
import { userRepository } from '../repositories/user.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import { paginated } from '../utils/api-response';
import { BadRequestError, NotFoundError } from '../utils/errors';
import { auditService } from './audit.service';

/** A report older than this is shown as stale rather than current. */
export const HEALTH_STALE_DAYS = 30;

/** Count findings carrying a particular issue. */
function countIssue(
  findings: readonly PasswordHealthFinding[],
  issue: (typeof HEALTH_ISSUE)[keyof typeof HEALTH_ISSUE],
): number {
  return findings.filter((finding) => finding.issues.includes(issue)).length;
}

/**
 * Recompute the headline score from the findings.
 *
 * The client also computes it, and the client's value is ignored. Not because
 * the client is untrusted for the findings themselves - it necessarily is
 * trusted for those - but because the *scoring formula* must be identical across
 * every user for the org-wide comparison to mean anything. Two clients on
 * different versions would otherwise produce incomparable numbers and a league
 * table that ranks by release date.
 */
function scoreFindings(findings: readonly PasswordHealthFinding[]): number {
  const assessable = findings.filter((finding) => finding.passwordLength > 0);
  if (assessable.length === 0) return 100;

  const WEIGHTS: Record<string, number> = {
    [HEALTH_ISSUE.COMPROMISED]: 40,
    [HEALTH_ISSUE.REUSED]: 15,
    [HEALTH_ISSUE.WEAK]: 12,
    [HEALTH_ISSUE.SHORT]: 8,
    [HEALTH_ISSUE.OLD]: 4,
    [HEALTH_ISSUE.MISSING]: 0,
  };

  let penalty = 0;
  for (const finding of assessable) {
    const weights = finding.issues.map((issue) => WEIGHTS[issue] ?? 0).sort((a, b) => b - a);
    penalty += weights.reduce((sum, weight, index) => sum + (index === 0 ? weight : weight / 2), 0);
  }

  return Math.max(0, Math.min(100, Math.round(100 - penalty / assessable.length)));
}

export const passwordHealthService = {
  /**
   * Accept a report from the client that computed it.
   *
   * The report always replaces the previous one for that user. Keeping history
   * would let an administrator watch an individual's hygiene move over time,
   * which is surveillance rather than security: the actionable question is
   * "what is wrong now", and that is what is stored.
   */
  async submit(
    dto: SubmitHealthReportDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<PasswordHealthReport> {
    const generatedAt = new Date(dto.generatedAt);

    // A clock far in the future would make a report look permanently fresh.
    const skewLimit = Date.now() + 24 * 60 * 60 * 1000;
    if (generatedAt.getTime() > skewLimit) {
      throw new BadRequestError('That report is dated in the future. Check the device clock.');
    }

    const findings = dto.findings as PasswordHealthFinding[];

    await withTransaction((tx) =>
      passwordHealthRepository.replaceReport(
        {
          userId: actor.userId,
          totalItems: dto.totalItems,
          assessedItems: dto.assessedItems,
          weakCount: countIssue(findings, HEALTH_ISSUE.WEAK),
          reusedCount: countIssue(findings, HEALTH_ISSUE.REUSED),
          oldCount: countIssue(findings, HEALTH_ISSUE.OLD),
          compromisedCount: countIssue(findings, HEALTH_ISSUE.COMPROMISED),
          healthScore: scoreFindings(findings),
          breachCheckPerformed: dto.breachCheckPerformed,
          generatedAt,
        },
        findings,
        tx,
      ),
    );

    await auditService.record({
      action: AUDIT_ACTIONS.PASSWORD_HEALTH_REPORTED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      // Counts only. Item ids belong in the findings table, not in a trail
      // several people can read.
      metadata: {
        assessedItems: dto.assessedItems,
        findings: findings.length,
        breachCheckPerformed: dto.breachCheckPerformed,
      },
    });

    const report = await passwordHealthRepository.findForUser(actor.userId);
    if (!report) throw new NotFoundError('The report could not be read back.');
    return report;
  },

  /** The caller's own report and its per-item findings. */
  async ownReport(userId: string): Promise<{
    report: PasswordHealthReport | null;
    findings: PasswordHealthFinding[];
    staleAfterDays: number;
  }> {
    const [report, findings] = await Promise.all([
      passwordHealthRepository.findForUser(userId),
      passwordHealthRepository.findingsForUser(userId),
    ]);

    return { report, findings, staleAfterDays: HEALTH_STALE_DAYS };
  },

  /** Org-wide list, for administrators and managers. */
  async list(filter: ListReportsFilter): Promise<PaginatedResult<PasswordHealthReport>> {
    const { items, total, page, pageSize } = await passwordHealthRepository.list(filter);
    return paginated(items, total, page, pageSize);
  },

  async summary(): Promise<PasswordHealthSummary> {
    return passwordHealthRepository.summary(HEALTH_STALE_DAYS);
  },

  /**
   * One user's findings, for an administrator investigating a bad score.
   *
   * They see item ids, severities and flags - enough to tell the user "four of
   * your logins are reused", and not enough to learn what any of them is for.
   */
  async reportFor(userId: string): Promise<{
    report: PasswordHealthReport | null;
    findings: PasswordHealthFinding[];
  }> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    const [report, findings] = await Promise.all([
      passwordHealthRepository.findForUser(userId),
      passwordHealthRepository.findingsForUser(userId),
    ]);

    return { report, findings };
  },
};

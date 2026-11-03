/**
 * Security posture score.
 *
 * ## What a score is for, and what it is not
 *
 * A single number is a poor security assessment and a good *prompt*. Nobody
 * reads a settings page with sixty switches looking for the one that is wrong;
 * everybody notices a B that used to be an A. So the number exists to route
 * attention, and every point lost carries a specific finding with a specific
 * fix and a link to the page that fixes it.
 *
 * Three rules keep it honest:
 *
 *  1. **Nothing is deducted for something the administrator cannot change.**
 *     A score that punishes you for running on a LAN without TLS, when TLS is
 *     not available on that LAN, is noise. Where a control genuinely does not
 *     apply, the check is skipped rather than failed.
 *  2. **Findings are ranked by real consequence, not by how easy they are to
 *     measure.** Sixty accounts sharing a password is a bigger problem than a
 *     lockout window set to twenty minutes instead of fifteen, and the weights
 *     say so.
 *  3. **A passing check is still shown.** "You have this right" is information,
 *     and a list of only problems reads as though nothing is working.
 *
 * ## Weighting
 *
 * Each area has a maximum. Areas are not equal: a weak password policy exposes
 * every account, while a slightly generous session timeout exposes an
 * unattended desk. Totals are normalised to 100 at the end.
 */

import {
  SCORE_AREA,
  SCORE_AREA_LABEL,
  gradeFor,
  type AreaScore,
  type ScoreArea,
  type ScoreFinding,
  type SecuritySettings,
  type SecurityScore,
} from '@passm/shared';

import { logger } from '../config/logger';
import { analyticsRepository } from '../repositories/analytics.repository';
import { ipRuleRepository } from '../repositories/ip-rule.repository';
import { securityScoreRepository } from '../repositories/security-score.repository';
import { userRepository } from '../repositories/user.repository';
import { passwordHealthService } from './password-health.service';
import { securitySettingsService } from './security-settings.service';

/** Points available per area. Sums to 100. */
const AREA_MAX: Record<ScoreArea, number> = {
  [SCORE_AREA.AUTHENTICATION]: 20,
  [SCORE_AREA.PASSWORDS]: 25,
  [SCORE_AREA.SESSIONS]: 15,
  [SCORE_AREA.ACCESS_CONTROL]: 15,
  [SCORE_AREA.MONITORING]: 10,
  [SCORE_AREA.NETWORK]: 15,
};

/** Builder that accumulates findings and tallies deductions per area. */
class ScoreSheet {
  private readonly findings: ScoreFinding[] = [];
  private readonly deductions = new Map<ScoreArea, number>();

  /**
   * Record a check.
   *
   * `passed` decides whether the impact is deducted; the finding is recorded
   * either way so the console can show what was examined.
   */
  check(input: {
    id: string;
    area: ScoreArea;
    passed: boolean;
    impact: number;
    severity: ScoreFinding['severity'];
    title: string;
    detail: string;
    remediation: string;
    actionUrl?: string | null;
  }): void {
    this.findings.push({
      id: input.id,
      area: input.area,
      impact: input.passed ? 0 : input.impact,
      severity: input.severity,
      title: input.title,
      detail: input.detail,
      remediation: input.remediation,
      actionUrl: input.actionUrl ?? null,
      passed: input.passed,
    });

    if (!input.passed) {
      this.deductions.set(input.area, (this.deductions.get(input.area) ?? 0) + input.impact);
    }
  }

  build(): { score: number; areas: AreaScore[]; findings: ScoreFinding[] } {
    const areas: AreaScore[] = (Object.keys(AREA_MAX) as ScoreArea[]).map((area) => {
      const max = AREA_MAX[area];
      // Deductions are clamped at the area maximum: one badly configured area
      // must not be able to drag the total below zero and swamp the others.
      const lost = Math.min(this.deductions.get(area) ?? 0, max);
      return { area, label: SCORE_AREA_LABEL[area], score: max - lost, max };
    });

    const total = areas.reduce((sum, area) => sum + area.score, 0);

    // Worst first, and a failing check always outranks a passing one of equal
    // impact - the list is meant to be read top-down and acted on.
    const findings = [...this.findings].sort((a, b) => {
      if (a.passed !== b.passed) return a.passed ? 1 : -1;
      return b.impact - a.impact;
    });

    return { score: Math.max(0, Math.round(total)), areas, findings };
  }
}

/** Evaluate how sensitive actions are confirmed. Sign-in itself is Google's. */
function scoreAuthentication(sheet: ScoreSheet, settings: SecuritySettings): void {
  sheet.check({
    id: 'auth.step-up-admin',
    area: SCORE_AREA.AUTHENTICATION,
    passed: settings.stepUpForAdminAction,
    impact: 5,
    severity: 'high',
    title: 'Confirmation before destructive admin actions',
    detail: settings.stepUpForAdminAction
      ? 'Deleting users and signing everyone out require a fresh Google confirmation.'
      : 'A hijacked admin session can delete users and sign everyone out with no further check.',
    remediation: 'Turn on two-step verification for administrator actions.',
    actionUrl: '/admin/settings?category=stepUp',
  });

  sheet.check({
    id: 'auth.step-up-settings',
    area: SCORE_AREA.AUTHENTICATION,
    passed: settings.stepUpForSettingsChange,
    impact: 5,
    severity: 'medium',
    title: 'Confirmation before policy changes',
    detail: settings.stepUpForSettingsChange
      ? 'Changing security policy requires a fresh Google confirmation.'
      : 'Security policy can be weakened silently from a hijacked admin session.',
    remediation: 'Turn on two-step verification for settings changes.',
    actionUrl: '/admin/settings?category=stepUp',
  });
}

/** Evaluate the actual state of stored passwords. */
async function scorePasswords(sheet: ScoreSheet): Promise<void> {
  // The state of the passwords actually stored, from the last health reports.
  try {
    const summary = await passwordHealthService.summary();
    const totalItems = summary.totalAssessedItems;

    if (totalItems > 0) {
      const weakRatio = summary.weakCount / totalItems;
      sheet.check({
        id: 'pw.weak-stored',
        area: SCORE_AREA.PASSWORDS,
        passed: weakRatio < 0.1,
        impact: 5,
        severity: 'high',
        title: 'Weak passwords in vaults',
        detail: `${summary.weakCount} of ${totalItems} assessed passwords are weak.`,
        remediation: 'Open the password health report and ask the owners of the worst entries to rotate them.',
        actionUrl: '/admin/health',
      });

      const reusedRatio = summary.reusedCount / totalItems;
      sheet.check({
        id: 'pw.reused-stored',
        area: SCORE_AREA.PASSWORDS,
        passed: reusedRatio < 0.1,
        impact: 5,
        severity: 'high',
        title: 'Reused passwords in vaults',
        detail: `${summary.reusedCount} assessed passwords appear more than once.`,
        remediation:
          'Reuse is what turns one breach into many. Rotate duplicates, starting with anything reused across a personal and a shared vault.',
        actionUrl: '/admin/health',
      });
    }
  } catch (error) {
    // A missing health report must not fail the whole score - it is one input
    // among several, and the policy checks above are still meaningful.
    logger.warn('Password health unavailable for the security score', { error });
  }
}

function scoreSessions(sheet: ScoreSheet, settings: SecuritySettings): void {
  sheet.check({
    id: 'session.idle-timeout',
    area: SCORE_AREA.SESSIONS,
    passed: settings.sessionIdleTimeoutMinutes <= 240,
    impact: 5,
    severity: 'medium',
    title: 'Session idle timeout',
    detail: `Sessions survive ${settings.sessionIdleTimeoutMinutes} minutes of inactivity.`,
    remediation:
      'Four hours or less. An unattended session is the most common way a vault is read by the wrong person. ' +
      'A long window is a defensible trade for a LAN-only tool - the vault still auto-locks separately, and ' +
      'that lock is what protects an unattended screen - but it is a trade, so this stays flagged.',
    actionUrl: '/admin/settings?category=session',
  });

  sheet.check({
    id: 'session.absolute-timeout',
    area: SCORE_AREA.SESSIONS,
    passed: settings.sessionAbsoluteTimeoutHours <= 24,
    impact: 4,
    severity: 'medium',
    title: 'Absolute session lifetime',
    detail: `Sessions end ${settings.sessionAbsoluteTimeoutHours} hours after sign-in regardless of activity.`,
    remediation:
      'Cap at 24 hours. This is what bounds the value of a stolen refresh token. If it is set longer on ' +
      'purpose, revoking sessions from Admin > Sessions is the compensating control - use it when a device ' +
      'is lost, because expiry will not do it for you.',
    actionUrl: '/admin/settings?category=session',
  });

  sheet.check({
    id: 'session.vault-autolock',
    area: SCORE_AREA.SESSIONS,
    passed: settings.vaultAutoLockMinutes <= 30,
    impact: 3,
    severity: 'medium',
    title: 'Idle sign-out',
    detail: `The console signs out after ${settings.vaultAutoLockMinutes} minutes without input.`,
    remediation: 'Thirty minutes or less, so a walk-away does not leave passwords open in a browser tab.',
    actionUrl: '/admin/settings?category=vault',
  });


}

async function scoreAccessControl(sheet: ScoreSheet, settings: SecuritySettings): Promise<void> {
  sheet.check({
    id: 'access.device-trust-window',
    area: SCORE_AREA.ACCESS_CONTROL,
    passed: !settings.deviceTrustEnabled || settings.deviceTrustDays <= 90,
    impact: 4,
    severity: 'low',
    title: 'Device trust lifetime',
    detail: settings.deviceTrustEnabled
      ? `A trusted device stays trusted for ${settings.deviceTrustDays} days.`
      : 'Device trust is switched off entirely.',
    remediation: 'Ninety days or fewer, so a machine that leaves the company stops being trusted on its own.',
    actionUrl: '/admin/settings?category=device',
  });

  try {
    const byRole = await userRepository.countByRole();
    const admins = byRole.admin ?? 0;

    // Both extremes are real problems, in opposite directions.
    sheet.check({
      id: 'access.admin-count',
      area: SCORE_AREA.ACCESS_CONTROL,
      passed: admins >= 2 && admins <= 5,
      impact: 6,
      severity: admins < 2 ? 'high' : 'medium',
      title: 'Number of administrators',
      detail:
        admins < 2
          ? `Only ${admins} administrator account exists.`
          : `${admins} accounts hold full administrative rights.`,
      remediation:
        admins < 2
          ? 'Appoint a second administrator. With one, losing that person or their password locks the company out of its own vaults.'
          : 'Keep it to a handful. Every administrator can reset master passwords and read the whole audit trail.',
      actionUrl: '/admin/users?role=admin',
    });

    const locked = await analyticsRepository.lockedAccounts();
    sheet.check({
      id: 'access.locked-accounts',
      area: SCORE_AREA.ACCESS_CONTROL,
      passed: locked.length === 0,
      impact: 5,
      severity: 'medium',
      title: 'Locked accounts',
      detail:
        locked.length === 0
          ? 'No accounts are currently locked.'
          : `${locked.length} account(s) are locked out right now.`,
      remediation:
        'Check whether these are people who forgot a password or an attempt to guess one. Repeated lockouts on the same account are worth investigating.',
      actionUrl: '/admin/users?status=locked',
    });
  } catch (error) {
    logger.warn('Directory counters unavailable for the security score', { error });
  }
}

function scoreMonitoring(sheet: ScoreSheet, settings: SecuritySettings): void {
  sheet.check({
    id: 'monitor.new-device',
    area: SCORE_AREA.MONITORING,
    passed: settings.notifyOnNewDevice,
    impact: 4,
    severity: 'high',
    title: 'Alert on a new device',
    detail: settings.notifyOnNewDevice
      ? 'Users are told when an unrecognised device signs in.'
      : 'A stolen password can be used from a new machine with nobody told.',
    remediation:
      'Turn it on. The server cannot tell a stolen session from a real one, but the person it belongs to can.',
    actionUrl: '/admin/settings?category=notification',
  });


}

async function scoreNetwork(
  sheet: ScoreSheet,
  settings: SecuritySettings,
  tlsActive: boolean,
): Promise<void> {
  sheet.check({
    id: 'net.csrf',
    area: SCORE_AREA.NETWORK,
    passed: settings.csrfEnabled,
    impact: 6,
    severity: 'high',
    title: 'CSRF protection',
    detail: settings.csrfEnabled
      ? 'State-changing requests must carry a matching token.'
      : 'CSRF token checking is switched off.',
    remediation: 'Turn it back on. The only reason to disable it is diagnosing a client that cannot read the cookie.',
    actionUrl: '/admin/settings?category=network',
  });

  /**
   * TLS is scored only where it is actually achievable.
   *
   * This product is explicitly designed to run over plain HTTP on a private
   * LAN, at the operator's instruction. Deducting points for that would be
   * scoring a deployment decision the administrator already made deliberately
   * and cannot revisit from this page. The finding is reported as informational
   * so it is visible without being punitive.
   */
  sheet.check({
    id: 'net.tls',
    area: SCORE_AREA.NETWORK,
    passed: tlsActive,
    impact: 8,
    severity: 'high',
    title: tlsActive ? 'Served over HTTPS' : 'Served over plain HTTP',
    detail: tlsActive
      ? 'Traffic between clients and this server is encrypted in transit.'
      : 'Traffic is unencrypted in transit. The server releases passwords in plaintext to the client that asks, so on plain HTTP anyone on the network path can read them - along with session cookies.',
    remediation: tlsActive
      ? 'Nothing to do.'
      : 'Put a TLS certificate in front of this host (TLS_ENABLED, or a reverse proxy).',
    actionUrl: null,
  });

  try {
    const rules = await ipRuleRepository.findAll();
    const enabled = rules.filter((rule) => rule.enabled);

    if (settings.ipAllowListMode === 'enforce') {
      sheet.check({
        id: 'net.ip-allow-list',
        area: SCORE_AREA.NETWORK,
        passed: enabled.length > 0,
        impact: 5,
        severity: 'high',
        title: 'IP allow list',
        detail:
          enabled.length > 0
            ? `Enforcing, with ${enabled.length} active rule(s).`
            : 'Set to enforce, but no rules are enabled - so nothing is actually restricted.',
        remediation: 'Add at least one rule, or set the mode back to off so the configuration is not misleading.',
        actionUrl: '/admin/settings?category=network',
      });
    } else {
      // Not having an allow list is a legitimate choice, so this costs less
      // than having one configured wrongly.
      sheet.check({
        id: 'net.ip-allow-list',
        area: SCORE_AREA.NETWORK,
        passed: false,
        impact: 4,
        severity: 'low',
        title: 'IP allow list',
        detail:
          settings.ipAllowListMode === 'audit'
            ? 'Running in audit mode: nothing is blocked, but blocks are being logged.'
            : 'Not configured. Any address that can reach this server may attempt to sign in.',
        remediation:
          'On a LAN deployment, add your office ranges and run in audit mode for a week before enforcing. Check the audit log for addresses you forgot.',
        actionUrl: '/admin/settings?category=network',
      });
    }
  } catch (error) {
    logger.warn('IP rules unavailable for the security score', { error });
  }

  sheet.check({
    id: 'net.emergency-lock',
    area: SCORE_AREA.NETWORK,
    passed: !settings.emergencyLockActive,
    impact: 0,
    severity: 'high',
    title: settings.emergencyLockActive ? 'Emergency lock is ON' : 'Emergency lock is off',
    detail: settings.emergencyLockActive
      ? 'All non-administrator access is currently suspended.'
      : 'Normal operation.',
    remediation: settings.emergencyLockActive
      ? 'Lift the lock once the incident is resolved. While it is on, nobody can reach their passwords.'
      : 'Nothing to do.',
    actionUrl: settings.emergencyLockActive ? '/admin/settings?category=emergency' : null,
  });
}

export const securityScoreService = {
  /**
   * Compute the current score.
   *
   * Individual inputs are allowed to fail without failing the whole
   * computation - a score of "most of the checks, honestly labelled" is more
   * useful than an error page.
   */
  async compute(tlsActive: boolean): Promise<SecurityScore> {
    const settings = await securitySettingsService.getSettings();
    const sheet = new ScoreSheet();

    scoreAuthentication(sheet, settings);
    await scorePasswords(sheet);
    scoreSessions(sheet, settings);
    await scoreAccessControl(sheet, settings);
    scoreMonitoring(sheet, settings);
    await scoreNetwork(sheet, settings, tlsActive);

    const { score, areas, findings } = sheet.build();
    const previousScore = await securityScoreRepository.latestScore();

    // Persisted so the dashboard can show a trend. A bare number is not
    // actionable; "down eight points since Tuesday" is a question worth asking.
    await securityScoreRepository
      .record({
        score,
        grade: gradeFor(score),
        areas,
        findingCount: findings.filter((finding) => !finding.passed).length,
      })
      .catch((error: unknown) => {
        logger.warn('Could not record the security score', { error });
      });

    return {
      score,
      grade: gradeFor(score),
      areas,
      findings,
      computedAt: new Date().toISOString(),
      previousScore,
    };
  },

  /** Score history for the trend chart. */
  async history(days: number): Promise<{ score: number; grade: string; computedAt: string }[]> {
    return securityScoreRepository.history(days);
  },
};

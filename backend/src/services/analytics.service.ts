/**
 * Dashboard and security reporting.
 *
 * Two composed views over metadata the server already holds. Neither touches
 * vault contents, and neither can: the item counts here are counts of rows, and
 * the server cannot say what a single one of them contains.
 *
 * The security dashboard turns raw numbers into a small, fixed set of alerts.
 * That restraint is the design: a rules engine that can emit anything trains
 * people to ignore the panel, whereas six detections that each have an obvious
 * response get acted on.
 */

import {
  ROLES,
  SECURITY_ALERT_LEVEL,
  VAULT_ITEM_TYPE_LABEL,
  type AdminDashboardStats,
  type CategoryCount,
  type RoleName,
  type SecurityAlert,
  type SecurityDashboard,
  type VaultItemType,
} from '@passm/shared';
import { USER_STATUS, VAULT_KIND } from '@passm/shared';

import { analyticsRepository } from '../repositories/analytics.repository';
import { sharedVaultRepository } from '../repositories/shared-vault.repository';
import { userRepository } from '../repositories/user.repository';

/** Sessions untouched for this long are counted as stale. */
const STALE_SESSION_DAYS = 14;

/** Trusted devices unused for this long are counted as dormant. */
const DORMANT_DEVICE_DAYS = 90;

/** Failed sign-ins from one address across this many accounts looks like an attack. */
const SPRAY_ACCOUNT_THRESHOLD = 5;

export const analyticsService = {
  /**
   * Headline statistics.
   *
   * Every query is independent, so they run concurrently: the dashboard is the
   * first thing an administrator loads, and serialising a dozen aggregates would
   * make it the slowest page in the console.
   */
  async dashboard(windowDays: number): Promise<AdminDashboardStats> {
    const [
      statusCounts,
      roleCounts,
      userCounters,
      groups,
      itemCounts,
      accessCounters,
      logins,
      vaultWrites,
    ] = await Promise.all([
      userRepository.countByStatus(),
      userRepository.countByRole(),
      userRepository.dashboardCounters(),
      sharedVaultRepository.count(VAULT_KIND.GROUP),
      sharedVaultRepository.countItemsByType(),
      analyticsRepository.accessCounters(),
      analyticsRepository.loginSeries(windowDays),
      analyticsRepository.vaultWriteSeries(windowDays),
    ]);

    const itemsByType: CategoryCount[] = Object.entries(itemCounts)
      .map(([type, value]) => ({
        label: VAULT_ITEM_TYPE_LABEL[type as VaultItemType] ?? type,
        value,
      }))
      .sort((a, b) => b.value - a.value);

    const totalItems = itemsByType.reduce((sum, entry) => sum + entry.value, 0);
    const totalUsers = Object.values(statusCounts).reduce((sum, value) => sum + value, 0);

    const byRole = {
      [ROLES.ADMIN]: roleCounts[ROLES.ADMIN] ?? 0,
      [ROLES.EMPLOYEE]: roleCounts[ROLES.EMPLOYEE] ?? 0,
    } as Record<RoleName, number>;

    return {
      users: {
        total: totalUsers,
        active: statusCounts[USER_STATUS.ACTIVE] ?? 0,
        pending: statusCounts[USER_STATUS.PENDING] ?? 0,
        locked: statusCounts[USER_STATUS.LOCKED] ?? 0,
        suspended: statusCounts[USER_STATUS.SUSPENDED] ?? 0,
        activeLast30Days: userCounters.activeLast30Days,
        newLast30Days: userCounters.newLast30Days,
        byRole,
      },
      vaults: {
        groups,
        totalItems,
        itemsByType,
      },
      access: {
        activeSessions: accessCounters.activeSessions,
        trustedDevices: accessCounters.trustedDevices,
        knownDevices: accessCounters.knownDevices,
      },
      activity: {
        logins: logins.success,
        failedLogins: logins.failure,
        vaultWrites,
      },
      generatedAt: new Date().toISOString(),
    };
  },

  /** Detections and sign-in telemetry over a bounded window. */
  async security(windowDays: number): Promise<SecurityDashboard> {
    const [logins, failedAccounts, failedAddresses, locked, events, hygiene] =
      await Promise.all([
        analyticsRepository.loginSeries(windowDays),
        analyticsRepository.topFailedAccounts(windowDays, 10),
        analyticsRepository.topFailedAddresses(windowDays, 10),
        analyticsRepository.lockedAccounts(),
        analyticsRepository.securityEventCounts(windowDays),
        analyticsRepository.hygieneCounts(STALE_SESSION_DAYS, DORMANT_DEVICE_DAYS),
      ]);

    const loginOutcomes = logins.success.map((point, index) => ({
      date: point.date,
      success: point.value,
      failure: logins.failure[index]?.value ?? 0,
    }));

    const alerts: SecurityAlert[] = [];

    // Refresh-token replay. The rotation scheme already revoked the session, so
    // this is not "act now" - it is "find out why", and it is never routine.
    if (events.tokenReuse > 0) {
      alerts.push({
        id: 'token-reuse',
        level: SECURITY_ALERT_LEVEL.CRITICAL,
        title: 'Refresh token replay detected',
        detail:
          'A refresh token was presented after it had already been redeemed. The affected sessions were revoked automatically. This means a token leaked, or a client is retrying incorrectly - both are worth understanding.',
        count: events.tokenReuse,
        actionHref: `/admin/audit?action=auth.token.reuse_detected`,
        actionLabel: 'Review the audit trail',
      });
    }

    const sprayAddresses = failedAddresses.filter(
      (entry) => entry.distinctAccounts >= SPRAY_ACCOUNT_THRESHOLD,
    );
    if (sprayAddresses.length > 0) {
      alerts.push({
        id: 'password-spray',
        level: SECURITY_ALERT_LEVEL.CRITICAL,
        title: 'One source is failing sign-in across many accounts',
        detail: `${sprayAddresses.length} address${
          sprayAddresses.length === 1 ? '' : 'es'
        } failed against ${SPRAY_ACCOUNT_THRESHOLD} or more different accounts. Google sign-in cannot be password-guessed here, so this is someone presenting tokens for accounts that are locked, suspended or outside the allowed domain - worth a look.`,
        count: sprayAddresses.length,
        actionHref: '/admin/security',
        actionLabel: 'See the addresses',
      });
    }

    if (locked.length > 0) {
      alerts.push({
        id: 'locked-accounts',
        level: SECURITY_ALERT_LEVEL.WARNING,
        title: 'Accounts are locked',
        detail:
          'An administrator has locked these people out. A lock with an end date lifts itself; an open-ended one stays until it is lifted.',
        count: locked.length,
        actionHref: '/admin/users?status=locked',
        actionLabel: 'Review locked accounts',
      });
    }

    if (events.fingerprintMismatch > 0) {
      alerts.push({
        id: 'fingerprint-mismatch',
        level: SECURITY_ALERT_LEVEL.WARNING,
        title: 'Device fingerprints changed',
        detail:
          'A device presented different characteristics than when it was registered. A browser or OS update produces this routinely, so it is a prompt to look rather than evidence of anything - fingerprints are never treated as an authentication factor here.',
        count: events.fingerprintMismatch,
        actionHref: '/admin/devices',
        actionLabel: 'Review devices',
      });
    }

    if (hygiene.dormantTrustedDevices > 0) {
      alerts.push({
        id: 'dormant-devices',
        level: SECURITY_ALERT_LEVEL.INFO,
        title: 'Trusted devices have gone quiet',
        detail: `Trusted but unused for ${DORMANT_DEVICE_DAYS} days or more. Standing authorisation for hardware that may no longer exist is worth clearing.`,
        count: hygiene.dormantTrustedDevices,
        actionHref: '/admin/devices?status=trusted',
        actionLabel: 'Review trusted devices',
      });
    }

    if (hygiene.staleSessions > 0) {
      alerts.push({
        id: 'stale-sessions',
        level: SECURITY_ALERT_LEVEL.INFO,
        title: 'Sessions are idle but still valid',
        detail: `Active with no activity for ${STALE_SESSION_DAYS} days or more.`,
        count: hygiene.staleSessions,
        actionHref: '/admin/sessions',
        actionLabel: 'Review sessions',
      });
    }

    return {
      alerts,
      loginOutcomes,
      topFailedAccounts: failedAccounts,
      topFailedAddresses: failedAddresses,
      lockedAccounts: locked.map((entry) => ({
        userId: entry.userId,
        email: entry.email,
        fullName: entry.fullName,
        status: entry.status as SecurityDashboard['lockedAccounts'][number]['status'],
        lockedUntil: entry.lockedUntil,
      })),
      tokenReuseEvents: events.tokenReuse,
      fingerprintMismatches: events.fingerprintMismatch,
      staleSessions: hygiene.staleSessions,
      dormantTrustedDevices: hygiene.dormantTrustedDevices,
      windowDays,
      generatedAt: new Date().toISOString(),
    };
  },
};

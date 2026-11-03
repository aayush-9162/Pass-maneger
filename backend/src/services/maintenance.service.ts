/**
 * Background maintenance.
 *
 * Housekeeping that would otherwise need cron: expiring stale state and pruning
 * high-volume tables. Runs in-process on an interval.
 *
 * Correctness note: in a PM2 cluster every worker runs this loop, so each pass
 * executes N times. Every statement here is idempotent and `LIMIT`-bounded, so
 * duplicate passes are harmless - they simply find nothing left to do. If the
 * duplication ever becomes costly, move this to a single scheduled job; the
 * functions are deliberately callable on their own.
 *
 * None of this is load-bearing for security: expired sessions and lapsed device
 * trust are already rejected at request time by checking timestamps, not status
 * alone. This job keeps the *data* tidy, it does not enforce the policy.
 */

import { logger } from '../config/logger';
import { deviceRepository } from '../repositories/device.repository';
import { loginAttemptRepository } from '../repositories/login-attempt.repository';
import { accessRequestRepository } from '../repositories/access-request.repository';
import { sessionRepository } from '../repositories/session.repository';

/** How often the loop runs. */
const INTERVAL_MS = 15 * 60_000; // 15 minutes

/** Retention windows. */
const RETENTION = {
  /** Revoked/expired session rows. Audit history lives in `audit_logs`. */
  terminatedSessionDays: 30,
  /** Raw login attempts - forensics feed, not the compliance record. */
  loginAttemptDays: 90,
  /** Untrusted devices unused for this long are forgotten. */
  staleDeviceDays: 180,
  /**
   * Trashed vault items are purged after this long.
   *
   * Long enough that an accidental deletion is recoverable, short enough that
   * ciphertext a user believes they deleted does not linger indefinitely.
   */
  trashedItemDays: 30,
} as const;

export interface MaintenanceReport {
  /** Approval requests nobody acted on before they lapsed. */
  accessRequestsExpired: number;
  sessionsMarkedExpired: number;
  sessionsDeleted: number;
  deviceTrustExpired: number;
  devicesDeleted: number;
  loginAttemptsDeleted: number;
  vaultItemsPurged: number;
  durationMs: number;
}

let timer: NodeJS.Timeout | null = null;

export const maintenanceService = {
  /** Execute one maintenance pass. Safe to call directly (tests, manual runs). */
  async runOnce(): Promise<MaintenanceReport> {
    const startedAt = Date.now();

    const sessionsMarkedExpired = await sessionRepository.markExpiredSessions();
    const sessionsDeleted = await sessionRepository.deleteTerminatedOlderThan(
      RETENTION.terminatedSessionDays,
    );
    const deviceTrustExpired = await deviceRepository.expireLapsedTrust();
    const devicesDeleted = await deviceRepository.deleteStaleUntrusted(RETENTION.staleDeviceDays);
    const loginAttemptsDeleted = await loginAttemptRepository.deleteOlderThan(
      RETENTION.loginAttemptDays,
    );
    // Personal vaults are gone, and with them the trash this purge existed
    // for. Kept as a constant so the report shape (and its consumers) survive.
    const vaultItemsPurged = 0;
    // Lapse approval requests past their TTL. Without this, a request raised for
    // a reason that expired months ago stays approvable - and eventually
    // somebody approves it.
    const accessRequestsExpired = await accessRequestRepository.expireStale();

    const report: MaintenanceReport = {
      accessRequestsExpired,
      sessionsMarkedExpired,
      sessionsDeleted,
      deviceTrustExpired,
      devicesDeleted,
      loginAttemptsDeleted,
      vaultItemsPurged,
      durationMs: Date.now() - startedAt,
    };

    const touchedAnything = Object.entries(report).some(
      ([key, value]) => key !== 'durationMs' && value > 0,
    );

    // Only log when something actually changed: a quiet system should produce a
    // quiet log, so that a non-empty maintenance line is worth reading.
    if (touchedAnything) {
      logger.info('Maintenance pass complete', report);
    } else {
      logger.debug('Maintenance pass complete (nothing to do)', report);
    }

    return report;
  },

  /** Start the interval loop. Idempotent. */
  start(): void {
    if (timer) return;

    timer = setInterval(() => {
      // Never let a maintenance failure become an unhandled rejection and take
      // the process down.
      void this.runOnce().catch((error: unknown) => {
        logger.error('Maintenance pass failed', { error });
      });
    }, INTERVAL_MS);

    // Do not hold the event loop open: shutdown must not wait for the next tick.
    timer.unref();

    logger.info('Maintenance scheduler started', { intervalMinutes: INTERVAL_MS / 60_000 });
  },

  /** Stop the loop during graceful shutdown. */
  stop(): void {
    if (!timer) return;
    clearInterval(timer);
    timer = null;
    logger.info('Maintenance scheduler stopped');
  },
};

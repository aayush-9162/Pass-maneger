/**
 * Security notifications.
 *
 * ## What this is for
 *
 * The audit log records everything and is read by almost nobody. A notification
 * is the opposite: a small number of events, pushed at the one person who can
 * recognise them as wrong. "Signed in from a new device" is the single most
 * useful security signal in a password manager, because the user knows whether
 * it was them and no server-side heuristic does.
 *
 * ## Why every raise is gated on policy and deduplicated
 *
 * An alert channel that cries wolf is worse than no alert channel - people learn
 * to dismiss the badge without reading it, and then miss the one that mattered.
 * So each type is individually switchable by an administrator, and repeat events
 * of the same type collapse inside a window.
 *
 * ## Failure policy
 *
 * Raising a notification never fails the operation that triggered it. Nobody
 * should be unable to sign in because the notifications table is full. Every
 * method swallows its errors and logs.
 */

import {
  AUDIT_ACTIONS,
  NOTIFICATION_SEVERITY,
  NOTIFICATION_TYPE,
  ROLES,
  ROUTES,
  type NotificationSeverity,
  type NotificationType,
  type SecuritySettings,
  type SecurityNotification,
} from '@passm/shared';

import { logger } from '../config/logger';
import {
  notificationRepository,
  type CreateNotificationInput,
} from '../repositories/notification.repository';
import { userRepository } from '../repositories/user.repository';
import { auditService } from './audit.service';
import { securitySettingsService } from './security-settings.service';

/**
 * How long the same notification type is suppressed for one user.
 *
 * Per type, because the right window differs: a new device is worth telling
 * someone about every time it happens, while failed sign-ins arrive in bursts
 * and one alert per burst is the useful granularity.
 */
const DEDUPE_MINUTES: Partial<Record<NotificationType, number>> = {
  [NOTIFICATION_TYPE.FAILED_LOGINS]: 15,
  [NOTIFICATION_TYPE.NEW_LOCATION]: 60,
  [NOTIFICATION_TYPE.EMERGENCY_LOCK]: 60,
  // Someone poking at a field produces a burst - the observer fires on every
  // flip of the attribute. One alert per burst is the useful granularity; the
  // audit trail keeps every individual attempt.
  [NOTIFICATION_TYPE.PASSWORD_TAMPER]: 10,
};

/**
 * Which setting switches each type on.
 *
 * Types with no entry are always delivered - they are direct consequences of
 * something the user or an administrator just did, and suppressing them would
 * leave the user unable to explain their own account state.
 */
const POLICY_KEY: Partial<Record<NotificationType, keyof SecuritySettings>> = {
  [NOTIFICATION_TYPE.NEW_DEVICE]: 'notifyOnNewDevice',
  [NOTIFICATION_TYPE.NEW_LOCATION]: 'notifyOnNewLocation',
  [NOTIFICATION_TYPE.VAULT_SHARED]: 'notifyOnVaultShared',
  [NOTIFICATION_TYPE.ADMIN_ACTION]: 'notifyOnAdminAction',
  [NOTIFICATION_TYPE.PASSWORD_TAMPER]: 'notifyOnPasswordTamper',
};

export interface RaiseInput {
  userId: string;
  type: NotificationType;
  severity?: NotificationSeverity;
  title: string;
  body: string;
  metadata?: Record<string, string | number | boolean>;
  actionUrl?: string | null;
  actionLabel?: string | null;
  /** Skip the policy check. For alerts the user must always receive. */
  force?: boolean;
}

export const notificationService = {
  /**
   * Raise a notification, subject to policy and deduplication.
   *
   * Returns whether one was actually written, which the caller almost never
   * needs but the tests do.
   */
  async raise(input: RaiseInput): Promise<boolean> {
    try {
      if (!input.force) {
        const policyKey = POLICY_KEY[input.type];
        if (policyKey) {
          const enabled = await securitySettingsService.get(policyKey);
          if (enabled !== true) return false;
        }
      }

      const dedupeWindow = DEDUPE_MINUTES[input.type];
      if (dedupeWindow !== undefined) {
        const recent = await notificationRepository.existsRecent(
          input.userId,
          input.type,
          dedupeWindow,
        );
        if (recent) return false;
      }

      const payload: CreateNotificationInput = {
        userId: input.userId,
        type: input.type,
        severity: input.severity ?? NOTIFICATION_SEVERITY.INFO,
        title: input.title,
        body: input.body,
        metadata: input.metadata ?? null,
        actionUrl: input.actionUrl ?? null,
        actionLabel: input.actionLabel ?? null,
      };

      await notificationRepository.create(payload);

      // Recorded so the security dashboard can show what has been raised
      // without reading every user's private inbox.
      void auditService
        .record({
          action: AUDIT_ACTIONS.NOTIFICATION_RAISED,
          targetUserId: input.userId,
          isSharedResource: true,
          metadata: { notificationType: input.type, severity: payload.severity },
        })
        .catch(() => undefined);

      return true;
    } catch (error) {
      // Never propagate. A failure here must not break sign-in, sharing, or
      // whatever else triggered it.
      logger.error('Could not raise a security notification', {
        error,
        userId: input.userId,
        type: input.type,
      });
      return false;
    }
  },

  /**
   * Raise the same notification for every active administrator.
   *
   * Deduplication is per user, so a burst of attempts still produces at most one
   * alert each rather than one per administrator per attempt.
   */
  async raiseForAdmins(input: Omit<RaiseInput, 'userId'>): Promise<number> {
    try {
      const adminIds = await userRepository.listActiveIdsByRole(ROLES.ADMIN);
      const results = await Promise.all(
        adminIds.map(async (userId) => this.raise({ ...input, userId })),
      );
      return results.filter(Boolean).length;
    } catch (error) {
      logger.error('Could not fan a notification out to administrators', {
        error,
        type: input.type,
      });
      return 0;
    }
  },

  // -------------------------------------------------------------------------
  // Typed helpers
  //
  // Call sites read better as `notifyNewDevice(...)` than as a `raise` with six
  // string literals, and the wording stays consistent across the app rather than
  // being reinvented at each call site.
  // -------------------------------------------------------------------------

  /**
   * Somebody tried to unmask a password they are not allowed to see.
   *
   * Goes to administrators, never to the person who did it: they already know,
   * and telling them only teaches them that it is detected.
   */
  async notifyPasswordTamper(actor: {
    userId: string;
    name: string;
    host: string | null;
  }): Promise<void> {
    const where = actor.host ? ` on ${actor.host}` : '';
    await this.raiseForAdmins({
      type: NOTIFICATION_TYPE.PASSWORD_TAMPER,
      severity: NOTIFICATION_SEVERITY.WARNING,
      title: 'Someone tried to reveal a hidden password',
      body:
        `${actor.name} tried to unmask a password${where}. The field was re-masked ` +
        'automatically, but this is a deliberate attempt to read a credential the ' +
        'password-access policy hides from them.',
      metadata: {
        actorUserId: actor.userId,
        ...(actor.host ? { host: actor.host } : {}),
      },
      actionUrl: '/admin/audit?action=item.reveal.blocked',
      actionLabel: 'See the attempts',
    });
  },

  async notifyNewDevice(userId: string, deviceName: string, ip: string): Promise<void> {
    await this.raise({
      userId,
      type: NOTIFICATION_TYPE.NEW_DEVICE,
      severity: NOTIFICATION_SEVERITY.WARNING,
      title: 'New device signed in',
      body: `"${deviceName}" signed in from ${ip}. If this was not you, remove the device and change your password now.`,
      metadata: { deviceName, ip },
      actionUrl: '/settings?tab=devices',
      actionLabel: 'Review devices',
    });
  },

  async notifyNewLocation(userId: string, ip: string): Promise<void> {
    await this.raise({
      userId,
      type: NOTIFICATION_TYPE.NEW_LOCATION,
      severity: NOTIFICATION_SEVERITY.INFO,
      title: 'Sign-in from a new address',
      body: `Your account was accessed from ${ip}, which has not been seen before.`,
      metadata: { ip },
      actionUrl: '/settings?tab=sessions',
      actionLabel: 'Review sessions',
    });
  },

  async notifyVaultShared(userId: string, vaultName: string, sharedBy: string): Promise<void> {
    await this.raise({
      userId,
      type: NOTIFICATION_TYPE.VAULT_SHARED,
      severity: NOTIFICATION_SEVERITY.INFO,
      title: 'A vault was shared with you',
      body: `${sharedBy} gave you access to "${vaultName}".`,
      metadata: { vaultName, sharedBy },
      actionUrl: ROUTES.SHARED.VAULTS.replace('/shared', '/shared'),
      actionLabel: 'Open shared vaults',
    });
  },

  async notifyAdminAction(userId: string, action: string, byName: string): Promise<void> {
    await this.raise({
      userId,
      type: NOTIFICATION_TYPE.ADMIN_ACTION,
      severity: NOTIFICATION_SEVERITY.WARNING,
      title: 'An administrator acted on your account',
      body: `${byName} ${action}.`,
      metadata: { action, byName },
    });
  },

  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  async list(
    userId: string,
    options: { limit: number; offset: number; unreadOnly: boolean },
  ): Promise<{ items: SecurityNotification[]; unreadCount: number; total: number }> {
    const [items, unreadCount, total] = await Promise.all([
      notificationRepository.findForUser(userId, options),
      notificationRepository.countForUser(userId, true),
      notificationRepository.countForUser(userId, false),
    ]);

    return { items, unreadCount, total };
  },

  async markRead(userId: string, ids: readonly string[]): Promise<number> {
    return notificationRepository.markRead(userId, ids);
  },

  async remove(userId: string, id: string): Promise<boolean> {
    return notificationRepository.remove(userId, id);
  },

  /**
   * Tell every user the emergency lock is on.
   *
   * Called with the affected user ids rather than fanning out over the whole
   * table, so a lock during an incident does not also become a write storm.
   */
  async notifyEmergencyLock(userIds: readonly string[], message: string): Promise<void> {
    for (const userId of userIds) {
      await this.raise({
        userId,
        type: NOTIFICATION_TYPE.EMERGENCY_LOCK,
        severity: NOTIFICATION_SEVERITY.CRITICAL,
        title: 'Access suspended',
        body: message,
        force: true,
      });
    }
  },
};

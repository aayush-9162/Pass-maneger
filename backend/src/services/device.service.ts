/**
 * Device registration and "remember this device".
 *
 * ## What device trust is - and is not
 *
 * A trusted device lets the user skip *step-up* checks (today: the second-factor
 * prompt once MFA enrolment ships). It never replaces the password. Trust is
 * granted only by a successful password login with `rememberDevice`, so holding
 * an access token is not enough to promote a device.
 *
 * Trust is proven by two things together:
 *  1. A device-trust JWT in an httpOnly cookie, and
 *  2. an HMAC of that JWT stored on the `devices` row.
 *
 * Requiring both means revocation is instant and server-side: clearing the row
 * invalidates a cookie the attacker may still hold.
 *
 * ## Fingerprints
 *
 * `fingerprint_hash` is a *change detector*, never an authentication factor -
 * browser fingerprints are trivially forged. A changed fingerprint on a trusted
 * device downgrades it to untrusted and writes an audit event, which is a
 * conservative response to "this cookie appeared on a different-looking client".
 */

import {
  AUDIT_ACTIONS,
  DEVICE_STATUS,
  ERROR_CODES,
  SESSION_REVOKE_REASON,
  type DeviceIdentity,
  type DeviceInfo,
} from '@passm/shared';

import { env } from '../config/env';
import { logger } from '../config/logger';
import { isDeviceTrusted, toDeviceInfo, type DeviceRecord } from '../models/device.model';
import { deviceRepository } from '../repositories/device.repository';
import type { RequestContext } from '../types/auth.types';
import { AppError, ForbiddenError, NotFoundError } from '../utils/errors';
import { newId } from '../utils/ids';
import { inferDeviceName, inferPlatform } from '../utils/request-context';
import { auditService } from './audit.service';
import { hashToken, sha256Hex, timingSafeEqual } from './crypto.service';
import { sessionService } from './session.service';
import { signDeviceTrustToken, verifyDeviceTrustToken } from './token.service';

export interface RegisteredDevice {
  device: DeviceRecord;
  /** True when this login created the device row. */
  isNew: boolean;
  /** True when a previously recorded fingerprint no longer matches. */
  fingerprintChanged: boolean;
  /**
   * Device id the client must persist. Echoed back so a client that did not send
   * one can store the server-generated value and be recognised next time.
   */
  deviceId: string;
}

export interface GrantedTrust {
  trustToken: string;
  expiresAt: Date;
  expiresInSeconds: number;
}

export const deviceService = {
  /**
   * Register (or refresh) the device taking part in a login.
   *
   * Called after credentials are verified: an unauthenticated caller must not be
   * able to fill the `devices` table.
   */
  async registerForLogin(params: {
    userId: string;
    identity: DeviceIdentity | null;
    context: RequestContext;
  }): Promise<RegisteredDevice> {
    const { userId, identity, context } = params;

    // A client that sent no device id gets one allocated; it is returned in the
    // login response so the next request is recognised as the same device.
    const deviceId = identity?.deviceId ?? newId();
    const platform = identity?.platform ?? inferPlatform(context.userAgent);
    const name = identity?.name ?? inferDeviceName(context.userAgent);
    const fingerprintHash = identity?.fingerprint ? sha256Hex(identity.fingerprint) : null;

    const existing = await deviceRepository.findByUserAndClientDeviceId(userId, deviceId);

    if (!existing) {
      await this.enforceDeviceLimit(userId, context);
    }

    const { device, isNew } = await deviceRepository.upsert({
      userId,
      deviceId,
      name,
      platform,
      fingerprintHash,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });

    // Compare against the value from *before* this upsert: the upsert itself
    // may have written the new fingerprint.
    const previousFingerprint = existing?.fingerprintHash ?? null;
    const fingerprintChanged =
      previousFingerprint !== null &&
      fingerprintHash !== null &&
      !timingSafeEqual(previousFingerprint, fingerprintHash);

    if (fingerprintChanged) {
      logger.warn('Device fingerprint changed', {
        userId,
        deviceRowId: device.id,
        requestId: context.requestId,
      });

      await auditService.recordFailure({
        action: AUDIT_ACTIONS.DEVICE_FINGERPRINT_MISMATCH,
        actorUserId: userId,
        targetUserId: userId,
        deviceId: device.id,
        context,
        metadata: { deviceName: device.name, platform: device.platform },
      });

      // Conservative response: a trusted device whose fingerprint moved is no
      // longer treated as trusted until the user opts in again.
      if (isDeviceTrusted(device)) {
        await deviceRepository.revokeTrust(device.id, false);
        await auditService.record({
          action: AUDIT_ACTIONS.DEVICE_TRUST_REVOKED,
          actorUserId: userId,
          targetUserId: userId,
          deviceId: device.id,
          context,
          metadata: { reason: 'fingerprint_changed' },
        });
      }
    }

    if (isNew) {
      await auditService.record({
        action: AUDIT_ACTIONS.DEVICE_REGISTERED,
        actorUserId: userId,
        targetUserId: userId,
        deviceId: device.id,
        context,
        metadata: { deviceName: device.name, platform: device.platform },
      });
    }

    // Re-read when trust was just dropped, so callers see the current status.
    const current = fingerprintChanged
      ? ((await deviceRepository.findById(device.id)) ?? device)
      : device;

    return { device: current, isNew, fingerprintChanged, deviceId };
  },

  /**
   * Keep the device count bounded.
   *
   * Evicts the least recently used *untrusted* device rather than rejecting the
   * login: a hard failure would let an attacker lock a user out just by
   * registering devices. If every slot is held by a trusted device the user must
   * revoke one explicitly - that is a deliberate decision they should make.
   */
  async enforceDeviceLimit(userId: string, context: RequestContext): Promise<void> {
    const activeCount = await deviceRepository.countActiveForUser(userId);
    if (activeCount < env.security.maxDevicesPerUser) return;

    const devices = await deviceRepository.listByUser(userId);
    const evictable = devices
      .filter((device) => !isDeviceTrusted(device) && device.status !== DEVICE_STATUS.REVOKED)
      .sort(
        (a, b) =>
          (a.lastUsedAt?.getTime() ?? a.createdAt.getTime()) -
          (b.lastUsedAt?.getTime() ?? b.createdAt.getTime()),
      );

    const victim = evictable[0];

    if (!victim) {
      throw new AppError(
        409,
        ERROR_CODES.DEVICE_LIMIT_REACHED,
        `You have reached the maximum of ${env.security.maxDevicesPerUser} remembered devices. ` +
          'Remove one from your account settings before signing in from a new device.',
      );
    }

    await sessionService.revokeAllForDevice(victim.id, SESSION_REVOKE_REASON.DEVICE_REVOKED);
    await deviceRepository.revokeTrust(victim.id, true);

    logger.info('Evicted least-recently-used device to honour the per-user cap', {
      userId,
      deviceRowId: victim.id,
      cap: env.security.maxDevicesPerUser,
    });

    await auditService.record({
      action: AUDIT_ACTIONS.DEVICE_TRUST_REVOKED,
      actorUserId: userId,
      targetUserId: userId,
      deviceId: victim.id,
      context,
      metadata: { reason: 'device_limit_reached', deviceName: victim.name },
    });
  },

  /**
   * Grant "remember this device" and issue the trust token.
   *
   * Only the token's HMAC is stored, so the database alone cannot be used to
   * mint a working cookie.
   */
  async grantTrust(params: {
    userId: string;
    device: DeviceRecord;
    context: RequestContext;
  }): Promise<GrantedTrust | null> {
    const { userId, device, context } = params;

    if (device.status === DEVICE_STATUS.REVOKED) {
      // A revoked device must be reinstated deliberately, not by logging in.
      logger.warn('Refused to trust a revoked device', { userId, deviceRowId: device.id });
      return null;
    }

    const issued = signDeviceTrustToken({
      userId,
      deviceRowId: device.id,
      deviceId: device.deviceId,
    });

    const granted = await deviceRepository.grantTrust(
      device.id,
      hashToken(issued.token),
      issued.expiresAt,
    );

    if (!granted) return null;

    await auditService.record({
      action: AUDIT_ACTIONS.DEVICE_TRUSTED,
      actorUserId: userId,
      targetUserId: userId,
      deviceId: device.id,
      context,
      metadata: {
        deviceName: device.name,
        expiresAt: issued.expiresAt.toISOString(),
      },
    });

    return {
      trustToken: issued.token,
      expiresAt: issued.expiresAt,
      expiresInSeconds: issued.expiresInSeconds,
    };
  },

  /**
   * Validate a device-trust cookie.
   *
   * All four must hold: valid signature, the row is still trusted and unexpired,
   * the stored HMAC matches this exact token, and the token's user/device match
   * the caller. Any failure is simply "not trusted" - never an error, because an
   * expired trust cookie is a normal condition.
   */
  async verifyTrust(params: {
    trustToken: string | undefined;
    userId: string;
    deviceRowId: string;
  }): Promise<boolean> {
    const { trustToken, userId, deviceRowId } = params;
    if (!trustToken) return false;

    try {
      const claims = verifyDeviceTrustToken(trustToken);
      if (claims.userId !== userId || claims.deviceRowId !== deviceRowId) return false;

      const device = await deviceRepository.findById(deviceRowId);
      if (!device || device.userId !== userId) return false;
      if (!isDeviceTrusted(device)) return false;
      if (device.deviceId !== claims.deviceId) return false;

      return (
        device.trustTokenHash !== null &&
        timingSafeEqual(device.trustTokenHash, hashToken(trustToken))
      );
    } catch {
      // Expired or malformed cookie: not trusted, nothing more to report.
      return false;
    }
  },

  /** Devices for a user, newest/trusted first. */
  async listForUser(userId: string, currentDeviceRowId?: string): Promise<DeviceInfo[]> {
    const devices = await deviceRepository.listByUser(userId);
    return devices.map((device) => toDeviceInfo(device, currentDeviceRowId));
  },

  /**
   * Withdraw trust from a device the caller owns.
   *
   * Also revokes the device's sessions: leaving them alive would defeat the
   * point of "this device is no longer mine".
   */
  async revokeTrust(params: {
    deviceRowId: string;
    ownerUserId: string;
    actorUserId: string;
    context: RequestContext;
    blockDevice?: boolean;
  }): Promise<DeviceInfo> {
    const { deviceRowId, ownerUserId, actorUserId, context, blockDevice = true } = params;

    const device = await deviceRepository.findByIdForUser(deviceRowId, ownerUserId);
    if (!device) throw new NotFoundError('Device not found.');

    await deviceRepository.revokeTrust(device.id, blockDevice);
    const revokedSessions = await sessionService.revokeAllForDevice(
      device.id,
      SESSION_REVOKE_REASON.DEVICE_REVOKED,
    );

    await auditService.record({
      action: AUDIT_ACTIONS.DEVICE_TRUST_REVOKED,
      actorUserId,
      targetUserId: ownerUserId,
      deviceId: device.id,
      context,
      metadata: {
        deviceName: device.name,
        revokedSessions,
        blocked: blockDevice,
        selfService: actorUserId === ownerUserId,
      },
    });

    const updated = await deviceRepository.findById(device.id);
    return toDeviceInfo(updated ?? device);
  },

  /**
   * Administrative revocation by device id alone.
   *
   * The owner is resolved from the device row. {@link deviceService.revokeTrust}
   * requires the caller to name the owner, which is the right shape for the
   * self-service path (it makes an IDOR impossible), but wrong for an admin
   * console showing a flat list of every device in the tenant - there, taking
   * the owner from the request would let a caller mis-attribute the action.
   */
  async revokeTrustById(params: {
    deviceRowId: string;
    actorUserId: string;
    context: RequestContext;
    blockDevice?: boolean;
  }): Promise<DeviceInfo> {
    const device = await deviceRepository.findById(params.deviceRowId);
    if (!device) throw new NotFoundError('Device not found.');

    return this.revokeTrust({
      deviceRowId: device.id,
      ownerUserId: device.userId,
      actorUserId: params.actorUserId,
      context: params.context,
      blockDevice: params.blockDevice ?? true,
    });
  },

  /** Rename a device the caller owns. */
  async rename(params: {
    deviceRowId: string;
    userId: string;
    name: string;
  }): Promise<DeviceInfo> {
    const device = await deviceRepository.findByIdForUser(params.deviceRowId, params.userId);
    if (!device) throw new NotFoundError('Device not found.');

    await deviceRepository.rename(device.id, params.name);
    return toDeviceInfo({ ...device, name: params.name }, device.id);
  },

  /**
   * Load a device, asserting ownership.
   * @throws {ForbiddenError} when the device belongs to someone else.
   */
  async requireOwnedDevice(deviceRowId: string, userId: string): Promise<DeviceRecord> {
    const device = await deviceRepository.findById(deviceRowId);
    if (!device) throw new NotFoundError('Device not found.');
    if (device.userId !== userId) {
      throw new ForbiddenError('You do not have access to this device.');
    }
    return device;
  },
};

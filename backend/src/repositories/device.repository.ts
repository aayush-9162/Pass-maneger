/**
 * Device repository.
 *
 * Device rows are keyed by `(user_id, device_id)`, so the same physical browser
 * yields one row per user account. {@link deviceRepository.upsert} relies on that
 * unique index: `INSERT ... ON DUPLICATE KEY UPDATE` makes "register on first
 * sight, touch on every later sight" a single atomic statement, with no
 * check-then-insert race between two concurrent logins.
 */

import { DEVICE_STATUS, type DevicePlatform } from '@passm/shared';

import { execute, query, queryOne, type RowDataPacket, type SqlExecutor } from '../config/database';
import { mapDeviceRow, type DeviceRecord, type DeviceRow } from '../models/device.model';
import { newId } from '../utils/ids';

const DEVICE_COLUMNS = `
  id, user_id, device_id, name, platform, fingerprint_hash,
  status, trust_token_hash, trust_granted_at, trust_expires_at,
  last_ip_address, last_user_agent, last_used_at, created_at, updated_at
`;

export interface UpsertDeviceInput {
  userId: string;
  deviceId: string;
  name: string;
  platform: DevicePlatform;
  fingerprintHash: string | null;
  ipAddress: string | null;
  userAgent: string | null;
}

interface CountRow extends RowDataPacket {
  total: number;
}

export const deviceRepository = {
  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  async findById(id: string, executor?: SqlExecutor): Promise<DeviceRecord | null> {
    const row = await queryOne<DeviceRow>(
      `SELECT ${DEVICE_COLUMNS} FROM devices WHERE id = ? LIMIT 1`,
      [id],
      executor,
    );
    return row ? mapDeviceRow(row) : null;
  },

  /**
   * Scoped lookup: the id *and* the owner must match.
   *
   * Every device endpoint uses this rather than `findById`, which is what
   * prevents an IDOR - passing someone else's device id returns null instead of
   * their record.
   */
  async findByIdForUser(
    id: string,
    userId: string,
    executor?: SqlExecutor,
  ): Promise<DeviceRecord | null> {
    const row = await queryOne<DeviceRow>(
      `SELECT ${DEVICE_COLUMNS} FROM devices WHERE id = ? AND user_id = ? LIMIT 1`,
      [id, userId],
      executor,
    );
    return row ? mapDeviceRow(row) : null;
  },

  async findByUserAndClientDeviceId(
    userId: string,
    deviceId: string,
    executor?: SqlExecutor,
  ): Promise<DeviceRecord | null> {
    const row = await queryOne<DeviceRow>(
      `SELECT ${DEVICE_COLUMNS} FROM devices WHERE user_id = ? AND device_id = ? LIMIT 1`,
      [userId, deviceId],
      executor,
    );
    return row ? mapDeviceRow(row) : null;
  },

  async listByUser(userId: string, executor?: SqlExecutor): Promise<DeviceRecord[]> {
    const rows = await query<DeviceRow>(
      `SELECT ${DEVICE_COLUMNS} FROM devices
        WHERE user_id = ?
        ORDER BY (status = 'trusted') DESC, last_used_at DESC, created_at DESC
        LIMIT 200`,
      [userId],
      executor,
    );
    return rows.map(mapDeviceRow);
  },

  /** Devices that still count against MAX_DEVICES_PER_USER (revoked ones do not). */
  async countActiveForUser(userId: string, executor?: SqlExecutor): Promise<number> {
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM devices WHERE user_id = ? AND status <> ?`,
      [userId, DEVICE_STATUS.REVOKED],
      executor,
    );
    return row?.total ?? 0;
  },

  // -------------------------------------------------------------------------
  // Writes
  // -------------------------------------------------------------------------

  /**
   * Register the device if unseen, otherwise refresh its "last seen" columns.
   *
   * Deliberately does *not* touch `status`, `trust_token_hash` or
   * `trust_expires_at`: simply showing up must never grant or extend trust, and a
   * revoked device must stay revoked no matter how often it reconnects.
   *
   * @returns the row and whether it was created by this call.
   */
  async upsert(
    input: UpsertDeviceInput,
    executor?: SqlExecutor,
  ): Promise<{ device: DeviceRecord; isNew: boolean }> {
    const id = newId();

    // Uses the row-alias form of ON DUPLICATE KEY UPDATE (MySQL 8.0.19+) rather
    // than the VALUES() function, which is deprecated in 8.0.20+ and would emit
    // a server warning on every login.
    const result = await execute(
      `INSERT INTO devices (
         id, user_id, device_id, name, platform, fingerprint_hash,
         status, last_ip_address, last_user_agent, last_used_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(3)) AS incoming
       ON DUPLICATE KEY UPDATE
         name             = COALESCE(NULLIF(incoming.name, ''), devices.name),
         platform         = incoming.platform,
         fingerprint_hash = COALESCE(incoming.fingerprint_hash, devices.fingerprint_hash),
         last_ip_address  = incoming.last_ip_address,
         last_user_agent  = incoming.last_user_agent,
         last_used_at     = NOW(3)`,
      [
        id,
        input.userId,
        input.deviceId,
        input.name,
        input.platform,
        input.fingerprintHash,
        DEVICE_STATUS.REGISTERED,
        input.ipAddress,
        input.userAgent,
      ],
      executor,
    );

    // mysql2 reports affectedRows === 1 for an insert and 2 for an update that
    // actually changed columns (0 when the update was a no-op).
    const isNew = result.affectedRows === 1;

    const device = await this.findByUserAndClientDeviceId(input.userId, input.deviceId, executor);
    if (!device) {
      // Only reachable if the row vanished between the upsert and the read.
      throw new Error('Device upsert succeeded but the row could not be read back.');
    }

    return { device, isNew };
  },

  /** Refresh "last seen" metadata on an already-known device. */
  async touch(
    id: string,
    ipAddress: string | null,
    userAgent: string | null,
    executor?: SqlExecutor,
  ): Promise<void> {
    await execute(
      `UPDATE devices
          SET last_ip_address = ?, last_user_agent = ?, last_used_at = NOW(3)
        WHERE id = ?`,
      [ipAddress, userAgent, id],
      executor,
    );
  },

  /** Store a newly observed fingerprint after a mismatch has been audited. */
  async updateFingerprint(
    id: string,
    fingerprintHash: string | null,
    executor?: SqlExecutor,
  ): Promise<void> {
    await execute('UPDATE devices SET fingerprint_hash = ? WHERE id = ?', [fingerprintHash, id], executor);
  },

  /**
   * Grant "remember this device".
   *
   * Only reachable from a successful password login, and only for a device that
   * is not revoked - re-trusting a revoked device must require an explicit admin
   * or user action, not just another login.
   *
   * @returns `true` when trust was granted.
   */
  async grantTrust(
    id: string,
    trustTokenHash: string,
    expiresAt: Date,
    executor?: SqlExecutor,
  ): Promise<boolean> {
    const result = await execute(
      `UPDATE devices
          SET status = ?, trust_token_hash = ?, trust_granted_at = NOW(3), trust_expires_at = ?
        WHERE id = ? AND status <> ?`,
      [DEVICE_STATUS.TRUSTED, trustTokenHash, expiresAt, id, DEVICE_STATUS.REVOKED],
      executor,
    );
    return result.affectedRows >= 1;
  },

  /**
   * Withdraw trust.
   *
   * @param revoke `true` marks the device `revoked` (an admin/user kill switch);
   *   `false` returns it to `registered`, which is what an expired grant means.
   */
  async revokeTrust(id: string, revoke: boolean, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute(
      `UPDATE devices
          SET status = ?, trust_token_hash = NULL, trust_granted_at = NULL, trust_expires_at = NULL
        WHERE id = ?`,
      [revoke ? DEVICE_STATUS.REVOKED : DEVICE_STATUS.REGISTERED, id],
      executor,
    );
    return result.affectedRows === 1;
  },

  /** Restore a revoked device to `registered` (admin un-block). */
  async reinstate(id: string, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute(
      `UPDATE devices SET status = ? WHERE id = ? AND status = ?`,
      [DEVICE_STATUS.REGISTERED, id, DEVICE_STATUS.REVOKED],
      executor,
    );
    return result.affectedRows === 1;
  },

  async rename(id: string, name: string, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute('UPDATE devices SET name = ? WHERE id = ?', [name, id], executor);
    return result.affectedRows === 1;
  },

  // -------------------------------------------------------------------------
  // Maintenance
  // -------------------------------------------------------------------------

  /** Demote devices whose trust grant has lapsed back to `registered`. */
  async expireLapsedTrust(executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE devices
          SET status = ?, trust_token_hash = NULL, trust_granted_at = NULL, trust_expires_at = NULL
        WHERE status = ? AND trust_expires_at IS NOT NULL AND trust_expires_at <= NOW(3)`,
      [DEVICE_STATUS.REGISTERED, DEVICE_STATUS.TRUSTED],
      executor,
    );
    return result.affectedRows;
  },

  /** Delete untrusted devices unused for `days` (keeps the device list readable). */
  async deleteStaleUntrusted(days: number, executor?: SqlExecutor): Promise<number> {
    const safeDays = Math.min(Math.max(Math.floor(days), 7), 3650);
    const result = await execute(
      `DELETE FROM devices
        WHERE status = ?
          AND (last_used_at IS NULL OR last_used_at < DATE_SUB(NOW(3), INTERVAL ? DAY))
          AND created_at < DATE_SUB(NOW(3), INTERVAL ? DAY)
        LIMIT 1000`,
      [DEVICE_STATUS.REGISTERED, safeDays, safeDays],
      executor,
    );
    return result.affectedRows;
  },
};

/** Device model. */

import {
  DEVICE_PLATFORM,
  DEVICE_STATUS,
  type DeviceInfo,
  type DevicePlatform,
  type DeviceStatus,
} from '@passm/shared';
import type { RowDataPacket } from 'mysql2';

import { isFuture, toIso, toIsoRequired } from '../utils/date';

export interface DeviceRow extends RowDataPacket {
  id: string;
  user_id: string;
  device_id: string;
  name: string;
  platform: string;
  fingerprint_hash: string | null;
  status: string;
  trust_token_hash: string | null;
  trust_granted_at: Date | null;
  trust_expires_at: Date | null;
  last_ip_address: string | null;
  last_user_agent: string | null;
  last_used_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface DeviceRecord {
  id: string;
  userId: string;
  /** Client-generated identifier. */
  deviceId: string;
  name: string;
  platform: DevicePlatform;
  fingerprintHash: string | null;
  status: DeviceStatus;
  /** HMAC of the issued device-trust token - never serialize. */
  trustTokenHash: string | null;
  trustGrantedAt: Date | null;
  trustExpiresAt: Date | null;
  lastIpAddress: string | null;
  lastUserAgent: string | null;
  lastUsedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export function mapDeviceRow(row: DeviceRow): DeviceRecord {
  return {
    id: row.id,
    userId: row.user_id,
    deviceId: row.device_id,
    name: row.name,
    platform: (Object.values(DEVICE_PLATFORM) as string[]).includes(row.platform)
      ? (row.platform as DevicePlatform)
      : DEVICE_PLATFORM.UNKNOWN,
    fingerprintHash: row.fingerprint_hash,
    status: row.status as DeviceStatus,
    trustTokenHash: row.trust_token_hash,
    trustGrantedAt: row.trust_granted_at,
    trustExpiresAt: row.trust_expires_at,
    lastIpAddress: row.last_ip_address,
    lastUserAgent: row.last_user_agent,
    lastUsedAt: row.last_used_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Is this device currently trusted?
 *
 * Requires all three: status `trusted`, a stored token hash, and an unexpired
 * grant. Checking the timestamp as well as the status means an expired grant
 * stops counting immediately, even before the maintenance job rewrites the row.
 */
export function isDeviceTrusted(device: DeviceRecord): boolean {
  return (
    device.status === DEVICE_STATUS.TRUSTED &&
    device.trustTokenHash !== null &&
    isFuture(device.trustExpiresAt)
  );
}

/** Client-safe projection. Drops `trustTokenHash` and `fingerprintHash`. */
export function toDeviceInfo(device: DeviceRecord, currentDeviceRowId?: string): DeviceInfo {
  return {
    id: device.id,
    deviceId: device.deviceId,
    name: device.name,
    platform: device.platform,
    status: device.status,
    trusted: isDeviceTrusted(device),
    trustExpiresAt: toIso(device.trustExpiresAt),
    lastIpAddress: device.lastIpAddress,
    lastUsedAt: toIso(device.lastUsedAt),
    isCurrent: currentDeviceRowId !== undefined && device.id === currentDeviceRowId,
    createdAt: toIsoRequired(device.createdAt),
  };
}

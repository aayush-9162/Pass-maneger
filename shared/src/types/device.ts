/** Device registration and "remember this device" types. */

/** Broad device class, derived from the User-Agent and reported by the client. */
export const DEVICE_PLATFORM = {
  WEB: 'web',
  EXTENSION: 'extension',
  DESKTOP: 'desktop',
  MOBILE: 'mobile',
  UNKNOWN: 'unknown',
} as const;

export type DevicePlatform = (typeof DEVICE_PLATFORM)[keyof typeof DEVICE_PLATFORM];

export const DEVICE_STATUS = {
  /** Seen before, but not marked as trusted - full login required each time. */
  REGISTERED: 'registered',
  /** User checked "remember this device"; step-up checks may be skipped. */
  TRUSTED: 'trusted',
  /** Trust withdrawn by the user or an admin. */
  REVOKED: 'revoked',
} as const;

export type DeviceStatus = (typeof DEVICE_STATUS)[keyof typeof DEVICE_STATUS];

/** Device metadata as sent by a client on every request (see `HEADERS`). */
export interface DeviceIdentity {
  /** Stable UUID v4 generated once per browser/profile and persisted locally. */
  deviceId: string;
  /**
   * Client-computed fingerprint (hashed browser + platform signals).
   * Used only as a *change detector*, never as an authentication factor.
   */
  fingerprint?: string;
  /** User friendly label, e.g. "Chrome on Windows". */
  name?: string;
  platform?: DevicePlatform;
}

/** Device record as returned to clients. */
export interface DeviceInfo {
  id: string;
  deviceId: string;
  name: string;
  platform: DevicePlatform;
  status: DeviceStatus;
  trusted: boolean;
  /** When the trust grant expires (null when not trusted). */
  trustExpiresAt: string | null;
  lastIpAddress: string | null;
  lastUsedAt: string | null;
  /** True when this record matches the device making the current request. */
  isCurrent: boolean;
  createdAt: string;
}

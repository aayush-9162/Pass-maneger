/** Session model. */

import { SESSION_STATUS, type SessionInfo, type SessionStatus } from '@passm/shared';
import type { RowDataPacket } from 'mysql2';

import { isFuture, toIsoRequired } from '../utils/date';

export interface SessionRow extends RowDataPacket {
  id: string;
  user_id: string;
  device_id: string | null;
  refresh_token_hash: string;
  previous_refresh_token_hash: string | null;
  refresh_token_generation: number;
  status: string;
  ip_address: string | null;
  user_agent: string | null;
  created_at: Date;
  last_activity_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  revoked_reason: string | null;
  /** Present when the repository joins `devices` for display purposes. */
  device_name?: string | null;
  device_client_id?: string | null;
}

export interface SessionRecord {
  id: string;
  userId: string;
  deviceRowId: string | null;
  /** HMAC of the current refresh token - never serialize. */
  refreshTokenHash: string;
  previousRefreshTokenHash: string | null;
  refreshTokenGeneration: number;
  status: SessionStatus;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  revokedReason: string | null;
  deviceName: string | null;
  deviceClientId: string | null;
}

export function mapSessionRow(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    userId: row.user_id,
    deviceRowId: row.device_id,
    refreshTokenHash: row.refresh_token_hash,
    previousRefreshTokenHash: row.previous_refresh_token_hash,
    refreshTokenGeneration: row.refresh_token_generation,
    status: row.status as SessionStatus,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    createdAt: row.created_at,
    lastActivityAt: row.last_activity_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    revokedReason: row.revoked_reason,
    deviceName: row.device_name ?? null,
    deviceClientId: row.device_client_id ?? null,
  };
}

/**
 * Is this session usable right now?
 *
 * Absolute expiry is checked here; the *idle* timeout is applied by
 * `session.service` because it needs the configured policy window.
 */
export function isSessionUsable(session: SessionRecord): boolean {
  return session.status === SESSION_STATUS.ACTIVE && isFuture(session.expiresAt);
}

/** Client-safe projection. Drops both token hashes. */
export function toSessionInfo(session: SessionRecord, currentSessionId?: string): SessionInfo {
  return {
    id: session.id,
    deviceId: session.deviceClientId,
    deviceName: session.deviceName,
    status: session.status,
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    isCurrent: currentSessionId !== undefined && session.id === currentSessionId,
    createdAt: toIsoRequired(session.createdAt),
    lastActivityAt: toIsoRequired(session.lastActivityAt),
    expiresAt: toIsoRequired(session.expiresAt),
  };
}

/** Cached session snapshot - the minimum needed to authorize a request. */
export interface CachedSession {
  id: string;
  userId: string;
  deviceRowId: string | null;
  status: SessionStatus;
  expiresAtMs: number;
  lastActivityAtMs: number;
  /**
   * Sign-in time, for the absolute timeout.
   *
   * Optional because a snapshot cached by an older build will not have it. Those
   * drain within `SESSION_CACHE_TTL_SECONDS`; until they do, the absolute check
   * is skipped rather than comparing against `NaN`, which would read as "expired"
   * and sign out every user at once on deploy.
   */
  createdAtMs?: number;
}

export function toCachedSession(session: SessionRecord): CachedSession {
  return {
    id: session.id,
    userId: session.userId,
    deviceRowId: session.deviceRowId,
    status: session.status,
    expiresAtMs: session.expiresAt.getTime(),
    lastActivityAtMs: session.lastActivityAt.getTime(),
    createdAtMs: session.createdAt.getTime(),
  };
}

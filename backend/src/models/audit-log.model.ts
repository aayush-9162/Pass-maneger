/** Audit log model. */

import type { AuditAction, AuditLogEntry, AuditOutcome } from '@passm/shared';
import type { RowDataPacket } from 'mysql2';

import { toIsoRequired } from '../utils/date';

export interface AuditLogRow extends RowDataPacket {
  id: string;
  action: string;
  outcome: string;
  actor_user_id: string | null;
  actor_email: string | null;
  target_user_id: string | null;
  session_id: string | null;
  device_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  /**
   * mysql2 parses JSON columns into objects already. Older MySQL/driver
   * combinations can hand back a string, so both are handled on read.
   */
  metadata: unknown;
  created_at: Date;
}

export interface AuditLogRecord {
  id: string;
  action: AuditAction;
  outcome: AuditOutcome;
  actorUserId: string | null;
  actorEmail: string | null;
  targetUserId: string | null;
  sessionId: string | null;
  deviceId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  requestId: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

function parseMetadata(value: unknown): Record<string, unknown> | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object') return value as Record<string, unknown>;
  if (typeof value === 'string') {
    try {
      const parsed: unknown = JSON.parse(value);
      return typeof parsed === 'object' && parsed !== null
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      // Never let a malformed audit row break a listing.
      return null;
    }
  }
  return null;
}

export function mapAuditLogRow(row: AuditLogRow): AuditLogRecord {
  return {
    id: row.id,
    action: row.action as AuditAction,
    outcome: row.outcome as AuditOutcome,
    actorUserId: row.actor_user_id,
    actorEmail: row.actor_email,
    targetUserId: row.target_user_id,
    sessionId: row.session_id,
    deviceId: row.device_id,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    requestId: row.request_id,
    metadata: parseMetadata(row.metadata),
    createdAt: row.created_at,
  };
}

export function toAuditLogEntry(record: AuditLogRecord): AuditLogEntry {
  return {
    id: record.id,
    action: record.action,
    outcome: record.outcome,
    actorUserId: record.actorUserId,
    actorEmail: record.actorEmail,
    targetUserId: record.targetUserId,
    sessionId: record.sessionId,
    deviceId: record.deviceId,
    ipAddress: record.ipAddress,
    userAgent: record.userAgent,
    requestId: record.requestId,
    metadata: record.metadata,
    createdAt: toIsoRequired(record.createdAt),
  };
}

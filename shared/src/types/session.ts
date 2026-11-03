/** Session types. */

export const SESSION_STATUS = {
  ACTIVE: 'active',
  /** Refresh token was rotated; this row is kept briefly for reuse detection. */
  ROTATED: 'rotated',
  /** Explicit logout, admin revocation, or password change. */
  REVOKED: 'revoked',
  EXPIRED: 'expired',
} as const;

export type SessionStatus = (typeof SESSION_STATUS)[keyof typeof SESSION_STATUS];

/** Why a session was terminated - surfaced in the audit trail. */
export const SESSION_REVOKE_REASON = {
  USER_LOGOUT: 'user_logout',
  USER_LOGOUT_ALL: 'user_logout_all',
  ADMIN_REVOKE: 'admin_revoke',
  PASSWORD_CHANGED: 'password_changed',
  REFRESH_REUSE_DETECTED: 'refresh_reuse_detected',
  DEVICE_REVOKED: 'device_revoked',
  ROLE_CHANGED: 'role_changed',
  ACCOUNT_DISABLED: 'account_disabled',
  IDLE_TIMEOUT: 'idle_timeout',
  /** Evicted as least-recently-used when the per-user session cap was hit. */
  SESSION_LIMIT: 'session_limit',
  /** Hard deadline reached, regardless of activity. */
  ABSOLUTE_TIMEOUT: 'absolute_timeout',
  /** Ended by the break-glass switch. */
  EMERGENCY_LOCK: 'emergency_lock',
} as const;

export type SessionRevokeReason =
  (typeof SESSION_REVOKE_REASON)[keyof typeof SESSION_REVOKE_REASON];

/** Session record as returned to clients ("where am I logged in?"). */
export interface SessionInfo {
  id: string;
  deviceId: string | null;
  deviceName: string | null;
  status: SessionStatus;
  ipAddress: string | null;
  userAgent: string | null;
  /** True when this is the session making the current request. */
  isCurrent: boolean;
  createdAt: string;
  lastActivityAt: string;
  expiresAt: string;
}

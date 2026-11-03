/**
 * Administrative dashboard and security reporting.
 *
 * Everything here is an aggregate the server can compute from metadata it
 * already holds - account states, session and device rows, audit entries. None
 * of it touches vault contents, because none of it can.
 */

import type { RoleName } from '../constants/roles';
import type { UserStatus } from './user';

/** A point in a time series. `date` is `YYYY-MM-DD` in UTC. */
export interface TimeSeriesPoint {
  date: string;
  value: number;
}

/** A labelled slice for a bar or donut chart. */
export interface CategoryCount {
  label: string;
  value: number;
}

/** Headline numbers for the admin dashboard. */
export interface AdminDashboardStats {
  users: {
    total: number;
    active: number;
    pending: number;
    locked: number;
    suspended: number;
    /** Signed in within the last 30 days. */
    activeLast30Days: number;
    /** Created within the last 30 days. */
    newLast30Days: number;
    byRole: Record<RoleName, number>;
  };
  vaults: {
    /** Password groups. */
    groups: number;
    /** Passwords, in groups or standing alone. */
    totalItems: number;
    itemsByType: CategoryCount[];
  };
  access: {
    activeSessions: number;
    trustedDevices: number;
    knownDevices: number;
  };
  activity: {
    /** Successful sign-ins per day, last 30 days. */
    logins: TimeSeriesPoint[];
    /** Failed sign-ins per day, last 30 days. */
    failedLogins: TimeSeriesPoint[];
    /** Item writes per day, last 30 days. */
    vaultWrites: TimeSeriesPoint[];
  };
  generatedAt: string;
}

/** Severity of a security finding on the security dashboard. */
export const SECURITY_ALERT_LEVEL = {
  CRITICAL: 'critical',
  WARNING: 'warning',
  INFO: 'info',
} as const;

export type SecurityAlertLevel =
  (typeof SECURITY_ALERT_LEVEL)[keyof typeof SECURITY_ALERT_LEVEL];

/**
 * One thing an administrator should look at.
 *
 * Deliberately a small, fixed set of detections rather than a rules engine.
 * Each one is something with a clear response; an alert nobody knows how to act
 * on is noise that trains people to ignore the whole panel.
 */
export interface SecurityAlert {
  id: string;
  level: SecurityAlertLevel;
  title: string;
  detail: string;
  /** How many entities are affected. */
  count: number;
  /** Console route that lets the admin act on it. */
  actionHref?: string;
  actionLabel?: string;
}

export interface SecurityDashboard {
  alerts: SecurityAlert[];
  /** Sign-in outcomes per day, last 30 days. */
  loginOutcomes: { date: string; success: number; failure: number }[];
  /** Accounts with the most failed sign-ins in the window. */
  topFailedAccounts: { email: string; attempts: number; lastAttemptAt: string }[];
  /** Source addresses with the most failed sign-ins in the window. */
  topFailedAddresses: { ipAddress: string; attempts: number; distinctAccounts: number }[];
  /** Currently locked accounts. */
  lockedAccounts: {
    userId: string;
    email: string;
    fullName: string;
    status: UserStatus;
    lockedUntil: string | null;
  }[];
  /** Refresh-token replays detected in the window: always worth investigating. */
  tokenReuseEvents: number;
  /** Device fingerprint changes in the window. */
  fingerprintMismatches: number;
  /** Sessions older than the configured maximum age that are still active. */
  staleSessions: number;
  /** Devices trusted but unused for 90 days or more. */
  dormantTrustedDevices: number;
  windowDays: number;
  generatedAt: string;
}

/** Admin-facing session row, with its owner resolved. */
export interface AdminSessionRow {
  id: string;
  userId: string;
  email: string;
  fullName: string;
  role: RoleName;
  deviceId: string | null;
  deviceName: string | null;
  platform: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  status: string;
  createdAt: string;
  lastActivityAt: string;
  expiresAt: string;
}

/** Admin-facing device row, with its owner resolved. */
export interface AdminDeviceRow {
  id: string;
  userId: string;
  email: string;
  fullName: string;
  deviceId: string;
  name: string;
  platform: string;
  status: string;
  trusted: boolean;
  trustExpiresAt: string | null;
  lastIpAddress: string | null;
  lastUsedAt: string | null;
  activeSessionCount: number;
  createdAt: string;
}

/** A role, with the count of accounts holding it and its effective permissions. */
export interface RoleSummary {
  id: string;
  name: RoleName;
  label: string;
  description: string | null;
  level: number;
  isSystem: boolean;
  userCount: number;
  permissions: string[];
}

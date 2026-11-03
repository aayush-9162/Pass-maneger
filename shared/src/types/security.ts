/**
 * Security surface contracts: settings, IP rules, notifications, the security
 * score, and step-up verification.
 */

import type { SecuritySettings, SettingCategory } from '../constants/security';

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/** One setting as the admin panel sees it: value plus who last touched it. */
export interface SecuritySettingEntry {
  key: keyof SecuritySettings;
  value: SecuritySettings[keyof SecuritySettings];
  /** True when no row exists and the shipped default is in force. */
  isDefault: boolean;
  updatedAt: string | null;
  updatedByName: string | null;
}

export interface SecuritySettingsResponse {
  settings: SecuritySettings;
  entries: readonly SecuritySettingEntry[];
  /**
   * Settings the environment pins, which the panel must show as read-only.
   *
   * An operator who sets `SECURITY_SETTINGS_LOCK` keeps a floor that a
   * compromised admin account cannot lower.
   */
  lockedKeys: readonly (keyof SecuritySettings)[];
  /** False on a plaintext deployment, so TLS-only settings can be flagged. */
  tlsActive: boolean;
}

export interface UpdateSecuritySettingsRequest {
  /** Only the keys being changed. Absent keys are left alone. */
  settings: Partial<SecuritySettings>;
  /** Why. Recorded in the audit trail; required for dangerous keys. */
  reason?: string;
}

// ---------------------------------------------------------------------------
// IP allow list
// ---------------------------------------------------------------------------

export const IP_RULE_SCOPE = {
  /** Applies to every account. */
  GLOBAL: 'global',
  /** Applies to one user only. */
  USER: 'user',
  /** Applies to everyone holding a role. */
  ROLE: 'role',
} as const;

export type IpRuleScope = (typeof IP_RULE_SCOPE)[keyof typeof IP_RULE_SCOPE];

export interface IpRule {
  id: string;
  /** IPv4/IPv6 address or CIDR block, e.g. `192.168.1.0/24`. */
  cidr: string;
  label: string;
  scope: IpRuleScope;
  /** Set when scope is `user`. */
  userId: string | null;
  userName: string | null;
  /** Set when scope is `role`. */
  roleName: string | null;
  enabled: boolean;
  createdAt: string;
  createdByName: string | null;
  /** Last time a request matched this rule; helps spot dead entries. */
  lastMatchedAt: string | null;
  matchCount: number;
}

export interface CreateIpRuleRequest {
  cidr: string;
  label: string;
  scope: IpRuleScope;
  userId?: string | null;
  roleName?: string | null;
}

/** Result of checking one address against the list, for the admin tester. */
export interface IpCheckResult {
  ip: string;
  allowed: boolean;
  /** The rule that matched, if any. */
  matchedRuleId: string | null;
  matchedCidr: string | null;
  /** What the current mode means for this address right now. */
  effect: 'allowed' | 'would-block' | 'blocked';
  reason: string;
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

export const NOTIFICATION_TYPE = {
  NEW_DEVICE: 'new_device',
  NEW_LOCATION: 'new_location',
  FAILED_LOGINS: 'failed_logins',
  VAULT_SHARED: 'vault_shared',
  ADMIN_ACTION: 'admin_action',
  ACCOUNT_LOCKED: 'account_locked',
  EMERGENCY_LOCK: 'emergency_lock',
  ACCESS_REQUEST: 'access_request',
  /**
   * Somebody tried to unmask a password the policy hides from them.
   *
   * Raised to administrators rather than to the person who did it - they know
   * what they did, and telling them only reveals that it was detected.
   */
  PASSWORD_TAMPER: 'password_tamper',
  SECURITY_ALERT: 'security_alert',
} as const;

export type NotificationType = (typeof NOTIFICATION_TYPE)[keyof typeof NOTIFICATION_TYPE];

export const NOTIFICATION_SEVERITY = {
  INFO: 'info',
  WARNING: 'warning',
  CRITICAL: 'critical',
} as const;

export type NotificationSeverity =
  (typeof NOTIFICATION_SEVERITY)[keyof typeof NOTIFICATION_SEVERITY];

export interface SecurityNotification {
  id: string;
  type: NotificationType;
  severity: NotificationSeverity;
  title: string;
  body: string;
  /** Non-sensitive context: device name, city, count. Never a secret. */
  metadata: Record<string, string | number | boolean> | null;
  readAt: string | null;
  createdAt: string;
  /** Deep link into the app, e.g. `/admin/devices`. */
  actionUrl: string | null;
  actionLabel: string | null;
}

export interface NotificationListResponse {
  items: readonly SecurityNotification[];
  unreadCount: number;
  total: number;
}

// ---------------------------------------------------------------------------
// Step-up verification
// ---------------------------------------------------------------------------

/** Actions that can demand a fresh Google re-confirmation. */
export const STEP_UP_ACTION = {
  REVEAL: 'reveal',
  EXPORT: 'export',
  ADMIN_ACTION: 'admin_action',
  SETTINGS_CHANGE: 'settings_change',
} as const;

export type StepUpAction = (typeof STEP_UP_ACTION)[keyof typeof STEP_UP_ACTION];

export interface StepUpChallenge {
  /** Opaque id tying the answer back to this challenge. */
  challengeId: string;
  action: StepUpAction;
  /**
   * Passed to Google as the ID token `nonce`, so the token that comes back is
   * good for this challenge only. Not a secret.
   */
  nonce: string;
  expiresAt: string;
}

export interface StepUpVerifyRequest {
  challengeId: string;
  /**
   * A fresh Google ID token, requested with the challenge nonce as its `nonce`.
   *
   * The nonce binds this sign-in to this one challenge, so a token captured
   * from an earlier confirmation - or from the original sign-in - cannot be
   * replayed to satisfy a new one.
   */
  credential: string;
}

export interface StepUpStatus {
  /** True while a recent verification still covers this action. */
  verified: boolean;
  expiresAt: string | null;
  /** Which actions currently require a check, from live policy. */
  requiredFor: readonly StepUpAction[];
}

// ---------------------------------------------------------------------------
// Security score
// ---------------------------------------------------------------------------

export const SCORE_AREA = {
  AUTHENTICATION: 'authentication',
  PASSWORDS: 'passwords',
  SESSIONS: 'sessions',
  ACCESS_CONTROL: 'accessControl',
  MONITORING: 'monitoring',
  NETWORK: 'network',
} as const;

export type ScoreArea = (typeof SCORE_AREA)[keyof typeof SCORE_AREA];

export interface ScoreFinding {
  id: string;
  area: ScoreArea;
  /** Points lost. Zero for a passing check, which is still worth showing. */
  impact: number;
  severity: 'low' | 'medium' | 'high';
  title: string;
  detail: string;
  /** Concrete next step, not a platitude. */
  remediation: string;
  /** Where to go and fix it. */
  actionUrl: string | null;
  /** True when this check passed. */
  passed: boolean;
}

export interface AreaScore {
  area: ScoreArea;
  label: string;
  score: number;
  max: number;
}

export interface SecurityScore {
  /** 0-100. */
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  areas: readonly AreaScore[];
  findings: readonly ScoreFinding[];
  computedAt: string;
  /** Score at the previous computation, to show a trend. */
  previousScore: number | null;
}

export const SCORE_AREA_LABEL: Record<ScoreArea, string> = {
  [SCORE_AREA.AUTHENTICATION]: 'Authentication',
  [SCORE_AREA.PASSWORDS]: 'Passwords',
  [SCORE_AREA.SESSIONS]: 'Sessions',
  [SCORE_AREA.ACCESS_CONTROL]: 'Access control',
  [SCORE_AREA.MONITORING]: 'Monitoring',
  [SCORE_AREA.NETWORK]: 'Network',
};

/** Letter grade for a score. Bands are conventional, not arbitrary. */
export function gradeFor(score: number): SecurityScore['grade'] {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// ---------------------------------------------------------------------------
// Emergency lock
// ---------------------------------------------------------------------------

export interface EmergencyLockState {
  active: boolean;
  message: string;
  activatedAt: string | null;
  activatedByName: string | null;
  reason: string | null;
  /** Sessions terminated when it was switched on. */
  sessionsTerminated: number;
}

export interface EmergencyLockRequest {
  active: boolean;
  reason: string;
  message?: string;
  /** Sign every session out immediately, including administrators'. */
  terminateSessions?: boolean;
}

// ---------------------------------------------------------------------------
// Category grouping helper
// ---------------------------------------------------------------------------

/** Settings keys grouped by category, for rendering the settings page. */
export type SettingsByCategory = Record<SettingCategory, readonly (keyof SecuritySettings)[]>;

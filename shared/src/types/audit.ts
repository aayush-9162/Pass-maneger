/** Audit trail types. Every security relevant action lands here. */

export const AUDIT_ACTIONS = {
  LOGIN_SUCCESS: 'auth.login.success',
  LOGIN_FAILED: 'auth.login.failed',
  LOGIN_BLOCKED_LOCKED: 'auth.login.blocked_locked',
  LOGOUT: 'auth.logout',
  TOKEN_REFRESHED: 'auth.token.refreshed',
  TOKEN_REUSE_DETECTED: 'auth.token.reuse_detected',

  USER_CREATED: 'user.created',
  USER_UPDATED: 'user.updated',
  USER_DISABLED: 'user.disabled',
  USER_ROLE_CHANGED: 'user.role.changed',
  /** Full account deletion, as opposed to a suspension. */
  USER_DELETED: 'user.deleted',
  /** Administrative lock, distinct from the automatic failed-login lockout. */
  USER_LOCKED: 'user.locked',
  USER_UNLOCKED: 'user.unlocked',
  /** Created automatically by a first Google sign-in from the allowed domain. */
  USER_AUTO_PROVISIONED: 'user.auto_provisioned',

  DEVICE_REGISTERED: 'device.registered',
  DEVICE_TRUSTED: 'device.trusted',
  DEVICE_TRUST_REVOKED: 'device.trust.revoked',
  DEVICE_FINGERPRINT_MISMATCH: 'device.fingerprint.mismatch',

  SESSION_REVOKED: 'session.revoked',
  SESSION_REVOKED_ALL: 'session.revoked_all',

  /**
   * Password groups and individual-password wrappers.
   *
   * Membership changes are audited in full: who was given access to a shared
   * credential, and when, is the first question asked after an incident.
   */
  SHARED_VAULT_CREATED: 'shared_vault.created',
  SHARED_VAULT_UPDATED: 'shared_vault.updated',
  SHARED_VAULT_DELETED: 'shared_vault.deleted',
  SHARED_VAULT_GRANT_ADDED: 'shared_vault.grant.added',
  SHARED_VAULT_GRANT_UPDATED: 'shared_vault.grant.updated',
  SHARED_VAULT_GRANT_REVOKED: 'shared_vault.grant.revoked',

  PASSWORD_HEALTH_REPORTED: 'password_health.reported',

  // --- Item access ---------------------------------------------------------
  /**
   * Item-level access.
   *
   * "Who read the production root password, and when" is the first question
   * asked after an incident. Viewed, copied and filled are recorded by the
   * server at the moment it releases the password, with the purpose the
   * client gave - so a modified client cannot stay silent, only mislabel.
   */
  ITEM_VIEWED: 'item.viewed',
  ITEM_COPIED: 'item.copied',
  ITEM_FILLED: 'item.filled',
  ITEM_CREATED: 'item.created',
  ITEM_EDITED: 'item.edited',
  ITEM_DELETED: 'item.deleted',
  ITEM_RESTORED: 'item.restored',
  ITEM_SHARED: 'item.shared',
  /** A client reported that a bulk export of secrets was attempted and refused. */
  ITEM_EXPORT_BLOCKED: 'item.export.blocked',
  /**
   * A non-administrator tried to reveal or copy a password while
   * `restrictPasswordAccessToAdmins` was on, and the client refused.
   *
   * Worth recording even though the console gives them no button to press: it is
   * what a modified client, or a user working around the policy, would trip.
   */
  ITEM_REVEAL_BLOCKED: 'item.reveal.blocked',

  // --- Approval workflow ---------------------------------------------------
  ACCESS_REQUESTED: 'access_request.created',
  ACCESS_APPROVED: 'access_request.approved',
  ACCESS_DENIED: 'access_request.denied',
  ACCESS_CANCELLED: 'access_request.cancelled',

  // --- Compliance ----------------------------------------------------------
  /** An administrator exported the audit trail. Exporting is itself auditable. */
  AUDIT_EXPORTED: 'audit.exported',

  // --- Security policy (Phase 6) -------------------------------------------
  /** One or more runtime settings were changed. Metadata carries the diff. */
  SETTINGS_CHANGED: 'security.settings.changed',
  SETTINGS_RESET: 'security.settings.reset',
  /** The break-glass switch was thrown, or lifted. */
  EMERGENCY_LOCK_ENABLED: 'security.emergency_lock.enabled',
  EMERGENCY_LOCK_DISABLED: 'security.emergency_lock.disabled',
  /** Access refused because the caller's address is not on the allow list. */
  IP_BLOCKED: 'security.ip.blocked',
  /** Logged in `audit` mode: what enforcement *would* have refused. */
  IP_WOULD_BLOCK: 'security.ip.would_block',
  IP_RULE_CREATED: 'security.ip_rule.created',
  IP_RULE_DELETED: 'security.ip_rule.deleted',
  IP_RULE_UPDATED: 'security.ip_rule.updated',
  /** A request arrived without a valid CSRF token. */
  CSRF_REJECTED: 'security.csrf.rejected',
  /** Google re-confirmation before a sensitive action. */
  STEP_UP_SUCCEEDED: 'security.step_up.succeeded',
  STEP_UP_FAILED: 'security.step_up.failed',
  /** A device was refused because it awaits administrator approval. */
  DEVICE_APPROVAL_REQUIRED: 'security.device.approval_required',
  DEVICE_APPROVED: 'security.device.approved',
  /** A security notification was raised for a user. */
  NOTIFICATION_RAISED: 'security.notification.raised',
} as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[keyof typeof AUDIT_ACTIONS];

export const AUDIT_ACTION_LIST: readonly AuditAction[] = Object.values(AUDIT_ACTIONS);

/**
 * Grouping used by the console's action filter.
 *
 * Purely presentational - the stored value is always the full action string.
 */
export const AUDIT_ACTION_CATEGORY: Readonly<Record<string, string>> = {
  auth: 'Authentication',
  user: 'User administration',
  device: 'Devices',
  session: 'Sessions',
  vault: 'Vaults',
  group: 'Groups',
  shared_vault: 'Shared vaults',
  item: 'Item access',
  access_request: 'Approvals',
  password_health: 'Password health',
  audit: 'Compliance',
  security: 'Security policy',
};

/** The category an action belongs to, derived from its prefix. */
export function auditCategoryOf(action: string): string {
  const prefix = action.split('.')[0] ?? '';
  return AUDIT_ACTION_CATEGORY[prefix] ?? 'Other';
}

export const AUDIT_OUTCOME = {
  SUCCESS: 'success',
  FAILURE: 'failure',
} as const;

export type AuditOutcome = (typeof AUDIT_OUTCOME)[keyof typeof AUDIT_OUTCOME];

export interface AuditLogEntry {
  id: string;
  action: AuditAction;
  outcome: AuditOutcome;
  /** Actor - null for pre-authentication events such as a failed login. */
  actorUserId: string | null;
  actorEmail: string | null;
  /** Subject of the action, when different from the actor (admin operations). */
  targetUserId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  deviceId: string | null;
  sessionId: string | null;
  requestId: string | null;
  /** Non-sensitive structured context. Never contains secrets or tokens. */
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

/** An audit row with the actor and target names resolved, for the console. */
export interface AuditLogView extends AuditLogEntry {
  targetEmail: string | null;
  targetName: string | null;
  actorName: string | null;
}

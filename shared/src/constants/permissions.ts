/**
 * Fine grained permissions and the role -> permission matrix.
 *
 * Routes should prefer permission checks (`requirePermission`) over raw role
 * checks: it keeps authorization declarative and makes it possible to change
 * what a role can do in exactly one place.
 */

import { ROLES, type RoleName } from './roles';

export const PERMISSIONS = {
  // --- User administration -------------------------------------------------
  USER_CREATE: 'user:create',
  USER_READ: 'user:read',
  USER_UPDATE: 'user:update',
  USER_DISABLE: 'user:disable',
  /** Apply or lift an administrative lock. */
  USER_LOCK: 'user:lock',

  // --- Role administration -------------------------------------------------
  ROLE_READ: 'role:read',
  ROLE_ASSIGN: 'role:assign',

  // --- Shared vaults -------------------------------------------------------
  /**
   * Administrative oversight of shared vaults: which exist and who has access.
   * Never by itself lets anyone *read the contents* - that needs a grant, and
   * granting oneself access is audited.
   */
  SHARED_VAULT_READ: 'shared_vault:read',
  SHARED_VAULT_MANAGE: 'shared_vault:manage',

  // --- Sessions ------------------------------------------------------------
  SESSION_READ_SELF: 'session:read:self',
  SESSION_REVOKE_SELF: 'session:revoke:self',
  SESSION_READ_ANY: 'session:read:any',
  SESSION_REVOKE_ANY: 'session:revoke:any',

  // --- Devices -------------------------------------------------------------
  DEVICE_READ_SELF: 'device:read:self',
  DEVICE_MANAGE_SELF: 'device:manage:self',
  DEVICE_READ_ANY: 'device:read:any',
  DEVICE_REVOKE_ANY: 'device:revoke:any',

  // --- Vault ---------------------------------------------------------------
  // Every role holds these: a personal vault is always the caller's own, and no
  // role can read another user's vault. There is no `vault:read:any` and there
  // never can be one - the server has no key, so an administrator could not
  // decrypt another user's items even if an endpoint existed.
  VAULT_READ: 'vault:read',
  VAULT_WRITE: 'vault:write',
  VAULT_MANAGE: 'vault:manage',

  // --- Approvals -----------------------------------------------------------
  /** Decide access requests on any vault, not only ones you administer. */
  APPROVAL_DECIDE_ANY: 'approval:decide:any',

  // --- Reporting -----------------------------------------------------------
  AUDIT_READ: 'audit:read',
  /**
   * See personal-vault access events in the trail.
   *
   * Separate from `audit:read` on purpose. Item-level auditing is required for
   * organisational credentials, but the same events for somebody's *own* vault
   * are a record of their private activity. Only this permission adds the
   * personal trail, and only administrators hold it.
   */
  AUDIT_READ_PERSONAL: 'audit:read:personal',
  /**
   * Export the audit trail.
   *
   * Admin-only, and the export is itself an audited event. Note there is no
   * counterpart for exporting vault *contents* - see `EXPORT_POLICY`.
   */
  AUDIT_EXPORT: 'audit:export',
  /** The administrative dashboard and its aggregate statistics. */
  ANALYTICS_READ: 'analytics:read',
  /** Org-wide password health. Individual reports are always self-readable. */
  PASSWORD_HEALTH_READ_ANY: 'password_health:read:any',

  /** View the runtime security policy. */
  SETTINGS_READ: 'settings:read',
  /**
   * Change the runtime security policy.
   *
   * Separated from `SETTINGS_READ` so read access to the policy can be granted
   * without the ability to weaken it.
   */
  SETTINGS_WRITE: 'settings:write',
  /** Manage the IP allow list. */
  IP_RULE_MANAGE: 'ip_rule:manage',
  /**
   * Switch the emergency lock on or off.
   *
   * Deliberately its own permission rather than folding into `SETTINGS_WRITE`:
   * it is the one control that stops the entire company working, and it should
   * be possible to grant policy editing without granting that.
   */
  EMERGENCY_LOCK: 'emergency:lock',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

/** Permissions every authenticated user holds, regardless of role. */
const BASE_PERMISSIONS: readonly Permission[] = [
  PERMISSIONS.SESSION_READ_SELF,
  PERMISSIONS.SESSION_REVOKE_SELF,
  PERMISSIONS.DEVICE_READ_SELF,
  PERMISSIONS.DEVICE_MANAGE_SELF,
  PERMISSIONS.VAULT_READ,
  PERMISSIONS.VAULT_WRITE,
  PERMISSIONS.VAULT_MANAGE,
  // Shared vaults the user is a member of are readable through membership, not
  // through this permission: it only admits them to the "shared with me" list.
  PERMISSIONS.SHARED_VAULT_READ,
];

/**
 * Role -> permission matrix.
 *
 * - Member: self service, plus the shared vaults they have been granted. They
 *   reach the API through the browser extension; the console is administrators
 *   only.
 * - Admin : full control, including provisioning and shared-vault governance.
 *
 * There is no middle tier. `manager` was removed because every capability that
 * distinguished it had already been taken away - console access and password
 * reveal are both administrator-only now - leaving a role that named nothing.
 */
export const ROLE_PERMISSIONS: Readonly<Record<RoleName, readonly Permission[]>> = {
  [ROLES.EMPLOYEE]: [...BASE_PERMISSIONS],

  [ROLES.ADMIN]: [
    ...BASE_PERMISSIONS,
    PERMISSIONS.USER_CREATE,
    PERMISSIONS.USER_READ,
    PERMISSIONS.USER_UPDATE,
    PERMISSIONS.USER_DISABLE,
    PERMISSIONS.USER_LOCK,
    PERMISSIONS.ROLE_READ,
    PERMISSIONS.ROLE_ASSIGN,
    PERMISSIONS.SHARED_VAULT_MANAGE,
    PERMISSIONS.SESSION_READ_ANY,
    PERMISSIONS.SESSION_REVOKE_ANY,
    PERMISSIONS.DEVICE_READ_ANY,
    PERMISSIONS.DEVICE_REVOKE_ANY,
    PERMISSIONS.APPROVAL_DECIDE_ANY,
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.AUDIT_READ_PERSONAL,
    PERMISSIONS.AUDIT_EXPORT,
    PERMISSIONS.ANALYTICS_READ,
    PERMISSIONS.PASSWORD_HEALTH_READ_ANY,
    PERMISSIONS.SETTINGS_READ,
    PERMISSIONS.SETTINGS_WRITE,
    PERMISSIONS.IP_RULE_MANAGE,
    PERMISSIONS.EMERGENCY_LOCK,
  ],
};

/**
 * Export policy.
 *
 * Stated as a constant rather than left implicit, because "can you get the
 * passwords out" is the question an auditor asks first and the answer must be
 * findable in one place.
 *
 * **The audit trail is exportable by administrators. Vault contents are not
 * exportable by anyone, including administrators.**
 *
 * There is no endpoint that returns decrypted secrets in bulk, and there cannot
 * usefully be one: the server holds no key, so any "export" it produced would be
 * ciphertext. A client *could* in principle assemble a plaintext export from
 * what it has already decrypted, so the console deliberately does not offer one,
 * and a client that reports attempting it raises `item.export.blocked`.
 *
 * This is a policy control at the client, and honest about it: a member who can
 * read a password can write it down. What the policy prevents is the one-click
 * bulk extraction that turns "read a credential" into "walk out with the vault".
 */
export const EXPORT_POLICY = {
  /** Audit log export, admin only, itself audited. */
  auditLog: { allowed: true, permission: PERMISSIONS.AUDIT_EXPORT },
  /** Vault contents. Not offered to any role. */
  vaultSecrets: { allowed: false, permission: null },
} as const;

/**
 * Password access policy.
 *
 * When `restrictPasswordAccessToAdmins` is on, only administrators may reveal or
 * copy a stored password. Everyone else still *uses* their credentials - the
 * browser extension fills them into the page - but never sees the characters.
 *
 * ## What this is, precisely
 *
 * A client-side control, in the same family as {@link EXPORT_POLICY} and stated
 * as plainly. The server cannot enforce it and no amount of code here will
 * change that: a password is encrypted under a key derived from the user's own
 * password, so their browser is necessarily holding the plaintext at the moment
 * it fills a form. Anyone willing to open developer tools can read it.
 *
 * What it does buy, which is not nothing:
 *
 * - Passwords stop appearing on screens, in screenshots and in screen shares.
 * - The clipboard - readable by every application on the machine, and synced to
 *   other devices on some platforms - never receives them.
 * - Casual sharing ("just send me the login") becomes a deliberate act rather
 *   than two clicks, and one that leaves `item.reveal.blocked` in the trail.
 * - Filling binds a credential to the site that owns it, so a phishing page gets
 *   nothing, whereas a human reading a password off the screen can type it
 *   anywhere.
 *
 * What it does not buy: protection from a determined insider. Anyone promising
 * otherwise is selling something.
 */
export const PASSWORD_ACCESS_POLICY = {
  /** The role that keeps reveal and copy when the restriction is on. */
  privilegedRole: ROLES.ADMIN,
  /** Filling a credential never requires this permission - that is the point. */
  fillingAlwaysAllowed: true,
} as const;

/**
 * May this role reveal or copy a stored password?
 *
 * @param restrictToAdmins The live `restrictPasswordAccessToAdmins` setting.
 */
export function canRevealStoredPassword(role: RoleName, restrictToAdmins: boolean): boolean {
  return !restrictToAdmins || role === PASSWORD_ACCESS_POLICY.privilegedRole;
}

/** Resolve the effective permission set for a role. */
export function permissionsForRole(role: RoleName): readonly Permission[] {
  return ROLE_PERMISSIONS[role] ?? [];
}

/** True when `role` holds `permission`. */
export function roleHasPermission(role: RoleName, permission: Permission): boolean {
  return permissionsForRole(role).includes(permission);
}

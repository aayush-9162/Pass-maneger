/** User domain types visible to clients. */

import type { Permission } from '../constants/permissions';
import type { RoleName } from '../constants/roles';

/** Account lifecycle state (mirrors the `users.status` ENUM in MySQL). */
export const USER_STATUS = {
  /** Has signed in, and may. */
  ACTIVE: 'active',
  /** Created (by an admin or by Google auto-provisioning) but never signed in. */
  PENDING: 'pending',
  /**
   * Blocked from signing in by an administrator, until `lockedUntil` (which
   * is far in the future for an open-ended lock).
   */
  LOCKED: 'locked',
  /** Administratively disabled. Cannot authenticate. */
  SUSPENDED: 'suspended',
} as const;

export type UserStatus = (typeof USER_STATUS)[keyof typeof USER_STATUS];

export const USER_STATUS_LIST: readonly UserStatus[] = [
  USER_STATUS.ACTIVE,
  USER_STATUS.PENDING,
  USER_STATUS.LOCKED,
  USER_STATUS.SUSPENDED,
];

export const USER_STATUS_LABEL: Readonly<Record<UserStatus, string>> = {
  [USER_STATUS.ACTIVE]: 'Active',
  [USER_STATUS.PENDING]: 'Pending',
  [USER_STATUS.LOCKED]: 'Locked',
  [USER_STATUS.SUSPENDED]: 'Suspended',
};

/**
 * The only user representation ever serialized to a client.
 *
 * Deliberately excludes the Google subject and every operational column an
 * ordinary member has no business seeing.
 */
export interface PublicUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  fullName: string;
  role: RoleName;
  /** Effective permissions for the user's role, resolved server-side. */
  permissions: Permission[];
  status: UserStatus;
  jobTitle: string | null;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Admin-facing list row (adds operational counters). */
export interface AdminUserListItem extends PublicUser {
  activeSessionCount: number;
  trustedDeviceCount: number;
  lockedUntil: string | null;
  /** Why an administrator locked the account. */
  lockReason: string | null;
  /** Password groups and individual passwords this user has a grant on. */
  sharedVaultCount: number;
}

/**
 * One row of "what can this person use" on the user detail page.
 *
 * `kind` distinguishes a named password group from the wrapper around one
 * individual password.
 */
export interface UserVaultAccess {
  vaultId: string;
  name: string;
  kind: 'group' | 'item';
  accessRole: string;
  hiddenPassword: boolean;
}

/** Everything the admin console shows on one user's detail page. */
export interface AdminUserDetail extends AdminUserListItem {
  createdByUserId: string | null;
  createdByName: string | null;
  lastLoginIp: string | null;
  /** Password groups and individual items this user is granted. */
  access: UserVaultAccess[];
}

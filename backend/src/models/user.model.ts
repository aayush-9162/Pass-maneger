/**
 * User model.
 *
 * {@link UserRecord} carries operational columns - the Google subject, lock
 * state, last sign-in address - that an ordinary member has no business seeing.
 * Convert with {@link toPublicUser} before anything leaves a controller.
 */

import {
  permissionsForRole,
  ROLES,
  isRoleName,
  type PublicUser,
  type RoleName,
  type UserStatus,
} from '@passm/shared';
import type { RowDataPacket } from 'mysql2';

import { toIso, toIsoRequired } from '../utils/date';

/** Raw `users` row, joined with `roles`. */
export interface UserRow extends RowDataPacket {
  id: string;
  email: string;
  google_subject: string | null;
  first_name: string;
  last_name: string;
  job_title: string | null;
  role_id: string;
  status: string;
  locked_until: Date | null;
  lock_reason: string | null;
  locked_by_user_id: string | null;
  last_login_at: Date | null;
  last_login_ip: string | null;
  created_by: string | null;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
  /** From the `roles` join. */
  role_name: string;
  role_level: number;
}

/** Domain record. Never serialize directly. */
export interface UserRecord {
  id: string;
  email: string;
  /** Google account id (`sub`), linked on the first Google sign-in. */
  googleSubject: string | null;
  firstName: string;
  lastName: string;
  jobTitle: string | null;
  roleId: string;
  role: RoleName;
  roleLevel: number;
  status: UserStatus;
  /** Administrative lock expiry; far in the future for an open-ended lock. */
  lockedUntil: Date | null;
  lockReason: string | null;
  lockedByUserId: string | null;
  lastLoginAt: Date | null;
  lastLoginIp: string | null;
  createdBy: string | null;
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

export function mapUserRow(row: UserRow): UserRecord {
  return {
    id: row.id,
    email: row.email,
    googleSubject: row.google_subject,
    firstName: row.first_name,
    lastName: row.last_name,
    jobTitle: row.job_title,
    roleId: row.role_id,
    // A row whose role somehow falls outside the known set is downgraded to the
    // least privileged role instead of failing open.
    role: isRoleName(row.role_name) ? row.role_name : ROLES.EMPLOYEE,
    roleLevel: row.role_level,
    status: row.status as UserStatus,
    lockedUntil: row.locked_until,
    lockReason: row.lock_reason,
    lockedByUserId: row.locked_by_user_id,
    lastLoginAt: row.last_login_at,
    lastLoginIp: row.last_login_ip,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deletedAt: row.deleted_at,
  };
}

/**
 * Project a {@link UserRecord} onto the client-safe {@link PublicUser}.
 *
 * The single boundary between internal state and the wire. Adding a sensitive
 * column to `users` cannot leak it unless someone edits this function.
 */
export function toPublicUser(user: UserRecord): PublicUser {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    fullName: `${user.firstName} ${user.lastName}`.trim(),
    role: user.role,
    permissions: [...permissionsForRole(user.role)],
    status: user.status,
    jobTitle: user.jobTitle,
    lastLoginAt: toIso(user.lastLoginAt),
    createdAt: toIsoRequired(user.createdAt),
    updatedAt: toIsoRequired(user.updatedAt),
  };
}

/**
 * Shared vault row mappers.
 *
 * Permissions are stored as a comma-separated string rather than a JSON column
 * or a join table: the set is tiny, closed and always read whole, so a string
 * keeps the grant a single row and the effective-permission query a single
 * scan. {@link parsePermissions} is the only place that string is interpreted,
 * and it discards anything not in the known set - so a value written by an older
 * or compromised build cannot widen access.
 */

import {
  DEFAULT_GROUP_ROLES,
  SHARED_VAULT_STATUS,
  VAULT_KIND,
  VAULT_PERMISSION_LIST,
  VAULT_ROLE,
  normalizeVaultPermissions,
  type DefaultGroupRole,
  type VaultKind,
  type VaultRestrictions,
  type VaultRole,
  type SharedVault,
  type SharedVaultGrant,
  type SharedVaultStatus,
  type VaultItemType,
  type VaultPermission,
  type GrantSubjectType,
} from '@passm/shared';
import type { RowDataPacket } from 'mysql2';

import { toIso, toIsoRequired } from '../utils/date';

const KNOWN_PERMISSIONS = new Set<string>(VAULT_PERMISSION_LIST);

/** Parse a stored permission string, dropping anything unrecognised. */
export function parsePermissions(value: string | null): VaultPermission[] {
  if (!value) return [];

  const parsed = value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry): entry is VaultPermission => KNOWN_PERMISSIONS.has(entry));

  return normalizeVaultPermissions(parsed);
}

/** Serialise a permission set for storage, normalised so equal sets compare equal. */
export function serializePermissions(permissions: readonly VaultPermission[]): string {
  return normalizeVaultPermissions(permissions).join(',');
}

/** Union several permission strings - how multiple grants reaching one user combine. */
export function mergePermissions(values: readonly (string | null)[]): VaultPermission[] {
  const merged = new Set<VaultPermission>();
  for (const value of values) {
    for (const permission of parsePermissions(value)) merged.add(permission);
  }
  return normalizeVaultPermissions([...merged]);
}

export interface SharedVaultRow extends RowDataPacket {
  id: string;
  name: string;
  description: string | null;
  color: string | null;
  kind: string;
  require_approval_to_join: number;
  require_approval_to_reveal: number;
  auto_grant_role: string | null;
  status: string;
  revision: number;
  created_by: string | null;
  created_at: Date;
  updated_at: Date;
  /** Joined / computed. */
  creator_first_name: string | null;
  creator_last_name: string | null;
  item_count: number;
  member_count: number;
}

function fullName(first: string | null, last: string | null): string | null {
  if (!first && !last) return null;
  return `${first ?? ''} ${last ?? ''}`.trim();
}

export function mapSharedVaultRow(row: SharedVaultRow): SharedVault {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    color: row.color,
    kind: (row.kind === VAULT_KIND.ITEM ? VAULT_KIND.ITEM : VAULT_KIND.GROUP) as VaultKind,
    requireApprovalToJoin: row.require_approval_to_join === 1,
    requireApprovalToReveal: row.require_approval_to_reveal === 1,
    autoGrantRole: (DEFAULT_GROUP_ROLES as readonly string[]).includes(row.auto_grant_role ?? '')
      ? (row.auto_grant_role as DefaultGroupRole)
      : null,
    createdByUserId: row.created_by,
    createdByName: fullName(row.creator_first_name, row.creator_last_name),
    itemCount: Number(row.item_count ?? 0),
    memberCount: Number(row.member_count ?? 0),
    status: (row.status === SHARED_VAULT_STATUS.ARCHIVED
      ? SHARED_VAULT_STATUS.ARCHIVED
      : SHARED_VAULT_STATUS.ACTIVE) as SharedVaultStatus,
    createdAt: toIsoRequired(row.created_at),
    updatedAt: toIsoRequired(row.updated_at),
  };
}

export interface GrantRow extends RowDataPacket {
  id: string;
  shared_vault_id: string;
  subject_type: string;
  subject_id: string;
  permissions: string;
  access_role: string;
  hidden_password: number;
  copy_only: number;
  no_edit: number;
  no_delete: number;
  granted_by: string | null;
  created_at: Date;
  updated_at: Date;
  /** The granted user's display name. */
  subject_name: string | null;
  subject_email: string | null;
  granted_by_first_name: string | null;
  granted_by_last_name: string | null;
}

/** Restriction flags as stored on a grant. */
export function mapRestrictions(row: {
  hidden_password: number;
  copy_only: number;
  no_edit: number;
  no_delete: number;
}): VaultRestrictions {
  return {
    hiddenPassword: row.hidden_password === 1,
    copyOnly: row.copy_only === 1,
    noEdit: row.no_edit === 1,
    noDelete: row.no_delete === 1,
  };
}

/**
 * Merge restrictions across every grant reaching one user.
 *
 * Restrictions are unioned, not intersected: they *subtract* from a role, so a
 * user reached by two grants keeps every restriction either one imposes. The
 * opposite rule would let anybody escape a hidden-password restriction by being
 * added to one unrestricted group, which is precisely the hole the restriction
 * exists to close.
 *
 * Note this is the reverse of how permissions combine - those union in the
 * *permissive* direction. Both rules are "the safest reading of what the
 * administrators intended", which is additive for capability and additive for
 * restriction.
 */
export function mergeRestrictions(
  values: readonly VaultRestrictions[],
): VaultRestrictions {
  return {
    hiddenPassword: values.some((r) => r.hiddenPassword),
    copyOnly: values.some((r) => r.copyOnly),
    noEdit: values.some((r) => r.noEdit),
    noDelete: values.some((r) => r.noDelete),
  };
}

export function mapGrantRow(row: GrantRow): SharedVaultGrant {
  return {
    id: row.id,
    sharedVaultId: row.shared_vault_id,
    subjectType: row.subject_type as GrantSubjectType,
    subjectId: row.subject_id,
    accessRole: (row.access_role ?? VAULT_ROLE.VIEWER) as VaultRole,
    restrictions: mapRestrictions(row),
    // A grant whose subject has been deleted still has a row; naming it plainly
    // is better than hiding it, because it is something an admin should clean up.
    subjectName: row.subject_name ?? '(deleted)',
    subjectEmail: row.subject_email,
    permissions: parsePermissions(row.permissions),
    grantedByUserId: row.granted_by,
    grantedByName: fullName(row.granted_by_first_name, row.granted_by_last_name),
    createdAt: toIsoRequired(row.created_at),
    updatedAt: toIsoRequired(row.updated_at),
  };
}

export interface SharedItemRow extends RowDataPacket {
  id: string;
  shared_vault_id: string;
  type: string;
  encrypted_data: string;
  encrypted_secret: string | null;
  favorite: number;
  revision: number;
  created_by: string | null;
  updated_by: string | null;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
  /** Joined. */
  updated_by_first_name?: string | null;
  updated_by_last_name?: string | null;
}

/**
 * An item as stored: everything a client sees, except that the contents are
 * still server envelopes. Only the shared-vault service opens them.
 */
export interface StoredSharedItem {
  id: string;
  sharedVaultId: string;
  type: VaultItemType;
  encryptedData: string;
  encryptedSecret: string | null;
  favorite: boolean;
  revision: number;
  updatedByUserId: string | null;
  updatedByName: string | null;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

export function mapSharedItemRow(row: SharedItemRow): StoredSharedItem {
  return {
    id: row.id,
    sharedVaultId: row.shared_vault_id,
    type: row.type as VaultItemType,
    encryptedData: row.encrypted_data,
    encryptedSecret: row.encrypted_secret,
    favorite: row.favorite === 1,
    revision: Number(row.revision),
    updatedByUserId: row.updated_by,
    updatedByName: fullName(row.updated_by_first_name ?? null, row.updated_by_last_name ?? null),
    createdAt: toIsoRequired(row.created_at),
    updatedAt: toIsoRequired(row.updated_at),
    deletedAt: toIso(row.deleted_at),
  };
}

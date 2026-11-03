/**
 * Shared vaults - password groups, and the wrappers individual passwords live in.
 *
 * ## Access is a grant, and nothing else
 *
 * A **grant** says a user may use a vault, with which role and restrictions.
 * The server checks it on every request and hands back plaintext to whoever
 * passes. There are no per-user keys to deliver: giving someone access is one
 * row, and they can use the passwords the moment it exists.
 *
 * ## Two halves per item
 *
 * Each item is stored as two server-side envelopes:
 *
 *  - `data` - name, username, URLs, notes. Returned with every listing.
 *  - `secret` - the password and TOTP seed. Released one item at a time by
 *    `GET .../items/:itemId/secret`, which checks the hidden-password
 *    restriction and the reveal-approval rule, and is audited.
 *
 * Keeping the secret off the listing means a page that shows fifty entries
 * moves zero passwords over the wire until someone asks for one.
 */

import type { GrantSubjectType, VaultPermission } from '../constants/sharing';
import type {
  DefaultGroupRole,
  VaultKind,
  VaultRestrictions,
  VaultRole,
} from '../constants/collaboration';
import type { VaultItemType } from './vault';

/**
 * A vault shared between people.
 *
 * `name` and `description` are visible to administrators who are not members,
 * so a group can be governed without being opened.
 */
export interface SharedVault {
  id: string;
  name: string;
  description: string | null;
  /** Colour token used by the console to make vaults distinguishable at a glance. */
  color: string | null;
  /** `group` = named collection; `item` = wrapper around one individual password. */
  kind: VaultKind;
  /** Joining requires an approved access request rather than a direct grant. */
  requireApprovalToJoin: boolean;
  /** Passwords are released only to members with an approved reveal request. */
  requireApprovalToReveal: boolean;
  /**
   * The role every new account receives on this group, or null when it is not
   * a default group. Applied when an account is created; existing accounts
   * are not touched.
   */
  autoGrantRole: DefaultGroupRole | null;
  createdByUserId: string | null;
  createdByName: string | null;
  itemCount: number;
  /** Users holding a grant. */
  memberCount: number;
  status: SharedVaultStatus;
  createdAt: string;
  updatedAt: string;
}

export const SHARED_VAULT_STATUS = {
  ACTIVE: 'active',
  ARCHIVED: 'archived',
} as const;

export type SharedVaultStatus = (typeof SHARED_VAULT_STATUS)[keyof typeof SHARED_VAULT_STATUS];

/** A shared vault as seen by a member, including their own access. */
export interface MemberSharedVault extends SharedVault {
  /** The caller's effective rights, unioned across every grant that reaches them. */
  permissions: VaultPermission[];
  /** Highest role across every grant reaching the caller. */
  accessRole: VaultRole;
  /** Restrictions, unioned across those grants - see `mergeRestrictions`. */
  restrictions: VaultRestrictions;
  /**
   * Whether the server will release passwords from this vault to the caller.
   *
   * False for a hidden-password member, and for a vault that requires an
   * approved reveal the caller does not have.
   */
  canReadSecrets: boolean;
}

/** A grant: who is entitled, and to what. */
export interface SharedVaultGrant {
  id: string;
  sharedVaultId: string;
  subjectType: GrantSubjectType;
  subjectId: string;
  /** Resolved display name of the user. */
  subjectName: string;
  subjectEmail: string | null;
  permissions: VaultPermission[];
  /** The named preset shown in the console. `permissions` is what is enforced. */
  accessRole: VaultRole;
  restrictions: VaultRestrictions;
  grantedByUserId: string | null;
  grantedByName: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Everything about an item except its secret. Returned with every listing. */
export interface SharedItemData {
  name: string;
  username?: string;
  /** Sites this login applies to; drives extension matching. */
  uris?: string[];
  notes?: string;
  tags?: string[];
}

/** The part of an item released only on request. */
export interface SharedItemSecret {
  password?: string;
  /** TOTP secret in `otpauth://` or bare base32 form. */
  totp?: string;
}

/** An item inside a shared vault, without its secret. */
export interface SharedVaultItem {
  id: string;
  sharedVaultId: string;
  type: VaultItemType;
  data: SharedItemData;
  /** True when a secret is stored - whether or not the caller may read it. */
  hasSecret: boolean;
  favorite: boolean;
  revision: number;
  /** Who last wrote this item. */
  updatedByUserId: string | null;
  updatedByName: string | null;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

/**
 * Why a secret is being fetched.
 *
 * Recorded in the audit trail with the release itself, so the trail says
 * "copied" or "filled" rather than only "released".
 */
export const SECRET_PURPOSE = {
  VIEW: 'view',
  COPY: 'copy',
  FILL: 'fill',
  EDIT: 'edit',
} as const;

export type SecretPurpose = (typeof SECRET_PURPOSE)[keyof typeof SECRET_PURPOSE];

export interface SharedItemSecretResponse {
  secret: SharedItemSecret;
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

export interface CreateSharedVaultRequest {
  name: string;
  description?: string;
  color?: string;
  /** Defaults to `group`. `item` creates the wrapper around one individual password. */
  kind?: VaultKind;
  requireApprovalToJoin?: boolean;
  requireApprovalToReveal?: boolean;
}

export interface UpdateSharedVaultRequest {
  name?: string;
  description?: string | null;
  color?: string | null;
  status?: SharedVaultStatus;
  /** Make this a default group (with this role), or `null` to stop. Needs `shared_vault:manage`. */
  autoGrantRole?: DefaultGroupRole | null;
}

export interface CreateGrantRequest {
  subjectType: GrantSubjectType;
  subjectId: string;
  /** Named role. The server derives the permission set from it. */
  role: VaultRole;
  restrictions?: Partial<VaultRestrictions>;
}

export interface UpdateGrantRequest {
  role: VaultRole;
  restrictions?: Partial<VaultRestrictions>;
}

export interface CreateSharedItemRequest {
  type: VaultItemType;
  data: SharedItemData;
  secret?: SharedItemSecret;
  favorite?: boolean;
}

export interface UpdateSharedItemRequest {
  data?: SharedItemData;
  /** Replaces the stored secret. Omit to keep it. */
  secret?: SharedItemSecret;
  favorite?: boolean;
  /** Expected current revision; a mismatch means someone else wrote first. */
  revision: number;
}

/**
 * Move an item to another group, or out to stand alone.
 *
 * `targetVaultId: null` means "Individual": the server creates a wrapper vault
 * owned by the caller. Moving an individual password away deletes its wrapper.
 */
export interface MoveSharedItemRequest {
  targetVaultId: string | null;
  revision: number;
}

/**
 * Collaboration: named access roles, restrictions, and what each really enforces.
 *
 * ## Roles versus restrictions
 *
 * A **role** is a preset bundle of the object permissions in `sharing.ts`. A
 * **restriction** subtracts from whatever role you hold. They are separate
 * because "editor, but cannot delete" is a normal thing to want and is not a
 * fifth role - modelling it as one produces a combinatorial mess the moment
 * somebody asks for "editor, but cannot delete *and* cannot see passwords".
 *
 * ## What is actually enforced, and where
 *
 * This is the part that matters, and the part most systems are vague about:
 *
 * | Control        | Enforced by                    | Can a determined member bypass it? |
 * | -------------- | ------------------------------ | ---------------------------------- |
 * | Role           | Server, on every request       | No                                 |
 * | No edit        | Server rejects the write       | No                                 |
 * | No delete      | Server rejects the delete      | No                                 |
 * | Hidden password| Server never releases it       | No                                 |
 * | Copy only      | Client UI + audit              | **Yes**                            |
 *
 * `copy_only` is the honest exception. Copying a password requires the plaintext
 * in the client, so the server has released it; the interface simply declines
 * to render the value and records every copy. It is a control against
 * shoulder-surfing and casual leakage, not against the member: "can use a secret
 * but can never obtain it" cannot be built, because the client has to receive
 * the value to use it.
 */

import { VAULT_ACCESS_PRESETS, type VaultPermission } from './sharing';

/** Named access roles, as the console presents them. */
export const VAULT_ROLE = {
  /** Full control, including deleting the vault and changing anyone's access. */
  OWNER: 'owner',
  /** Manages membership and content, cannot delete the vault. */
  ADMIN: 'admin',
  /** Creates and changes items. */
  EDITOR: 'editor',
  /** Reads only. */
  VIEWER: 'viewer',
} as const;

export type VaultRole = (typeof VAULT_ROLE)[keyof typeof VAULT_ROLE];

export const VAULT_ROLE_LIST: readonly VaultRole[] = [
  VAULT_ROLE.OWNER,
  VAULT_ROLE.ADMIN,
  VAULT_ROLE.EDITOR,
  VAULT_ROLE.VIEWER,
];

export const VAULT_ROLE_LABEL: Readonly<Record<VaultRole, string>> = {
  [VAULT_ROLE.OWNER]: 'Owner',
  [VAULT_ROLE.ADMIN]: 'Admin',
  [VAULT_ROLE.EDITOR]: 'Editor',
  [VAULT_ROLE.VIEWER]: 'Viewer',
};

/**
 * The role a default group hands every new account.
 *
 * Viewer only: new people are members, members use passwords through the
 * browser extension, and the extension changes nothing - so a higher role
 * would grant nothing they could use.
 */
export const DEFAULT_GROUP_ROLES = [VAULT_ROLE.VIEWER] as const;

export type DefaultGroupRole = (typeof DEFAULT_GROUP_ROLES)[number];

export const VAULT_ROLE_DESCRIPTION: Readonly<Record<VaultRole, string>> = {
  [VAULT_ROLE.OWNER]:
    'Everything, including deleting the vault and changing anyone’s access.',
  [VAULT_ROLE.ADMIN]: 'Manage members and content. Cannot delete the vault itself.',
  [VAULT_ROLE.EDITOR]: 'Add, change and remove items. Cannot change who has access.',
  [VAULT_ROLE.VIEWER]: 'Read items. Cannot change anything.',
};

/** Higher wins. Used for "at least this role" comparisons. */
export const VAULT_ROLE_RANK: Readonly<Record<VaultRole, number>> = {
  [VAULT_ROLE.OWNER]: 40,
  [VAULT_ROLE.ADMIN]: 30,
  [VAULT_ROLE.EDITOR]: 20,
  [VAULT_ROLE.VIEWER]: 10,
};

/**
 * Role to permission set.
 *
 * The permission set remains what the API enforces - the role is the label. That
 * indirection is what lets an operator express a custom combination without the
 * server needing a role for it.
 */
export const VAULT_ROLE_PERMISSIONS: Readonly<Record<VaultRole, readonly VaultPermission[]>> = {
  [VAULT_ROLE.OWNER]: VAULT_ACCESS_PRESETS.OWNER,
  [VAULT_ROLE.ADMIN]: VAULT_ACCESS_PRESETS.MANAGER,
  [VAULT_ROLE.EDITOR]: VAULT_ACCESS_PRESETS.EDITOR,
  [VAULT_ROLE.VIEWER]: VAULT_ACCESS_PRESETS.VIEWER,
};

/** Restrictions that subtract from a role. */
export interface VaultRestrictions {
  /**
   * Never release passwords to this member.
   *
   * Enforced by the server: the secret endpoint refuses them. They can still
   * see the item exists, its username and its URLs. They cannot view, copy or
   * autofill the password - that last one is the honest cost, and the console
   * states it.
   */
  hiddenPassword: boolean;
  /**
   * Hide the value in the interface and audit every copy.
   *
   * **Client-side only.** The member receives the password; a determined one
   * can read it out of the page. Useful against shoulder-surfing and accidental
   * disclosure, and it produces a trail. Not a barrier against the member.
   */
  copyOnly: boolean;
  /** Server rejects writes to items in this vault. */
  noEdit: boolean;
  /** Server rejects deletes of items in this vault. */
  noDelete: boolean;
}

export const NO_RESTRICTIONS: VaultRestrictions = {
  hiddenPassword: false,
  copyOnly: false,
  noEdit: false,
  noDelete: false,
};

export const RESTRICTION_LABEL: Readonly<Record<keyof VaultRestrictions, string>> = {
  hiddenPassword: 'Hidden password',
  copyOnly: 'Copy only',
  noEdit: 'No edit',
  noDelete: 'No delete',
};

export const RESTRICTION_DESCRIPTION: Readonly<Record<keyof VaultRestrictions, string>> = {
  hiddenPassword:
    'The server never sends them the password. Cannot view, copy OR autofill it. Enforced by the server, not by the interface. Leave this off if they need to sign in to the site: to let someone use a password without seeing it, use the "only administrators may see or copy passwords" policy instead.',
  copyOnly:
    'Can copy a password but not read it on screen. Every copy is audited. Has no effect while the organisation-wide policy already stops non-administrators copying — that policy is the stricter of the two.',
  noEdit: 'Cannot create or change items, whatever their role allows.',
  noDelete: 'Cannot delete items, whatever their role allows.',
};

/** True when this restriction is enforced by the server rather than the client. */
export const RESTRICTION_IS_ENFORCED: Readonly<Record<keyof VaultRestrictions, boolean>> = {
  hiddenPassword: true,
  copyOnly: false,
  noEdit: true,
  noDelete: true,
};

/**
 * Do these restrictions let the holder receive passwords at all?
 *
 * The single decision that determines whether somebody can read a password.
 * A vault that requires an approved reveal adds a second condition on top -
 * see the secret endpoint in the shared-vault service.
 */
export function entitledToSecrets(restrictions: VaultRestrictions): boolean {
  return !restrictions.hiddenPassword;
}

/**
 * What a `shared_vaults` row represents in the interface.
 *
 * Same table, two presentations. A `group` is a named collection of passwords -
 * the thing the Passwords page lists and users are given access to. An `item`
 * vault is the invisible wrapper around exactly one individual password, which
 * is how a single password is shareable through the same grant with no second
 * code path.
 */
export const VAULT_KIND = {
  GROUP: 'group',
  ITEM: 'item',
} as const;

export type VaultKind = (typeof VAULT_KIND)[keyof typeof VAULT_KIND];

// ---------------------------------------------------------------------------
// Approval workflow
// ---------------------------------------------------------------------------

export const REQUEST_TYPE = {
  /** Join a vault the requester has no grant on. */
  ACCESS: 'access',
  /** See the passwords of a vault whose passwords are hidden from them. */
  REVEAL: 'reveal',
  /** Move up to a more capable role on a vault they already belong to. */
  ELEVATE: 'elevate',
} as const;

export type RequestType = (typeof REQUEST_TYPE)[keyof typeof REQUEST_TYPE];

export const REQUEST_TYPE_LABEL: Readonly<Record<RequestType, string>> = {
  [REQUEST_TYPE.ACCESS]: 'Access request',
  [REQUEST_TYPE.REVEAL]: 'Password reveal',
  [REQUEST_TYPE.ELEVATE]: 'Elevated access',
};

export const REQUEST_STATUS = {
  PENDING: 'pending',
  APPROVED: 'approved',
  DENIED: 'denied',
  CANCELLED: 'cancelled',
  EXPIRED: 'expired',
} as const;

export type RequestStatus = (typeof REQUEST_STATUS)[keyof typeof REQUEST_STATUS];

/** How long a request stays actionable before it lapses. */
export const REQUEST_TTL_HOURS = 72;

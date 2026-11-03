/**
 * Shared-vault access rights.
 *
 * These are *object* permissions, granted per (vault, subject) pair, and are a
 * separate axis from the role permissions in `permissions.ts`. A role says what
 * you may do to the system; a grant says what you may do to one vault.
 *
 * An administrator holding `shared_vault:manage` can govern who has access to a
 * vault without holding a grant on it, and cannot read its contents until they
 * grant themselves one - which the audit trail records. Administration and
 * access stay different powers.
 */

/** The rights that can be granted on a shared vault. */
export const VAULT_PERMISSIONS = {
  /** See the vault and decrypt its items. Implied by every other right. */
  READ: 'read',
  /** Create and modify items. */
  EDIT: 'edit',
  /** Delete items. Separate from EDIT so a junior member cannot destroy history. */
  DELETE: 'delete',
  /** Hand the vault key to another user, and revoke it. */
  SHARE: 'share',
  /** Rename or delete the vault itself, and change anyone's grant. */
  ADMIN: 'admin',
} as const;

export type VaultPermission = (typeof VAULT_PERMISSIONS)[keyof typeof VAULT_PERMISSIONS];

export const VAULT_PERMISSION_LIST: readonly VaultPermission[] = [
  VAULT_PERMISSIONS.READ,
  VAULT_PERMISSIONS.EDIT,
  VAULT_PERMISSIONS.DELETE,
  VAULT_PERMISSIONS.SHARE,
  VAULT_PERMISSIONS.ADMIN,
];

export const VAULT_PERMISSION_LABEL: Readonly<Record<VaultPermission, string>> = {
  [VAULT_PERMISSIONS.READ]: 'Read',
  [VAULT_PERMISSIONS.EDIT]: 'Edit',
  [VAULT_PERMISSIONS.DELETE]: 'Delete',
  [VAULT_PERMISSIONS.SHARE]: 'Share',
  [VAULT_PERMISSIONS.ADMIN]: 'Admin',
};

export const VAULT_PERMISSION_DESCRIPTION: Readonly<Record<VaultPermission, string>> = {
  [VAULT_PERMISSIONS.READ]: 'View and decrypt every item in the vault.',
  [VAULT_PERMISSIONS.EDIT]: 'Add items and change existing ones.',
  [VAULT_PERMISSIONS.DELETE]: 'Move items to the trash and purge them.',
  [VAULT_PERMISSIONS.SHARE]: 'Give other people access, and take it away.',
  [VAULT_PERMISSIONS.ADMIN]: 'Rename or delete the vault and change anyone’s access.',
};

/**
 * Named bundles offered in the UI.
 *
 * Presets exist so the common case is one click, not five checkboxes; the
 * underlying model stays a plain permission set, so a custom combination is
 * always expressible.
 */
export const VAULT_ACCESS_PRESETS = {
  VIEWER: [VAULT_PERMISSIONS.READ],
  CONTRIBUTOR: [VAULT_PERMISSIONS.READ, VAULT_PERMISSIONS.EDIT],
  EDITOR: [VAULT_PERMISSIONS.READ, VAULT_PERMISSIONS.EDIT, VAULT_PERMISSIONS.DELETE],
  MANAGER: [
    VAULT_PERMISSIONS.READ,
    VAULT_PERMISSIONS.EDIT,
    VAULT_PERMISSIONS.DELETE,
    VAULT_PERMISSIONS.SHARE,
  ],
  OWNER: [
    VAULT_PERMISSIONS.READ,
    VAULT_PERMISSIONS.EDIT,
    VAULT_PERMISSIONS.DELETE,
    VAULT_PERMISSIONS.SHARE,
    VAULT_PERMISSIONS.ADMIN,
  ],
} as const satisfies Record<string, readonly VaultPermission[]>;

export type VaultAccessPreset = keyof typeof VAULT_ACCESS_PRESETS;

export const VAULT_ACCESS_PRESET_LABEL: Readonly<Record<VaultAccessPreset, string>> = {
  VIEWER: 'Viewer',
  CONTRIBUTOR: 'Contributor',
  EDITOR: 'Editor',
  MANAGER: 'Manager',
  OWNER: 'Owner',
};

/*
 * Who a grant can name.
 *
 * Users only. Departments went first (a people-group did the same job), and
 * people-groups went when "group" came to mean a group of *passwords*: access
 * is now a straight user -> vault edge, so there is nothing left to pick.
 */
export const GRANT_SUBJECT_TYPE = {
  USER: 'user',
} as const;

export type GrantSubjectType = (typeof GRANT_SUBJECT_TYPE)[keyof typeof GRANT_SUBJECT_TYPE];

/**
 * Normalise a permission set.
 *
 * Every right implies READ - a grant of EDIT without READ would describe someone
 * who can overwrite items they cannot see - so READ is added rather than
 * validated, and the result is ordered so two equal sets compare equal as JSON.
 */
export function normalizeVaultPermissions(
  permissions: readonly VaultPermission[],
): VaultPermission[] {
  const set = new Set<VaultPermission>(permissions);
  if (set.size > 0) set.add(VAULT_PERMISSIONS.READ);
  return VAULT_PERMISSION_LIST.filter((permission) => set.has(permission));
}

/** True when `granted` covers `required`. */
export function hasVaultPermission(
  granted: readonly VaultPermission[],
  required: VaultPermission,
): boolean {
  // ADMIN is deliberately *not* a wildcard here. It grants control over the
  // vault's configuration and membership; it does not silently confer EDIT or
  // DELETE on the contents. An administrator who wants to change items grants
  // themselves those rights explicitly, and that grant is auditable.
  return granted.includes(required);
}

/** The preset matching a permission set exactly, if there is one. */
export function presetFor(permissions: readonly VaultPermission[]): VaultAccessPreset | null {
  const normalized = normalizeVaultPermissions(permissions).join(',');

  for (const [name, preset] of Object.entries(VAULT_ACCESS_PRESETS)) {
    if (normalizeVaultPermissions(preset).join(',') === normalized) {
      return name as VaultAccessPreset;
    }
  }
  return null;
}

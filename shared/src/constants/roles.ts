/**
 * Role definitions shared across every client and the API.
 *
 * Roles are stored in the MySQL `roles` table, but the *identifiers* are
 * compile-time constants so that authorization checks cannot drift between
 * the database, the API and the UI.
 */

/** Canonical role identifiers (must match `roles.name` in MySQL). */
/*
 * Two roles, not three.
 *
 * `manager` was removed because everything it once meant had been taken away
 * from under it: managers cannot sign in to the console (administrators only)
 * and cannot reveal or copy a password. It named a middle tier that no longer
 * had any capability of its own, which is harder to explain than it is useful.
 *
 * `employee` is the identifier; the label people read is "Member".
 */
export const ROLES = {
  ADMIN: 'admin',
  EMPLOYEE: 'employee',
} as const;

export type RoleName = (typeof ROLES)[keyof typeof ROLES];

export const ROLE_NAMES: readonly RoleName[] = [ROLES.ADMIN, ROLES.EMPLOYEE];

/**
 * Privilege level per role. Higher wins.
 *
 * Used for "at least this role" checks (`requireMinRole`) so that adding a new
 * role in the middle of the hierarchy does not require touching every route.
 */
export const ROLE_LEVEL: Readonly<Record<RoleName, number>> = {
  [ROLES.ADMIN]: 100,
  [ROLES.EMPLOYEE]: 10,
};

/** Human readable labels for UI rendering. */
export const ROLE_LABEL: Readonly<Record<RoleName, string>> = {
  [ROLES.ADMIN]: 'Administrator',
  // "Member", not "Employee": the people using this are members of groups, and
  // the word has to make sense to whoever reads the user list.
  [ROLES.EMPLOYEE]: 'Member',
};

/** Type guard used when validating untrusted input (request bodies, JWT claims). */
export function isRoleName(value: unknown): value is RoleName {
  return typeof value === 'string' && (ROLE_NAMES as readonly string[]).includes(value);
}

/** True when `role` is at least as privileged as `minimum`. */
export function roleAtLeast(role: RoleName, minimum: RoleName): boolean {
  return ROLE_LEVEL[role] >= ROLE_LEVEL[minimum];
}

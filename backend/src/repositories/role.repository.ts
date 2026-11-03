/**
 * Role repository.
 *
 * Roles are a tiny, effectively static table, so lookups are memoised for the
 * process lifetime. Provisioning a user needs `roles.id` for the foreign key on
 * every call, and hitting MySQL for a three-row table on each request is waste.
 * The cache is invalidated explicitly by {@link clearRoleCache} (used by tests
 * and by the seeder).
 */

import type { RoleName } from '@passm/shared';

import { query, type SqlExecutor } from '../config/database';
import { mapRoleRow, type RoleRecord, type RoleRow } from '../models/role.model';

const ROLE_COLUMNS = 'id, name, label, description, level, is_system, created_at, updated_at';

let cache: Map<string, RoleRecord> | null = null;

async function loadCache(executor?: SqlExecutor): Promise<Map<string, RoleRecord>> {
  if (cache) return cache;

  const rows = await query<RoleRow>(
    `SELECT ${ROLE_COLUMNS} FROM roles ORDER BY level DESC`,
    [],
    executor,
  );

  const loaded = new Map<string, RoleRecord>();
  for (const row of rows) {
    const record = mapRoleRow(row);
    loaded.set(record.name, record);
    loaded.set(record.id, record);
  }

  cache = loaded;
  return loaded;
}

export const roleRepository = {
  /** Every role, ordered most privileged first. */
  async findAll(executor?: SqlExecutor): Promise<RoleRecord[]> {
    const rows = await query<RoleRow>(
      `SELECT ${ROLE_COLUMNS} FROM roles ORDER BY level DESC`,
      [],
      executor,
    );
    return rows.map(mapRoleRow);
  },

  async findByName(name: RoleName, executor?: SqlExecutor): Promise<RoleRecord | null> {
    return (await loadCache(executor)).get(name) ?? null;
  },

  async findById(id: string, executor?: SqlExecutor): Promise<RoleRecord | null> {
    return (await loadCache(executor)).get(id) ?? null;
  },

  /**
   * Resolve a role name to its id for a foreign key.
   * @throws when the role is missing - that means migration 002 never ran.
   */
  async requireIdByName(name: RoleName, executor?: SqlExecutor): Promise<string> {
    const role = await this.findByName(name, executor);
    if (!role) {
      throw new Error(
        `Role "${name}" is not present in the database. Run \`npm run db:migrate\` to seed system roles.`,
      );
    }
    return role.id;
  },
};

/** Drop the memoised roles. Call after any write to the `roles` table. */
export function clearRoleCache(): void {
  cache = null;
}

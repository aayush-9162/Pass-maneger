/**
 * Role model.
 *
 * `*Row` interfaces mirror MySQL columns exactly (snake_case, driver types);
 * `*Record` interfaces are the camelCase domain shape used everywhere above the
 * repository layer. Mapping happens in exactly one place per table.
 */

import type { RoleName } from '@passm/shared';
import type { RowDataPacket } from 'mysql2';

export interface RoleRow extends RowDataPacket {
  id: string;
  name: string;
  label: string;
  description: string | null;
  level: number;
  is_system: number;
  created_at: Date;
  updated_at: Date;
}

export interface RoleRecord {
  id: string;
  name: RoleName;
  label: string;
  description: string | null;
  level: number;
  isSystem: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export function mapRoleRow(row: RoleRow): RoleRecord {
  return {
    id: row.id,
    // Safe cast: `roles.name` is constrained to the seeded set, and the value is
    // re-validated by `isRoleName` before it is used in an authorization check.
    name: row.name as RoleName,
    label: row.label,
    description: row.description,
    level: row.level,
    isSystem: row.is_system === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

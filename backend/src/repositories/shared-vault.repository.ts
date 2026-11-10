/**
 * Shared vault repository - the storage behind both "groups" of passwords and
 * the single-item wrappers that individual passwords live in.
 *
 * ## The predicate that matters
 *
 * Grants name users directly - people-groups and departments are gone - so
 * membership is one equality, written once as {@link SUBJECT_MATCH} and used by
 * every query that resolves it: "who can see this vault" has exactly one
 * definition.
 *
 * ## What this repository never does
 *
 * It never opens an item envelope. Rows go in and come out as ciphertext; the
 * shared-vault service is the one place that encrypts and decrypts them.
 */

import {
  NO_RESTRICTIONS,
  VAULT_ROLE,
  VAULT_ROLE_PERMISSIONS,
  VAULT_ROLE_RANK,
} from '@passm/shared';
import type {
  GrantSubjectType,
  SharedVault,
  SharedVaultGrant,
  SharedVaultStatus,
  VaultItemType,
  VaultPermission,
  VaultRestrictions,
  VaultRole,
  VaultKind,
  DefaultGroupRole,
} from '@passm/shared';

import {
  execute,
  query,
  queryOne,
  type RowDataPacket,
  type SqlExecutor,
  type SqlParam,
} from '../config/database';
import {
  mapGrantRow,
  mapRestrictions,
  mergeRestrictions,
  mapSharedItemRow,
  mapSharedVaultRow,
  mergePermissions,
  parsePermissions,
  serializePermissions,
  type GrantRow,
  type SharedItemRow,
  type SharedVaultRow,
  type StoredSharedItem,
} from '../models/shared-vault.model';
import { newId } from '../utils/ids';
import { likePattern, limitOffsetClause, resolvePagination, resolveSortColumn, resolveSortDirection } from '../utils/sql';

/** Does grant `g` reach the user bound to the following `?` placeholder? */
const SUBJECT_MATCH = `(g.subject_type = 'user' AND g.subject_id = ?)`;

/**
 * Bind the user id(s) {@link SUBJECT_MATCH} consumes.
 *
 * This count tracks the number of `?` in that expression - three under
 * departments, two under people-groups, one now. Getting it wrong does not
 * fail loudly; it shifts every following parameter by one and quietly answers
 * the wrong question, which is why the binding lives next to the SQL.
 */
const subjectParams = (userId: string): SqlParam[] => [userId];

const VAULT_COLUMNS = `
  sv.id, sv.name, sv.description, sv.color, sv.kind,
  sv.require_approval_to_join, sv.require_approval_to_reveal, sv.auto_grant_role,
  sv.status, sv.revision, sv.created_by,
  sv.created_at, sv.updated_at,
  creator.first_name AS creator_first_name,
  creator.last_name  AS creator_last_name,
  (SELECT COUNT(*) FROM shared_vault_items i
     WHERE i.shared_vault_id = sv.id AND i.deleted_at IS NULL) AS item_count,
  (SELECT COUNT(*) FROM shared_vault_grants g WHERE g.shared_vault_id = sv.id) AS member_count
`;

const VAULT_SOURCE = `
  FROM shared_vaults sv
  LEFT JOIN users creator ON creator.id = sv.created_by
`;

const VAULT_SORT_COLUMNS = {
  name: 'sv.name',
  createdAt: 'sv.created_at',
  updatedAt: 'sv.updated_at',
  itemCount: 'item_count',
  members: 'member_count',
} as const;

const ITEM_COLUMNS = `
  i.id, i.shared_vault_id, i.type, i.encrypted_data, i.encrypted_secret,
  i.favorite, i.revision, i.created_by, i.updated_by,
  i.created_at, i.updated_at, i.deleted_at,
  ub.first_name AS updated_by_first_name,
  ub.last_name  AS updated_by_last_name
`;

const ITEM_SORT_COLUMNS = {
  updatedAt: 'i.updated_at',
  createdAt: 'i.created_at',
  type: 'i.type',
} as const;

interface CountRow extends RowDataPacket {
  total: number;
}

export interface CreateSharedVaultInput {
  name: string;
  description?: string | null;
  color?: string | null;
  /** `group` = named collection; `item` = wrapper around one individual password. */
  kind: VaultKind;
  requireApprovalToJoin?: boolean;
  requireApprovalToReveal?: boolean;
  createdBy: string;
}

export interface UpdateSharedVaultInput {
  name?: string | undefined;
  description?: string | null | undefined;
  color?: string | null | undefined;
  requireApprovalToJoin?: boolean | undefined;
  requireApprovalToReveal?: boolean | undefined;
  autoGrantRole?: DefaultGroupRole | null | undefined;
  status?: SharedVaultStatus | undefined;
}

export interface ListSharedVaultsFilter {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortDir?: string;
  search?: string;
  status?: SharedVaultStatus;
  kind?: VaultKind;
}

export const sharedVaultRepository = {
  // -------------------------------------------------------------------------
  // Vaults
  // -------------------------------------------------------------------------

  async findById(id: string, executor?: SqlExecutor): Promise<SharedVault | null> {
    const row = await queryOne<SharedVaultRow>(
      `SELECT ${VAULT_COLUMNS} ${VAULT_SOURCE} WHERE sv.id = ? AND sv.deleted_at IS NULL LIMIT 1`,
      [id],
      executor,
    );
    return row ? mapSharedVaultRow(row) : null;
  },

  /** Administrative listing: every vault, member or not. */
  async list(
    filter: ListSharedVaultsFilter = {},
    executor?: SqlExecutor,
  ): Promise<{ items: SharedVault[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['sv.deleted_at IS NULL'];
    const params: SqlParam[] = [];

    if (filter.search) {
      conditions.push('(sv.name LIKE ? OR sv.description LIKE ?)');
      const pattern = likePattern(filter.search);
      params.push(pattern, pattern);
    }
    if (filter.status) {
      conditions.push('sv.status = ?');
      params.push(filter.status);
    }
    if (filter.kind) {
      conditions.push('sv.kind = ?');
      params.push(filter.kind);
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const orderColumn = resolveSortColumn(filter.sortBy, VAULT_SORT_COLUMNS, 'name');
    const orderDirection = resolveSortDirection(filter.sortDir);

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM shared_vaults sv ${where}`,
      params,
      executor,
    );

    const rows = await query<SharedVaultRow>(
      `SELECT ${VAULT_COLUMNS} ${VAULT_SOURCE} ${where}
        ORDER BY ${orderColumn} ${orderDirection}, sv.id ASC
        ${limitOffsetClause(limit, offset)}`,
      [...params],
      executor,
    );

    return {
      items: rows.map(mapSharedVaultRow),
      total: countRow?.total ?? 0,
      page,
      pageSize,
    };
  },

  /** Vaults a specific user holds a grant on. */
  async listForUser(userId: string, executor?: SqlExecutor): Promise<SharedVault[]> {
    const rows = await query<SharedVaultRow>(
      `SELECT ${VAULT_COLUMNS} ${VAULT_SOURCE}
        WHERE sv.deleted_at IS NULL
          AND EXISTS (
            SELECT 1 FROM shared_vault_grants g
             WHERE g.shared_vault_id = sv.id AND ${SUBJECT_MATCH})
        ORDER BY sv.name ASC`,
      subjectParams(userId),
      executor,
    );
    return rows.map(mapSharedVaultRow);
  },

  /** Every vault not deleted - an administrator's view, which no grant limits. */
  async listActive(executor?: SqlExecutor): Promise<SharedVault[]> {
    const rows = await query<SharedVaultRow>(
      `SELECT ${VAULT_COLUMNS} ${VAULT_SOURCE}
        WHERE sv.deleted_at IS NULL
        ORDER BY sv.name ASC`,
      [],
      executor,
    );
    return rows.map(mapSharedVaultRow);
  },

  /** The user-detail "what can this person use" list: every vault granted to the user. */
  async accessForUser(
    userId: string,
    executor?: SqlExecutor,
  ): Promise<
    {
      vaultId: string;
      name: string;
      kind: 'group' | 'item';
      accessRole: string;
      hiddenPassword: boolean;
    }[]
  > {
    const rows = await query<
      RowDataPacket & {
        vault_id: string;
        name: string;
        kind: string;
        access_role: string;
        hidden_password: number;
      }
    >(
      `SELECT sv.id AS vault_id, sv.name, sv.kind, g.access_role, g.hidden_password
         FROM shared_vault_grants g
         JOIN shared_vaults sv ON sv.id = g.shared_vault_id AND sv.deleted_at IS NULL
        WHERE g.subject_type = 'user' AND g.subject_id = ?
        ORDER BY sv.kind ASC, sv.name ASC`,
      [userId],
      executor,
    );

    return rows.map((row) => ({
      vaultId: row.vault_id,
      name: row.name,
      kind: row.kind === 'item' ? ('item' as const) : ('group' as const),
      accessRole: row.access_role,
      hiddenPassword: Number(row.hidden_password) === 1,
    }));
  },

  async create(input: CreateSharedVaultInput, executor?: SqlExecutor): Promise<string> {
    const id = newId();

    await execute(
      `INSERT INTO shared_vaults
         (id, name, description, color, kind,
          require_approval_to_join, require_approval_to_reveal, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        input.name,
        input.description ?? null,
        input.color ?? null,
        input.kind,
        input.requireApprovalToJoin ? 1 : 0,
        input.requireApprovalToReveal ? 1 : 0,
        input.createdBy,
      ],
      executor,
    );

    return id;
  },

  async update(
    id: string,
    input: UpdateSharedVaultInput,
    executor?: SqlExecutor,
  ): Promise<number> {
    const columnMap: Record<keyof UpdateSharedVaultInput, string> = {
      name: 'name',
      description: 'description',
      color: 'color',
      requireApprovalToJoin: 'require_approval_to_join',
      requireApprovalToReveal: 'require_approval_to_reveal',
      autoGrantRole: 'auto_grant_role',
      status: 'status',
    };

    const assignments: string[] = [];
    const params: SqlParam[] = [];

    for (const [key, column] of Object.entries(columnMap) as [
      keyof UpdateSharedVaultInput,
      string,
    ][]) {
      const value = input[key];
      if (value === undefined) continue;
      assignments.push(`${column} = ?`);
      // Booleans map to TINYINT(1); mysql2 handles the conversion, but being
      // explicit keeps the stored value 0/1 rather than driver-dependent.
      params.push(typeof value === 'boolean' ? (value ? 1 : 0) : value);
    }

    if (assignments.length === 0) return 0;

    const result = await execute(
      `UPDATE shared_vaults SET ${assignments.join(', ')}, revision = revision + 1
        WHERE id = ? AND deleted_at IS NULL`,
      [...params, id],
      executor,
    );
    return result.affectedRows;
  },

  /**
   * Soft-delete the vault and drop every grant on it.
   *
   * Access ends immediately; the rows stay under the soft delete so an
   * accidental deletion is recoverable from the database, and `name` is
   * freed for reuse.
   */
  async softDelete(id: string, executor?: SqlExecutor): Promise<number> {
    await execute('DELETE FROM shared_vault_grants WHERE shared_vault_id = ?', [id], executor);

    const result = await execute(
      `UPDATE shared_vaults
          SET deleted_at = NOW(3),
              status = 'archived',
              name = CONCAT('deleted:', UNIX_TIMESTAMP(NOW(3)), ':', name)
        WHERE id = ? AND deleted_at IS NULL`,
      [id],
      executor,
    );
    return result.affectedRows;
  },

  async existsByName(name: string, excludeId?: string, executor?: SqlExecutor): Promise<boolean> {
    const row = await queryOne<CountRow>(
      'SELECT COUNT(*) AS total FROM shared_vaults WHERE name = ? AND id <> ? AND deleted_at IS NULL',
      [name, excludeId ?? ''],
      executor,
    );
    return (row?.total ?? 0) > 0;
  },

  async count(kind?: VaultKind, executor?: SqlExecutor): Promise<number> {
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM shared_vaults
        WHERE deleted_at IS NULL ${kind ? 'AND kind = ?' : ''}`,
      kind ? [kind] : [],
      executor,
    );
    return row?.total ?? 0;
  },

  // -------------------------------------------------------------------------
  // Permissions
  // -------------------------------------------------------------------------

  /**
   * The caller's effective rights on a vault: the union of every grant that
   * reaches them.
   *
   * Grants name users directly, so there is normally one row - but the union
   * keeps the answer right if a duplicate ever appears, rather than depending
   * on which row MySQL returns first.
   */
  async effectivePermissions(
    sharedVaultId: string,
    userId: string,
    executor?: SqlExecutor,
  ): Promise<VaultPermission[]> {
    return (await this.effectiveAccess(sharedVaultId, userId, executor)).permissions;
  },

  /**
   * The caller's full effective access: permissions, role and restrictions.
   *
   * Permissions and role combine *permissively* (the union, the highest role);
   * restrictions combine *restrictively* (the union of every restriction). Both
   * are the safest reading of what the administrators intended.
   */
  async effectiveAccess(
    sharedVaultId: string,
    userId: string,
    executor?: SqlExecutor,
  ): Promise<{
    permissions: VaultPermission[];
    role: VaultRole;
    restrictions: VaultRestrictions;
    hasGrant: boolean;
  }> {
    const rows = await query<
      RowDataPacket & {
        permissions: string;
        access_role: string;
        hidden_password: number;
        copy_only: number;
        no_edit: number;
        no_delete: number;
      }
    >(
      `SELECT g.permissions, g.access_role, g.hidden_password, g.copy_only,
              g.no_edit, g.no_delete
         FROM shared_vault_grants g
        WHERE g.shared_vault_id = ? AND ${SUBJECT_MATCH}`,
      [sharedVaultId, ...subjectParams(userId)],
      executor,
    );

    if (rows.length === 0) {
      return {
        permissions: [],
        role: VAULT_ROLE.VIEWER,
        restrictions: NO_RESTRICTIONS,
        hasGrant: false,
      };
    }

    const role = rows
      .map((row) => (row.access_role as VaultRole) ?? VAULT_ROLE.VIEWER)
      .reduce((best, candidate) =>
        VAULT_ROLE_RANK[candidate] > VAULT_ROLE_RANK[best] ? candidate : best,
      );

    return {
      permissions: mergePermissions(rows.map((row) => row.permissions)),
      role,
      restrictions: mergeRestrictions(rows.map(mapRestrictions)),
      hasGrant: true,
    };
  },

  /** Effective permissions for every vault the user can reach, in one query. */
  async effectivePermissionsForAll(
    userId: string,
    executor?: SqlExecutor,
  ): Promise<Map<string, VaultPermission[]>> {
    const rows = await query<RowDataPacket & { shared_vault_id: string; permissions: string }>(
      `SELECT g.shared_vault_id, g.permissions
         FROM shared_vault_grants g
        INNER JOIN shared_vaults sv ON sv.id = g.shared_vault_id AND sv.deleted_at IS NULL
        WHERE ${SUBJECT_MATCH}`,
      subjectParams(userId),
      executor,
    );

    const grouped = new Map<string, string[]>();
    for (const row of rows) {
      const existing = grouped.get(row.shared_vault_id);
      if (existing) existing.push(row.permissions);
      else grouped.set(row.shared_vault_id, [row.permissions]);
    }

    return new Map([...grouped].map(([vaultId, values]) => [vaultId, mergePermissions(values)]));
  },

  // -------------------------------------------------------------------------
  // Grants
  // -------------------------------------------------------------------------

  async listGrants(sharedVaultId: string, executor?: SqlExecutor): Promise<SharedVaultGrant[]> {
    const rows = await query<GrantRow>(
      `SELECT g.id, g.shared_vault_id, g.subject_type, g.subject_id, g.permissions,
              g.access_role, g.hidden_password, g.copy_only, g.no_edit, g.no_delete,
              g.granted_by, g.created_at, g.updated_at,
              CONCAT(su.first_name, ' ', su.last_name) AS subject_name,
              su.email AS subject_email,
              gb.first_name AS granted_by_first_name,
              gb.last_name  AS granted_by_last_name
         FROM shared_vault_grants g
         LEFT JOIN users su ON su.id = g.subject_id
         LEFT JOIN users gb ON gb.id = g.granted_by
        WHERE g.shared_vault_id = ?
        ORDER BY subject_name ASC`,
      [sharedVaultId],
      executor,
    );

    return rows.map(mapGrantRow);
  },

  /**
   * Create or replace a grant.
   *
   * Upsert rather than insert-or-fail: `uq_grants_vault_subject` makes one grant
   * per subject the invariant, and re-granting to someone who already has access
   * should update their rights, not 409.
   */
  async upsertGrant(
    sharedVaultId: string,
    subjectType: GrantSubjectType,
    subjectId: string,
    role: VaultRole,
    restrictions: VaultRestrictions,
    /** Null when the system granted it - a default group on account creation. */
    grantedBy: string | null,
    executor?: SqlExecutor,
  ): Promise<string> {
    const id = newId();

    // The permission set is derived from the role rather than accepted from the
    // caller, so the two can never disagree - the role is what the console
    // shows and the permissions are what the API enforces.
    const serialized = serializePermissions(VAULT_ROLE_PERMISSIONS[role]);

    await execute(
      `INSERT INTO shared_vault_grants
         (id, shared_vault_id, subject_type, subject_id, permissions, access_role,
          hidden_password, copy_only, no_edit, no_delete, granted_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AS new_grant
       ON DUPLICATE KEY UPDATE
         permissions     = new_grant.permissions,
         access_role     = new_grant.access_role,
         hidden_password = new_grant.hidden_password,
         copy_only       = new_grant.copy_only,
         no_edit         = new_grant.no_edit,
         no_delete       = new_grant.no_delete,
         granted_by      = new_grant.granted_by`,
      [
        id, sharedVaultId, subjectType, subjectId, serialized, role,
        restrictions.hiddenPassword ? 1 : 0,
        restrictions.copyOnly ? 1 : 0,
        restrictions.noEdit ? 1 : 0,
        restrictions.noDelete ? 1 : 0,
        grantedBy,
      ],
      executor,
    );

    const existing = await queryOne<RowDataPacket & { id: string }>(
      `SELECT id FROM shared_vault_grants
        WHERE shared_vault_id = ? AND subject_type = ? AND subject_id = ?`,
      [sharedVaultId, subjectType, subjectId],
      executor,
    );

    return existing?.id ?? id;
  },

  async findGrant(
    grantId: string,
    executor?: SqlExecutor,
  ): Promise<{
    id: string;
    sharedVaultId: string;
    subjectType: GrantSubjectType;
    subjectId: string;
    permissions: VaultPermission[];
    accessRole: VaultRole;
    restrictions: VaultRestrictions;
  } | null> {
    const row = await queryOne<
      RowDataPacket & {
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
      }
    >(
      `SELECT id, shared_vault_id, subject_type, subject_id, permissions,
              access_role, hidden_password, copy_only, no_edit, no_delete
         FROM shared_vault_grants WHERE id = ?`,
      [grantId],
      executor,
    );

    if (!row) return null;

    return {
      id: row.id,
      sharedVaultId: row.shared_vault_id,
      subjectType: row.subject_type as GrantSubjectType,
      subjectId: row.subject_id,
      permissions: parsePermissions(row.permissions),
      accessRole: row.access_role as VaultRole,
      restrictions: mapRestrictions(row),
    };
  },

  async updateGrantAccess(
    grantId: string,
    role: VaultRole,
    restrictions: VaultRestrictions,
    executor?: SqlExecutor,
  ): Promise<number> {
    const result = await execute(
      `UPDATE shared_vault_grants
          SET permissions = ?, access_role = ?,
              hidden_password = ?, copy_only = ?, no_edit = ?, no_delete = ?
        WHERE id = ?`,
      [
        serializePermissions(VAULT_ROLE_PERMISSIONS[role]),
        role,
        restrictions.hiddenPassword ? 1 : 0,
        restrictions.copyOnly ? 1 : 0,
        restrictions.noEdit ? 1 : 0,
        restrictions.noDelete ? 1 : 0,
        grantId,
      ],
      executor,
    );
    return result.affectedRows;
  },

  async removeGrant(grantId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute('DELETE FROM shared_vault_grants WHERE id = ?', [grantId], executor);
    return result.affectedRows;
  },

  /**
   * Grant a new account every default group, each with its configured role.
   *
   * Returns what was granted, for the audit trail. Upserts, so running it for
   * an account that already holds one of these grants changes nothing worse
   * than resetting that grant to the default role.
   */
  async grantDefaultGroups(
    userId: string,
    executor?: SqlExecutor,
  ): Promise<{ vaultId: string; name: string; role: DefaultGroupRole }[]> {
    const rows = await query<RowDataPacket & { id: string; name: string; auto_grant_role: DefaultGroupRole }>(
      `SELECT id, name, auto_grant_role FROM shared_vaults
        WHERE auto_grant_role IS NOT NULL AND kind = 'group'
          AND status = 'active' AND deleted_at IS NULL`,
      [],
      executor,
    );

    for (const row of rows) {
      await this.upsertGrant(row.id, 'user', userId, row.auto_grant_role, NO_RESTRICTIONS, null, executor);
    }

    return rows.map((row) => ({ vaultId: row.id, name: row.name, role: row.auto_grant_role }));
  },

  /** Remove every grant naming a user, across all vaults. The call a user deletion needs. */
  async removeAccessForUser(
    userId: string,
    executor?: SqlExecutor,
  ): Promise<{ revokedGrants: number }> {
    const grants = await execute(
      `DELETE FROM shared_vault_grants WHERE subject_type = 'user' AND subject_id = ?`,
      [userId],
      executor,
    );
    return { revokedGrants: grants.affectedRows };
  },

  /** True when the user is entitled to the vault by any grant. */
  async isEntitled(
    sharedVaultId: string,
    userId: string,
    executor?: SqlExecutor,
  ): Promise<boolean> {
    const row = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM shared_vault_grants g
        WHERE g.shared_vault_id = ? AND ${SUBJECT_MATCH}`,
      [sharedVaultId, ...subjectParams(userId)],
      executor,
    );
    return (row?.total ?? 0) > 0;
  },

  // -------------------------------------------------------------------------
  // Items
  // -------------------------------------------------------------------------

  async listItems(
    sharedVaultId: string,
    filter: {
      page?: number;
      pageSize?: number;
      sortBy?: string;
      sortDir?: string;
      type?: VaultItemType;
      includeDeleted?: boolean;
      updatedSince?: string;
    } = {},
    executor?: SqlExecutor,
  ): Promise<{ items: StoredSharedItem[]; total: number; page: number; pageSize: number }> {
    const { page, pageSize, limit, offset } = resolvePagination(filter);

    const conditions: string[] = ['i.shared_vault_id = ?'];
    const params: SqlParam[] = [sharedVaultId];

    if (!filter.includeDeleted) conditions.push('i.deleted_at IS NULL');
    if (filter.type) {
      conditions.push('i.type = ?');
      params.push(filter.type);
    }
    if (filter.updatedSince) {
      conditions.push('i.updated_at >= ?');
      params.push(new Date(filter.updatedSince));
    }

    const where = `WHERE ${conditions.join(' AND ')}`;
    const orderColumn = resolveSortColumn(filter.sortBy, ITEM_SORT_COLUMNS, 'updatedAt');
    const orderDirection = resolveSortDirection(filter.sortDir);

    const countRow = await queryOne<CountRow>(
      `SELECT COUNT(*) AS total FROM shared_vault_items i ${where}`,
      params,
      executor,
    );

    const rows = await query<SharedItemRow>(
      `SELECT ${ITEM_COLUMNS}
         FROM shared_vault_items i
         LEFT JOIN users ub ON ub.id = i.updated_by
         ${where}
        ORDER BY ${orderColumn} ${orderDirection}, i.id ASC
        ${limitOffsetClause(limit, offset)}`,
      [...params],
      executor,
    );

    return {
      items: rows.map(mapSharedItemRow),
      total: countRow?.total ?? 0,
      page,
      pageSize,
    };
  },

  async findItem(itemId: string, executor?: SqlExecutor): Promise<StoredSharedItem | null> {
    const row = await queryOne<SharedItemRow>(
      `SELECT ${ITEM_COLUMNS}
         FROM shared_vault_items i
         LEFT JOIN users ub ON ub.id = i.updated_by
        WHERE i.id = ? LIMIT 1`,
      [itemId],
      executor,
    );
    return row ? mapSharedItemRow(row) : null;
  },

  async createItem(
    input: {
      id: string;
      sharedVaultId: string;
      type: VaultItemType;
      encryptedData: string;
      encryptedSecret: string | null;
      favorite?: boolean;
      actorUserId: string;
    },
    executor?: SqlExecutor,
  ): Promise<void> {
    await execute(
      `INSERT INTO shared_vault_items
         (id, shared_vault_id, type, encrypted_data, encrypted_secret, favorite, created_by, updated_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        input.id,
        input.sharedVaultId,
        input.type,
        input.encryptedData,
        input.encryptedSecret,
        input.favorite ? 1 : 0,
        input.actorUserId,
        input.actorUserId,
      ],
      executor,
    );
  },

  /**
   * Update an item, guarded by its revision.
   *
   * Returns 0 when the revision has moved on, which the service turns into a
   * 409. In a shared vault this is not a theoretical race: two people editing
   * the same credential is the normal case, and a silent last-write-wins would
   * destroy one of them without either noticing.
   */
  async updateItem(
    itemId: string,
    expectedRevision: number,
    input: {
      encryptedData?: string | undefined;
      /** Null clears the secret; undefined leaves it alone. */
      encryptedSecret?: string | null | undefined;
      favorite?: boolean | undefined;
      sharedVaultId?: string | undefined;
      actorUserId: string;
    },
    executor?: SqlExecutor,
  ): Promise<number> {
    const assignments: string[] = ['revision = revision + 1', 'updated_by = ?'];
    const params: SqlParam[] = [input.actorUserId];

    if (input.encryptedData !== undefined) {
      assignments.push('encrypted_data = ?');
      params.push(input.encryptedData);
    }
    if (input.encryptedSecret !== undefined) {
      assignments.push('encrypted_secret = ?');
      params.push(input.encryptedSecret);
    }
    if (input.favorite !== undefined) {
      assignments.push('favorite = ?');
      params.push(input.favorite ? 1 : 0);
    }
    if (input.sharedVaultId !== undefined) {
      assignments.push('shared_vault_id = ?');
      params.push(input.sharedVaultId);
    }

    const result = await execute(
      `UPDATE shared_vault_items SET ${assignments.join(', ')}
        WHERE id = ? AND revision = ? AND deleted_at IS NULL`,
      [...params, itemId, expectedRevision],
      executor,
    );
    return result.affectedRows;
  },

  async softDeleteItem(itemId: string, actorUserId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE shared_vault_items
          SET deleted_at = NOW(3), updated_by = ?, revision = revision + 1
        WHERE id = ? AND deleted_at IS NULL`,
      [actorUserId, itemId],
      executor,
    );
    return result.affectedRows;
  },

  async restoreItem(itemId: string, actorUserId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute(
      `UPDATE shared_vault_items
          SET deleted_at = NULL, updated_by = ?, revision = revision + 1
        WHERE id = ? AND deleted_at IS NOT NULL`,
      [actorUserId, itemId],
      executor,
    );
    return result.affectedRows;
  },

  async purgeItem(itemId: string, executor?: SqlExecutor): Promise<number> {
    const result = await execute('DELETE FROM shared_vault_items WHERE id = ?', [itemId], executor);
    return result.affectedRows;
  },

  /** Item totals for the dashboard, by type across every shared vault. */
  async countItemsByType(executor?: SqlExecutor): Promise<Record<string, number>> {
    const rows = await query<RowDataPacket & { type: string; total: number }>(
      `SELECT i.type, COUNT(*) AS total
         FROM shared_vault_items i
        INNER JOIN shared_vaults sv ON sv.id = i.shared_vault_id AND sv.deleted_at IS NULL
        WHERE i.deleted_at IS NULL
        GROUP BY i.type`,
      [],
      executor,
    );
    return Object.fromEntries(rows.map((row) => [row.type, Number(row.total)]));
  },
};

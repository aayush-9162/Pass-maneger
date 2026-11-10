/**
 * Shared vaults - password groups, and the wrappers individual passwords live in.
 *
 * ## Two authorities, kept apart
 *
 *  - **Administrative** (`shared_vault:manage`). Create, rename, archive,
 *    delete; add, change and revoke grants. Everything about *who may have
 *    access*. It confers no ability to read anything by itself.
 *  - **Membership** (a grant). Read and write items, within the grant's role
 *    and restrictions.
 *
 * An administrator can hand themselves a grant - and the audit trail records
 * that they did.
 *
 * ## Who may change anything
 *
 * Only administrators, and only from the console. Everyone else uses passwords
 * through the browser extension - fill and copy - and the extension changes
 * nothing, whoever is signed in to it. {@link sharedVaultService.assertMayChange}
 * guards every write: groups, access and items. Vault roles still decide what
 * an administrator's own grant lets them do to items.
 *
 * ## Encryption
 *
 * Item contents are encrypted here, under ENCRYPTION_KEY, and nowhere else.
 * Each item is two envelopes: `data` (name, username, URLs, notes), returned
 * with every listing, and `secret` (password, TOTP), released one item at a
 * time by {@link sharedVaultService.getSecret}, which applies the
 * hidden-password restriction and the reveal-approval rule and audits the
 * release. Both envelopes carry the item id as AAD, so a blob copied onto
 * another row fails to open. The vault id is deliberately not bound in: a move
 * is then a one-column update rather than a re-encryption.
 */

import {
  AUDIT_ACTIONS,
  NO_RESTRICTIONS,
  PERMISSIONS,
  ROLES,
  SECRET_PURPOSE,
  SHARED_VAULT_STATUS,
  VAULT_KIND,
  VAULT_PERMISSIONS,
  VAULT_ROLE,
  VAULT_ROLE_PERMISSIONS,
  entitledToSecrets,
  hasVaultPermission,
  type MemberSharedVault,
  type PaginatedResult,
  type SecretPurpose,
  type SharedItemData,
  type SharedItemSecret,
  type SharedVault,
  type SharedVaultGrant,
  type SharedVaultItem,
  type VaultItemType,
  type VaultPermission,
  type VaultRestrictions,
  type VaultRole,
} from '@passm/shared';

import { withTransaction, type SqlExecutor } from '../config/database';
import { logger } from '../config/logger';
import type {
  CreateGrantDto,
  CreateSharedItemDto,
  CreateSharedVaultDto,
  ListSharedItemsQueryDto,
  MoveSharedItemDto,
  UpdateGrantDto,
  UpdateSharedItemDto,
  UpdateSharedVaultDto,
} from '../dto/sharing.dto';
import type { StoredSharedItem } from '../models/shared-vault.model';
import { accessRequestRepository } from '../repositories/access-request.repository';
import {
  sharedVaultRepository,
  type CreateSharedVaultInput,
  type ListSharedVaultsFilter,
} from '../repositories/shared-vault.repository';
import { userRepository } from '../repositories/user.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import { paginated } from '../utils/api-response';
import { BadRequestError, ConflictError, ForbiddenError, NotFoundError } from '../utils/errors';
import { newId } from '../utils/ids';
import { isDuplicateEntryError } from '../utils/sql';
import { auditService } from './audit.service';
import { decrypt, encrypt } from './crypto.service';

/** 409 for an optimistic-concurrency miss - a real event in a shared vault. */
function staleRevision(): ConflictError {
  return new ConflictError(
    'Someone else changed this item first. Reload it and apply your change again.',
  );
}

// ---------------------------------------------------------------------------
// Item envelopes
// ---------------------------------------------------------------------------

const itemAad = (itemId: string, part: 'data' | 'secret'): string =>
  `passm:item:v1:${itemId}:${part}`;

function sealData(itemId: string, data: SharedItemData): string {
  return encrypt(JSON.stringify(data), itemAad(itemId, 'data'));
}

/** Null when there is nothing worth storing, so `hasSecret` stays honest. */
function sealSecret(itemId: string, secret: SharedItemSecret | undefined): string | null {
  if (!secret || (!secret.password && !secret.totp)) return null;
  return encrypt(JSON.stringify(secret), itemAad(itemId, 'secret'));
}

function openItem(item: StoredSharedItem): SharedVaultItem {
  return {
    id: item.id,
    sharedVaultId: item.sharedVaultId,
    type: item.type,
    data: JSON.parse(decrypt(item.encryptedData, itemAad(item.id, 'data'))) as SharedItemData,
    hasSecret: item.encryptedSecret !== null,
    favorite: item.favorite,
    revision: item.revision,
    updatedByUserId: item.updatedByUserId,
    updatedByName: item.updatedByName,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    deletedAt: item.deletedAt,
  };
}

const RELEASE_ACTION: Record<SecretPurpose, (typeof AUDIT_ACTIONS)[keyof typeof AUDIT_ACTIONS]> = {
  [SECRET_PURPOSE.VIEW]: AUDIT_ACTIONS.ITEM_VIEWED,
  [SECRET_PURPOSE.COPY]: AUDIT_ACTIONS.ITEM_COPIED,
  [SECRET_PURPOSE.FILL]: AUDIT_ACTIONS.ITEM_FILLED,
  [SECRET_PURPOSE.EDIT]: AUDIT_ACTIONS.ITEM_VIEWED,
};

export const sharedVaultService = {
  // -------------------------------------------------------------------------
  // Administration
  // -------------------------------------------------------------------------

  /** Every shared vault. Requires `shared_vault:read`; contents are not included. */
  async listAll(filter: ListSharedVaultsFilter): Promise<PaginatedResult<SharedVault>> {
    const { items, total, page, pageSize } = await sharedVaultRepository.list(filter);
    return paginated(items, total, page, pageSize);
  },

  async getById(id: string, executor?: SqlExecutor): Promise<SharedVault> {
    const vault = await sharedVaultRepository.findById(id, executor);
    if (!vault) throw new NotFoundError('Shared vault not found.');
    return vault;
  },

  /**
   * Create a vault, with the creator as its owner.
   *
   * A vault created with nobody able to administer it would be ungovernable
   * from the moment of creation, so the owner grant is part of the same
   * transaction.
   */
  async create(
    dto: CreateSharedVaultDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVault> {
    this.assertMayChange(actor, context);
    let vaultId: string;
    try {
      vaultId = await withTransaction((tx) =>
        this.createWithOwner(
          {
            name: dto.name,
            description: dto.description ?? null,
            color: dto.color ?? null,
            kind: dto.kind,
            requireApprovalToJoin: dto.requireApprovalToJoin,
            requireApprovalToReveal: dto.requireApprovalToReveal,
          },
          actor.userId,
          tx,
        ),
      );
    } catch (error) {
      if (isDuplicateEntryError(error)) {
        throw new ConflictError(`A shared vault named "${dto.name}" already exists.`);
      }
      throw error;
    }

    await auditService.record({
      action: AUDIT_ACTIONS.SHARED_VAULT_CREATED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      metadata: { sharedVaultId: vaultId, name: dto.name, kind: dto.kind },
    });

    return this.getById(vaultId);
  },

  async update(
    id: string,
    dto: UpdateSharedVaultDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVault> {
    this.assertMayChange(actor, context);
    const existing = await this.getById(id);
    await this.assertCanAdminister(id, actor);

    if (dto.autoGrantRole !== undefined) {
      // Hands the group to everyone who joins the company from now on - a
      // tenant-wide decision, so a group's own admins cannot make it alone.
      if (!actor.permissions.includes(PERMISSIONS.SHARED_VAULT_MANAGE)) {
        throw new ForbiddenError('Only an administrator can make a group a default for new people.');
      }
      if (existing.kind !== VAULT_KIND.GROUP && dto.autoGrantRole !== null) {
        throw new BadRequestError('Only a group can be a default for new people.');
      }
    }

    try {
      const affected = await sharedVaultRepository.update(id, dto);
      if (affected === 0) throw new BadRequestError('Nothing was updated.');
    } catch (error) {
      if (isDuplicateEntryError(error)) {
        throw new ConflictError('Another shared vault already uses that name.');
      }
      throw error;
    }

    await auditService.record({
      action: AUDIT_ACTIONS.SHARED_VAULT_UPDATED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      metadata: {
        sharedVaultId: id,
        previousName: existing.name,
        fields: Object.keys(dto).filter((key) => dto[key as keyof UpdateSharedVaultDto] !== undefined),
      },
    });

    return this.getById(id);
  },

  /** Delete a vault. Every grant goes with it, so access ends at once. */
  async remove(
    id: string,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ revokedGrants: number }> {
    this.assertMayChange(actor, context);
    const vault = await this.getById(id);
    await this.assertCanAdminister(id, actor);

    await withTransaction((tx) => sharedVaultRepository.softDelete(id, tx));

    logger.warn('Shared vault deleted', {
      sharedVaultId: id,
      name: vault.name,
      actorUserId: actor.userId,
    });

    await auditService.record({
      action: AUDIT_ACTIONS.SHARED_VAULT_DELETED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      metadata: {
        sharedVaultId: id,
        name: vault.name,
        itemCount: vault.itemCount,
        revokedGrants: vault.memberCount,
      },
    });

    return { revokedGrants: vault.memberCount };
  },

  // -------------------------------------------------------------------------
  // Membership view
  // -------------------------------------------------------------------------

  /**
   * The caller's shared vaults, with their rights on each.
   *
   * For an administrator that is every vault, with full rights: the console is
   * theirs to run, and a group they were never granted would otherwise be
   * invisible to them - or visible as LP1-style "viewer" from a default grant,
   * and then refuse every change they made to it.
   */
  async listForMember(actor: AuthContext): Promise<MemberSharedVault[]> {
    const userId = actor.userId;

    if (this.isVaultAdministrator(actor)) {
      const vaults = await sharedVaultRepository.listActive();
      return vaults.map((vault) => ({
        ...vault,
        permissions: [...VAULT_ROLE_PERMISSIONS[VAULT_ROLE.OWNER]],
        accessRole: VAULT_ROLE.OWNER,
        restrictions: { ...NO_RESTRICTIONS },
        canReadSecrets: true,
      }));
    }

    const vaults = await sharedVaultRepository.listForUser(userId);

    // Effective access is resolved per vault rather than in one query: merging
    // roles and restrictions is not expressible as a single GROUP BY, and the
    // list one member can see is small by construction.
    return Promise.all(
      vaults.map(async (vault) => {
        const access = await sharedVaultRepository.effectiveAccess(vault.id, userId);
        return {
          ...vault,
          permissions: access.permissions,
          accessRole: access.role,
          restrictions: access.restrictions,
          canReadSecrets: await this.mayReadSecrets(vault, userId, access.restrictions),
        };
      }),
    );
  },

  // -------------------------------------------------------------------------
  // Grants
  // -------------------------------------------------------------------------

  async listGrants(vaultId: string, actor: AuthContext): Promise<SharedVaultGrant[]> {
    await this.getById(vaultId);
    await this.assertCanViewMembership(vaultId, actor);
    return sharedVaultRepository.listGrants(vaultId);
  },

  async addGrant(
    vaultId: string,
    dto: CreateGrantDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVaultGrant[]> {
    this.assertMayChange(actor, context);
    await this.getById(vaultId);
    await this.assertCanChangeMembership(vaultId, actor);

    const subject = await userRepository.findById(dto.subjectId);
    if (!subject) throw new NotFoundError('That user does not exist.');

    const role = dto.role as VaultRole;
    const restrictions: VaultRestrictions = { ...NO_RESTRICTIONS, ...(dto.restrictions ?? {}) };

    await sharedVaultRepository.upsertGrant(
      vaultId, dto.subjectType, dto.subjectId, role, restrictions, actor.userId,
    );

    await auditService.record({
      action: AUDIT_ACTIONS.SHARED_VAULT_GRANT_ADDED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: dto.subjectId,
      context,
      metadata: {
        sharedVaultId: vaultId,
        subjectType: dto.subjectType,
        subjectId: dto.subjectId,
        role,
        valuesHidden: restrictions.hiddenPassword,
        copyOnly: restrictions.copyOnly,
      },
    });

    return sharedVaultRepository.listGrants(vaultId);
  },

  async updateGrant(
    vaultId: string,
    grantId: string,
    dto: UpdateGrantDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVaultGrant[]> {
    this.assertMayChange(actor, context);
    await this.getById(vaultId);
    await this.assertCanChangeMembership(vaultId, actor);

    const grant = await sharedVaultRepository.findGrant(grantId);
    if (!grant || grant.sharedVaultId !== vaultId) throw new NotFoundError('Grant not found.');

    const role = dto.role as VaultRole;
    const restrictions: VaultRestrictions = { ...NO_RESTRICTIONS, ...(dto.restrictions ?? {}) };

    await this.assertNotRemovingLastAdmin(vaultId, grant.id, role);
    await sharedVaultRepository.updateGrantAccess(grantId, role, restrictions);

    await auditService.record({
      action: AUDIT_ACTIONS.SHARED_VAULT_GRANT_UPDATED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: grant.subjectId,
      context,
      metadata: {
        sharedVaultId: vaultId,
        subjectType: grant.subjectType,
        subjectId: grant.subjectId,
        previousRole: grant.accessRole,
        role,
        valuesHidden: restrictions.hiddenPassword,
        copyOnly: restrictions.copyOnly,
        noEdit: restrictions.noEdit,
        noDelete: restrictions.noDelete,
      },
    });

    return sharedVaultRepository.listGrants(vaultId);
  },

  /**
   * Revoke a grant. Access ends with the next request.
   *
   * What this cannot do is un-know a secret. Anyone who has read an item
   * already knows it, so revocation must be followed by rotating the
   * credentials themselves - the console says so at the point of revocation.
   */
  async revokeGrant(
    vaultId: string,
    grantId: string,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ grants: SharedVaultGrant[] }> {
    this.assertMayChange(actor, context);
    await this.getById(vaultId);
    await this.assertCanChangeMembership(vaultId, actor);

    const grant = await sharedVaultRepository.findGrant(grantId);
    if (!grant || grant.sharedVaultId !== vaultId) throw new NotFoundError('Grant not found.');

    await this.assertNotRemovingLastAdmin(vaultId, grantId, null);
    await sharedVaultRepository.removeGrant(grantId);

    await auditService.record({
      action: AUDIT_ACTIONS.SHARED_VAULT_GRANT_REVOKED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: grant.subjectId,
      context,
      metadata: {
        sharedVaultId: vaultId,
        subjectType: grant.subjectType,
        subjectId: grant.subjectId,
      },
    });

    return { grants: await sharedVaultRepository.listGrants(vaultId) };
  },

  // -------------------------------------------------------------------------
  // Items
  // -------------------------------------------------------------------------

  async listItems(
    vaultId: string,
    queryDto: ListSharedItemsQueryDto,
    actor: AuthContext,
  ): Promise<PaginatedResult<SharedVaultItem>> {
    await this.getById(vaultId);
    await this.requireVaultPermission(vaultId, actor, VAULT_PERMISSIONS.READ);

    const { items, total, page, pageSize } = await sharedVaultRepository.listItems(vaultId, {
      page: queryDto.page,
      pageSize: queryDto.pageSize,
      sortBy: queryDto.sortBy,
      sortDir: queryDto.sortDir,
      ...(queryDto.type ? { type: queryDto.type as VaultItemType } : {}),
      ...(queryDto.includeDeleted ? { includeDeleted: true } : {}),
      ...(queryDto.updatedSince ? { updatedSince: queryDto.updatedSince } : {}),
    });

    return paginated(items.map(openItem), total, page, pageSize);
  },

  /**
   * Every vault the caller can see and every live item in them, in one call.
   *
   * The console and the extension used to list each vault separately - one
   * request per group, and every individual password is a vault of its own.
   * Once administrators saw every vault, a single page load could spend most
   * of the per-IP request budget. Same rule as `listItems`: only vaults the
   * caller can READ.
   */
  async listAllItems(
    actor: AuthContext,
  ): Promise<{ vaults: MemberSharedVault[]; items: SharedVaultItem[] }> {
    const vaults = await this.listForMember(actor);
    const readable = vaults
      .filter((vault) => hasVaultPermission(vault.permissions, VAULT_PERMISSIONS.READ))
      .map((vault) => vault.id);

    const items = await sharedVaultRepository.listItemsInVaults(readable);
    return { vaults, items: items.map(openItem) };
  },

  async getItem(vaultId: string, itemId: string, actor: AuthContext): Promise<SharedVaultItem> {
    return openItem(await this.findMemberItem(vaultId, itemId, actor, VAULT_PERMISSIONS.READ));
  },

  /**
   * Release one item's secret.
   *
   * The only path a password leaves the server by. Refused for a member whose
   * grant hides passwords, and for a vault that requires an approved reveal
   * the caller does not hold; recorded in the audit trail with the purpose the
   * client gave, so the trail says "copied" or "filled" rather than only
   * "released".
   */
  async getSecret(
    vaultId: string,
    itemId: string,
    purpose: SecretPurpose,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedItemSecret> {
    const vault = await this.getById(vaultId);
    const item = await this.findMemberItem(vaultId, itemId, actor, VAULT_PERMISSIONS.READ);
    await this.requireSecretAccess(vault, actor);

    const secret = item.encryptedSecret
      ? (JSON.parse(decrypt(item.encryptedSecret, itemAad(item.id, 'secret'))) as SharedItemSecret)
      : {};

    await auditService.record({
      action: RELEASE_ACTION[purpose],
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      resourceType: 'shared_vault',
      resourceId: vaultId,
      isSharedResource: true,
      metadata: { itemId, vaultName: vault.name, purpose },
    });

    return secret;
  },

  async createItem(
    vaultId: string,
    dto: CreateSharedItemDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVaultItem> {
    this.assertMayChange(actor, context);
    const vault = await this.getById(vaultId);
    await this.requireVaultPermission(vaultId, actor, VAULT_PERMISSIONS.EDIT);

    if (vault.status === SHARED_VAULT_STATUS.ARCHIVED) {
      throw new ConflictError('This vault is archived. Restore it before adding items.');
    }
    if (vault.kind === VAULT_KIND.ITEM && vault.itemCount > 0) {
      throw new ConflictError('An individual password holds exactly one entry.');
    }
    if (dto.secret) await this.requireSecretAccess(vault, actor);

    const itemId = await this.storeItem(vaultId, dto, actor.userId);
    await this.auditItem(AUDIT_ACTIONS.ITEM_CREATED, vault, itemId, actor, context, {
      type: dto.type,
    });

    return this.getItem(vaultId, itemId, actor);
  },

  /**
   * Create an individual password: a wrapper vault owned by the caller, and
   * the one item inside it, in one transaction.
   *
   * The wrapper borrows the item's name; vault names are unique, so a clash
   * gets a short suffix rather than an error - two sites can share a title.
   */
  async createIndividualItem(
    dto: CreateSharedItemDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVaultItem> {
    this.assertMayChange(actor, context);
    const { vaultId, itemId } = await withTransaction(async (tx) => {
      const wrapperId = await this.createWrapper(dto.data.name, actor.userId, tx);
      return { vaultId: wrapperId, itemId: await this.storeItem(wrapperId, dto, actor.userId, tx) };
    });

    const vault = await this.getById(vaultId);
    await this.auditItem(AUDIT_ACTIONS.ITEM_CREATED, vault, itemId, actor, context, {
      type: dto.type,
      individual: true,
    });

    return this.getItem(vaultId, itemId, actor);
  },

  async updateItem(
    vaultId: string,
    itemId: string,
    dto: UpdateSharedItemDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVaultItem> {
    this.assertMayChange(actor, context);
    const vault = await this.getById(vaultId);
    await this.findMemberItem(vaultId, itemId, actor, VAULT_PERMISSIONS.EDIT);

    // Writing a password you are not allowed to read would let a hidden member
    // replace a credential they cannot see - refused for the same reason.
    if (dto.secret) await this.requireSecretAccess(vault, actor);

    const affected = await sharedVaultRepository.updateItem(itemId, dto.revision, {
      ...(dto.data ? { encryptedData: sealData(itemId, dto.data) } : {}),
      // Null clears the stored secret; leaving the key out keeps it.
      ...(dto.secret ? { encryptedSecret: sealSecret(itemId, dto.secret) } : {}),
      favorite: dto.favorite,
      actorUserId: actor.userId,
    });
    if (affected === 0) throw staleRevision();

    await this.auditItem(AUDIT_ACTIONS.ITEM_EDITED, vault, itemId, actor, context, {
      // Which parts changed, never their values.
      changedSecret: dto.secret !== undefined,
      changedData: dto.data !== undefined,
    });

    return this.getItem(vaultId, itemId, actor);
  },

  /**
   * Move an item to another group, or out to stand alone.
   *
   * Needs DELETE where it is (it disappears from there) and EDIT where it
   * goes. Access follows the destination immediately. An individual password
   * moved into a group leaves an empty wrapper behind, which is deleted in the
   * same transaction.
   */
  async moveItem(
    vaultId: string,
    itemId: string,
    dto: MoveSharedItemDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVaultItem> {
    this.assertMayChange(actor, context);
    const source = await this.getById(vaultId);
    const stored = await this.findMemberItem(vaultId, itemId, actor, VAULT_PERMISSIONS.DELETE);

    if (dto.targetVaultId === vaultId) {
      throw new BadRequestError('The item is already there.');
    }
    if (dto.targetVaultId === null && source.kind === VAULT_KIND.ITEM) {
      throw new BadRequestError('This password already stands alone.');
    }

    let target: SharedVault | null = null;
    if (dto.targetVaultId !== null) {
      target = await this.getById(dto.targetVaultId);
      if (target.kind !== VAULT_KIND.GROUP) {
        throw new BadRequestError('Passwords can only be moved into a group.');
      }
      await this.requireVaultPermission(target.id, actor, VAULT_PERMISSIONS.EDIT);
    }

    const name = (openItem(stored).data.name || 'Password').trim();

    const destinationId = await withTransaction(async (tx) => {
      const destination = target?.id ?? (await this.createWrapper(name, actor.userId, tx));

      const affected = await sharedVaultRepository.updateItem(
        itemId,
        dto.revision,
        { sharedVaultId: destination, actorUserId: actor.userId },
        tx,
      );
      if (affected === 0) throw staleRevision();

      if (source.kind === VAULT_KIND.ITEM) await sharedVaultRepository.softDelete(vaultId, tx);
      return destination;
    });

    await this.auditItem(AUDIT_ACTIONS.ITEM_EDITED, source, itemId, actor, context, {
      movedTo: destinationId,
      movedToName: target?.name ?? 'Individual',
    });

    return this.getItem(destinationId, itemId, actor);
  },

  /**
   * Delete an item. Deleting an individual password deletes its wrapper too -
   * an empty wrapper would resurface as a phantom entry in access pickers.
   */
  async deleteItem(
    vaultId: string,
    itemId: string,
    permanent: boolean,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ permanent: boolean }> {
    this.assertMayChange(actor, context);
    const vault = await this.getById(vaultId);
    await this.findMemberItem(vaultId, itemId, actor, VAULT_PERMISSIONS.DELETE);

    await withTransaction(async (tx) => {
      if (permanent) await sharedVaultRepository.purgeItem(itemId, tx);
      else await sharedVaultRepository.softDeleteItem(itemId, actor.userId, tx);

      if (vault.kind === VAULT_KIND.ITEM) await sharedVaultRepository.softDelete(vaultId, tx);
    });

    await this.auditItem(AUDIT_ACTIONS.ITEM_DELETED, vault, itemId, actor, context, { permanent });

    return { permanent };
  },

  async restoreItem(
    vaultId: string,
    itemId: string,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<SharedVaultItem> {
    this.assertMayChange(actor, context);
    await this.getById(vaultId);
    await this.requireVaultPermission(vaultId, actor, VAULT_PERMISSIONS.EDIT);

    const affected = await sharedVaultRepository.restoreItem(itemId, actor.userId);
    if (affected === 0) throw new NotFoundError('That item is not in the trash.');

    return this.getItem(vaultId, itemId, actor);
  },

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  async createWithOwner(
    input: Omit<CreateSharedVaultInput, 'createdBy'>,
    ownerId: string,
    executor: SqlExecutor,
  ): Promise<string> {
    const id = await sharedVaultRepository.create({ ...input, createdBy: ownerId }, executor);
    await sharedVaultRepository.upsertGrant(
      id, 'user', ownerId, VAULT_ROLE.OWNER, NO_RESTRICTIONS, ownerId, executor,
    );
    return id;
  },

  /** A wrapper vault for one individual password, retrying past name clashes. */
  async createWrapper(name: string, ownerId: string, executor: SqlExecutor): Promise<string> {
    const base = name.slice(0, 140);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const candidate =
        attempt === 0 ? base : `${base} (${Math.random().toString(36).slice(2, 6)})`;
      try {
        return await this.createWithOwner({ name: candidate, kind: VAULT_KIND.ITEM }, ownerId, executor);
      } catch (error) {
        if (!isDuplicateEntryError(error)) throw error;
      }
    }
    throw new ConflictError('Could not find a free name for this password. Try another name.');
  },

  async storeItem(
    vaultId: string,
    dto: CreateSharedItemDto,
    actorUserId: string,
    executor?: SqlExecutor,
  ): Promise<string> {
    const itemId = newId();
    await sharedVaultRepository.createItem(
      {
        id: itemId,
        sharedVaultId: vaultId,
        type: dto.type as VaultItemType,
        encryptedData: sealData(itemId, dto.data),
        encryptedSecret: sealSecret(itemId, dto.secret),
        favorite: dto.favorite,
        actorUserId,
      },
      executor,
    );
    return itemId;
  },

  /** The stored item, after the permission check and a same-vault check. */
  async findMemberItem(
    vaultId: string,
    itemId: string,
    actor: AuthContext,
    permission: VaultPermission,
  ): Promise<StoredSharedItem> {
    await this.getById(vaultId);
    await this.requireVaultPermission(vaultId, actor, permission);

    const item = await sharedVaultRepository.findItem(itemId);
    // Checking vault membership *and* that the item belongs to that vault: an id
    // from another vault must 404, not fall through to a permission check that
    // happens to pass.
    if (!item || item.sharedVaultId !== vaultId) throw new NotFoundError('Item not found.');
    return item;
  },

  async auditItem(
    action: (typeof AUDIT_ACTIONS)[keyof typeof AUDIT_ACTIONS],
    vault: SharedVault,
    itemId: string,
    actor: AuthContext,
    context: RequestContext,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await auditService.record({
      action,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      resourceType: 'shared_vault',
      resourceId: vault.id,
      isSharedResource: true,
      metadata: { itemId, vaultName: vault.name, ...metadata },
    });
  },

  /**
   * Refuse any change to groups, access or passwords unless it is an
   * administrator, in the console.
   *
   * The extension is read-only for everyone: it fills and copies, nothing more.
   * `fromExtension` is the client's own declaration, so on its own it would
   * only bind an honest client - the role check is what stops a member writing
   * through the API directly, since members can only ever sign in through the
   * extension anyway.
   */
  assertMayChange(actor: AuthContext, context: RequestContext): void {
    if (context.fromExtension) {
      throw new ForbiddenError(
        'Passwords cannot be changed from the browser extension. An administrator changes them in the PassM console.',
      );
    }
    if (actor.role !== ROLES.ADMIN) {
      throw new ForbiddenError('Only an administrator can add or change passwords and groups.');
    }
  },

  /** Whether the server will release this vault's passwords to the user. */
  async mayReadSecrets(
    vault: SharedVault,
    userId: string,
    restrictions: VaultRestrictions,
  ): Promise<boolean> {
    const needsApproval = !entitledToSecrets(restrictions) || vault.requireApprovalToReveal;
    if (!needsApproval) return true;
    return accessRequestRepository.hasApprovedReveal(vault.id, userId);
  },

  async requireSecretAccess(vault: SharedVault, actor: AuthContext): Promise<void> {
    // Hidden passwords and approval-to-reveal govern members. Administrators
    // are the ones who set those rules and approve the requests.
    if (this.isVaultAdministrator(actor)) return;

    const access = await sharedVaultRepository.effectiveAccess(vault.id, actor.userId);
    if (await this.mayReadSecrets(vault, actor.userId, access.restrictions)) return;

    throw new ForbiddenError(
      vault.requireApprovalToReveal && entitledToSecrets(access.restrictions)
        ? 'Passwords in this vault are released only after a reveal request is approved.'
        : 'Passwords in this vault are hidden from you. Ask an administrator if you need access.',
    );
  },

  /**
   * Administrators hold every right on every vault. Grants and restrictions
   * are how administrators govern *members*; applying them to administrators
   * meant one promoted later could not add a password to a group they did not
   * create ("You do not have that level of access to this vault").
   *
   * The same permission the group and access checks below already accept.
   */
  isVaultAdministrator(actor: AuthContext): boolean {
    return actor.permissions.includes(PERMISSIONS.SHARED_VAULT_MANAGE);
  },

  /** Require an object permission on a vault, after its restrictions. */
  async requireVaultPermission(
    vaultId: string,
    actor: AuthContext,
    permission: VaultPermission,
  ): Promise<VaultPermission[]> {
    if (this.isVaultAdministrator(actor)) return [...VAULT_ROLE_PERMISSIONS[VAULT_ROLE.OWNER]];

    const access = await sharedVaultRepository.effectiveAccess(vaultId, actor.userId);

    if (!hasVaultPermission(access.permissions, permission)) {
      throw new ForbiddenError('You do not have that level of access to this vault.');
    }

    // Restrictions subtract from the role, and are checked *after* it. A member
    // whose grant says "editor, no delete" passes the EDIT check and fails here
    // on DELETE - which is the whole point of modelling them separately.
    if (permission === VAULT_PERMISSIONS.EDIT && access.restrictions.noEdit) {
      throw new ForbiddenError('Your access to this vault is read-only.');
    }
    if (permission === VAULT_PERMISSIONS.DELETE && access.restrictions.noDelete) {
      throw new ForbiddenError('You are not permitted to delete items in this vault.');
    }

    return access.permissions;
  },

  /** Administrative control, or the `admin` right on the vault itself. */
  async assertCanAdminister(vaultId: string, actor: AuthContext): Promise<void> {
    if (actor.permissions.includes(PERMISSIONS.SHARED_VAULT_MANAGE)) return;

    const permissions = await sharedVaultRepository.effectivePermissions(vaultId, actor.userId);
    if (hasVaultPermission(permissions, VAULT_PERMISSIONS.ADMIN)) return;

    throw new ForbiddenError('You do not have permission to administer this vault.');
  },

  /** Changing who has access needs `share`, `admin`, or the global permission. */
  async assertCanChangeMembership(vaultId: string, actor: AuthContext): Promise<void> {
    if (actor.permissions.includes(PERMISSIONS.SHARED_VAULT_MANAGE)) return;

    const permissions = await sharedVaultRepository.effectivePermissions(vaultId, actor.userId);
    if (
      hasVaultPermission(permissions, VAULT_PERMISSIONS.SHARE) ||
      hasVaultPermission(permissions, VAULT_PERMISSIONS.ADMIN)
    ) {
      return;
    }

    throw new ForbiddenError('You do not have permission to change access to this vault.');
  },

  /**
   * Seeing the membership list is deliberately looser than changing it.
   *
   * Any member may see who else is in a vault they belong to - a shared
   * credential whose users are hidden from each other cannot be reasoned about
   * by the people responsible for it - and any administrator may see it for
   * governance.
   */
  async assertCanViewMembership(vaultId: string, actor: AuthContext): Promise<void> {
    // `shared_vault:read` is a base permission every account holds - it only
    // admits someone to their own "shared with me" list - so it is deliberately
    // not accepted here. Governance needs `shared_vault:manage`; anything else
    // needs an actual grant on this vault.
    if (actor.permissions.includes(PERMISSIONS.SHARED_VAULT_MANAGE)) return;

    const permissions = await sharedVaultRepository.effectivePermissions(vaultId, actor.userId);
    if (permissions.length > 0) return;

    throw new ForbiddenError('You do not have access to this vault.');
  },

  /**
   * Refuse a change that would leave a vault with no administrator.
   *
   * Without it, one click produces a vault whose grants nobody can edit,
   * recoverable only by a global administrator.
   */
  async assertNotRemovingLastAdmin(
    vaultId: string,
    grantId: string,
    newRole: VaultRole | null,
  ): Promise<void> {
    if (newRole === VAULT_ROLE.OWNER) return;

    const grants = await sharedVaultRepository.listGrants(vaultId);
    const remainingAdmins = grants.filter(
      (grant) =>
        grant.id !== grantId && hasVaultPermission(grant.permissions, VAULT_PERMISSIONS.ADMIN),
    );

    if (remainingAdmins.length === 0) {
      throw new ConflictError(
        'This is the only grant with admin rights on the vault. Give admin to someone else first.',
      );
    }
  },
};

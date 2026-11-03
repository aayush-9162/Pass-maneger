/**
 * The approval workflow.
 *
 * Two things can be requested, and they differ in a way worth being precise
 * about:
 *
 *  - **Access** to a vault. Approving it creates a grant, and the requester
 *    can use the vault at once.
 *  - **A reveal** - the passwords of a vault that hides them from the
 *    requester, or that releases them only on approval. Approving it is the
 *    whole of the change: the secret endpoint consults approved reveals before
 *    it refuses anyone.
 *
 * Who may decide: anyone with `share` or `admin` on the vault, or an
 * administrator holding `approval:decide:any`. A requester may never decide
 * their own request, including when they hold those rights - that check is in
 * `assertCanDecide` and is the one rule the whole workflow rests on.
 */

import {
  AUDIT_ACTIONS,
  PERMISSIONS,
  REQUEST_STATUS,
  REQUEST_TTL_HOURS,
  REQUEST_TYPE,
  VAULT_PERMISSIONS,
  VAULT_ROLE,
  entitledToSecrets,
  hasVaultPermission,
  type AccessRequest,
  type AccessRequestDecision,
  type PaginatedResult,
  type RequestType,
  type VaultRole,
} from '@passm/shared';

import { withTransaction } from '../config/database';
import { logger } from '../config/logger';
import type { CreateAccessRequestDto, DecideAccessRequestDto } from '../dto/collaboration.dto';
import {
  accessRequestRepository,
  type ListRequestsFilter,
} from '../repositories/access-request.repository';
import { sharedVaultRepository } from '../repositories/shared-vault.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import { paginated } from '../utils/api-response';
import { BadRequestError, ConflictError, ForbiddenError, NotFoundError } from '../utils/errors';
import { newId } from '../utils/ids';
import { auditService } from './audit.service';

export const approvalService = {
  /**
   * Raise a request.
   *
   * The preconditions differ by type and both are checked here rather than left
   * to the approver to notice: asking for access you already have, or a reveal
   * on a vault you are not even a member of, are mistakes worth catching before
   * they reach somebody's queue.
   */
  async create(
    sharedVaultId: string,
    dto: CreateAccessRequestDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<AccessRequest> {
    const vault = await sharedVaultRepository.findById(sharedVaultId);
    if (!vault) throw new NotFoundError('Shared vault not found.');

    const access = await sharedVaultRepository.effectiveAccess(sharedVaultId, actor.userId);
    const requestType = dto.requestType as RequestType;

    if (requestType === REQUEST_TYPE.ACCESS && access.hasGrant) {
      throw new ConflictError('You already have access to this vault.');
    }

    if (requestType === REQUEST_TYPE.REVEAL) {
      if (!access.hasGrant) {
        throw new ConflictError(
          'Request access to the vault first - a reveal only applies to a vault you are already in.',
        );
      }
      if (entitledToSecrets(access.restrictions) && !vault.requireApprovalToReveal) {
        throw new ConflictError('Passwords in this vault are not hidden from you.');
      }
    }

    if (requestType === REQUEST_TYPE.ELEVATE && !access.hasGrant) {
      throw new ConflictError('You are not a member of this vault yet.');
    }

    const duplicate = await accessRequestRepository.findPendingDuplicate(
      sharedVaultId,
      actor.userId,
      requestType,
    );
    if (duplicate) {
      throw new ConflictError(
        'You already have a request of this kind waiting for a decision on this vault.',
      );
    }

    const id = newId();
    await accessRequestRepository.create({
      id,
      sharedVaultId,
      requesterUserId: actor.userId,
      requestType,
      requestedRole: (dto.requestedRole as VaultRole | undefined) ?? null,
      itemId: dto.itemId ?? null,
      reason: dto.reason,
      expiresAt: new Date(Date.now() + REQUEST_TTL_HOURS * 3600_000),
    });

    await auditService.record({
      action: AUDIT_ACTIONS.ACCESS_REQUESTED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      resourceType: 'shared_vault',
      resourceId: sharedVaultId,
      isSharedResource: true,
      metadata: { requestId: id, requestType, requestedRole: dto.requestedRole ?? null },
    });

    const created = await accessRequestRepository.findById(id);
    if (!created) throw new NotFoundError('The request could not be read back.');
    return created;
  },

  /**
   * Approve or deny.
   *
   * The status guard lives in the repository's conditional UPDATE, so two
   * approvers clicking at the same instant do not both record a decision - the
   * second is told somebody was first rather than silently overwriting their
   * name on it.
   */
  async decide(
    requestId: string,
    dto: DecideAccessRequestDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<AccessRequestDecision> {
    const request = await accessRequestRepository.findById(requestId);
    if (!request) throw new NotFoundError('Request not found.');

    if (request.status !== REQUEST_STATUS.PENDING) {
      throw new ConflictError(`This request was already ${request.status}.`);
    }
    if (new Date(request.expiresAt).getTime() <= Date.now()) {
      throw new ConflictError('This request has expired. Ask the requester to raise a new one.');
    }

    await this.assertCanDecide(request, actor);

    const status = dto.approve ? REQUEST_STATUS.APPROVED : REQUEST_STATUS.DENIED;

    let grantCreated = false;

    await withTransaction(async (tx) => {
      const affected = await accessRequestRepository.decide(
        requestId,
        status,
        actor.userId,
        dto.note ?? null,
        tx,
      );

      if (affected === 0) {
        throw new ConflictError('Someone else decided this request a moment ago.');
      }

      if (!dto.approve) return;

      if (
        request.requestType === REQUEST_TYPE.ACCESS ||
        request.requestType === REQUEST_TYPE.ELEVATE
      ) {
        // Approving access is creating the grant - nothing else stands between
        // the requester and the vault.
        await sharedVaultRepository.upsertGrant(
          request.sharedVaultId,
          'user',
          request.requesterUserId,
          (request.requestedRole ?? VAULT_ROLE.VIEWER) as VaultRole,
          { hiddenPassword: false, copyOnly: false, noEdit: false, noDelete: false },
          actor.userId,
          tx,
        );
        grantCreated = true;
      }
    });

    await auditService.record({
      action: dto.approve ? AUDIT_ACTIONS.ACCESS_APPROVED : AUDIT_ACTIONS.ACCESS_DENIED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: request.requesterUserId,
      context,
      resourceType: 'shared_vault',
      resourceId: request.sharedVaultId,
      isSharedResource: true,
      metadata: {
        requestId,
        requestType: request.requestType,
        requestedRole: request.requestedRole,
        grantCreated,
      },
    });

    logger.info('Access request decided', {
      requestId,
      status,
      vaultId: request.sharedVaultId,
      requester: request.requesterUserId,
      decidedBy: actor.userId,
    });

    const updated = await accessRequestRepository.findById(requestId);
    if (!updated) throw new NotFoundError('The request could not be read back.');

    return {
      request: updated,
      grantCreated,
      message: !dto.approve
        ? 'Request denied. The requester can see the decision and your note.'
        : request.requestType === REQUEST_TYPE.REVEAL
          ? 'Approved. They can see the passwords in this vault now.'
          : 'Approved and access granted.',
    };
  },

  /** Withdraw one's own pending request. */
  async cancel(
    requestId: string,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<AccessRequest> {
    const request = await accessRequestRepository.findById(requestId);
    if (!request) throw new NotFoundError('Request not found.');

    if (request.requesterUserId !== actor.userId) {
      throw new ForbiddenError('You can only withdraw your own requests.');
    }

    const affected = await accessRequestRepository.cancel(requestId, actor.userId);
    if (affected === 0) {
      throw new ConflictError(`This request was already ${request.status}.`);
    }

    await auditService.record({
      action: AUDIT_ACTIONS.ACCESS_CANCELLED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      context,
      resourceType: 'shared_vault',
      resourceId: request.sharedVaultId,
      isSharedResource: true,
      metadata: { requestId },
    });

    const updated = await accessRequestRepository.findById(requestId);
    if (!updated) throw new NotFoundError('The request could not be read back.');
    return updated;
  },

  /** Requests the caller raised. */
  async listMine(
    actor: AuthContext,
    filter: ListRequestsFilter,
  ): Promise<PaginatedResult<AccessRequest>> {
    const result = await accessRequestRepository.list({
      ...filter,
      requesterUserId: actor.userId,
    });
    return paginated(result.items, result.total, result.page, result.pageSize);
  },

  /**
   * Requests awaiting the caller's decision.
   *
   * An administrator with `approval:decide:any` sees every queue; anybody else
   * sees only vaults they can actually act on, which is computed by asking which
   * of their vaults grant them `share` or `admin`.
   */
  async listForApprover(
    actor: AuthContext,
    filter: ListRequestsFilter,
  ): Promise<PaginatedResult<AccessRequest>> {
    const scope = await this.approvableVaultIds(actor);

    const result = await accessRequestRepository.list({
      ...filter,
      ...(scope === null ? {} : { vaultIds: scope }),
    });

    return paginated(result.items, result.total, result.page, result.pageSize);
  },

  async pendingCount(actor: AuthContext): Promise<number> {
    return accessRequestRepository.countPending(await this.approvableVaultIds(actor));
  },

  /**
   * Vault ids the caller may decide requests on, or `null` for "all of them".
   *
   * `null` rather than an exhaustive list because an administrator's scope is
   * every vault including ones created after this call, and materialising that
   * would be both wasteful and racy.
   */
  async approvableVaultIds(actor: AuthContext): Promise<string[] | null> {
    if (
      actor.permissions.includes(PERMISSIONS.APPROVAL_DECIDE_ANY) ||
      actor.permissions.includes(PERMISSIONS.SHARED_VAULT_MANAGE)
    ) {
      return null;
    }

    const permissionsByVault = await sharedVaultRepository.effectivePermissionsForAll(actor.userId);

    return [...permissionsByVault]
      .filter(
        ([, permissions]) =>
          hasVaultPermission(permissions, VAULT_PERMISSIONS.SHARE) ||
          hasVaultPermission(permissions, VAULT_PERMISSIONS.ADMIN),
      )
      .map(([vaultId]) => vaultId);
  },

  /**
   * May this person decide this request?
   *
   * The self-approval refusal comes first and is unconditional. Without it, any
   * vault admin could grant themselves a reveal on a vault whose passwords are
   * deliberately hidden from them - which would make the whole restriction
   * decorative.
   */
  async assertCanDecide(request: AccessRequest, actor: AuthContext): Promise<void> {
    if (request.requesterUserId === actor.userId) {
      throw new ForbiddenError(
        'You cannot decide your own request. Someone else with access to this vault has to.',
      );
    }

    if (
      actor.permissions.includes(PERMISSIONS.APPROVAL_DECIDE_ANY) ||
      actor.permissions.includes(PERMISSIONS.SHARED_VAULT_MANAGE)
    ) {
      return;
    }

    const access = await sharedVaultRepository.effectiveAccess(
      request.sharedVaultId,
      actor.userId,
    );

    if (
      hasVaultPermission(access.permissions, VAULT_PERMISSIONS.SHARE) ||
      hasVaultPermission(access.permissions, VAULT_PERMISSIONS.ADMIN)
    ) {
      return;
    }

    throw new ForbiddenError('You do not have permission to decide requests on this vault.');
  },

  /** Lapse anything nobody acted on. Called by the maintenance scheduler. */
  async expireStale(): Promise<number> {
    const expired = await accessRequestRepository.expireStale();
    if (expired > 0) logger.info('Access requests expired', { expired });
    return expired;
  },

  /** Guard used by the reveal path, so the DTO layer cannot bypass it. */
  assertReasonGiven(reason: string): void {
    if (reason.trim().length < 10) {
      throw new BadRequestError(
        'Give a real reason - an approver has nothing to judge without one.',
      );
    }
  },
};

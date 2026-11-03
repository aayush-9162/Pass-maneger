/**
 * User administration.
 *
 * Everything here is privileged, so the service enforces guardrails that no
 * amount of route configuration can express:
 *
 *  - An admin cannot change their own role or suspend themselves. Both are
 *    almost always a mistake, and both are irrecoverable without a second admin.
 *  - The last usable administrator cannot be demoted or suspended. Without this
 *    a single click can leave the tenant with no way back in short of direct
 *    database access.
 *  - Any change that alters effective privilege revokes the target's sessions, so
 *    already-issued access tokens (which carry the old role) stop working
 *    immediately rather than at their natural expiry.
 */

import {
  AUDIT_ACTIONS,
  ROLES,
  SESSION_REVOKE_REASON,
  USER_STATUS,
  type AdminUserDetail,
  type AdminUserListItem,
  type DeviceInfo,
  type PaginatedResult,
  type PublicUser,
  type RoleName,
  type SessionInfo,
} from '@passm/shared';

import { withTransaction } from '../config/database';
import { logger } from '../config/logger';
import { toPublicUser } from '../models/user.model';
import { userRepository, type ListUsersFilter } from '../repositories/user.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import type { LockUserDto, UnlockUserDto } from '../dto/admin.dto';
import type {
  ChangeUserRoleDto,
  ChangeUserStatusDto,
  UpdateUserDto,
} from '../dto/user.dto';
import { BadRequestError, ConflictError, NotFoundError } from '../utils/errors';
import { paginated } from '../utils/api-response';
import { toIso } from '../utils/date';
import { auditService } from './audit.service';
import { deviceService } from './device.service';
import { roleRepository } from '../repositories/role.repository';
import { sharedVaultRepository } from '../repositories/shared-vault.repository';
import { sessionService } from './session.service';

export const userService = {
  /** Paginated user list for administrators. */
  async list(filter: ListUsersFilter): Promise<PaginatedResult<AdminUserListItem>> {
    const { items, total, page, pageSize } = await userRepository.list(filter);

    const rows: AdminUserListItem[] = items.map((user) => ({
      ...toPublicUser(user),
      activeSessionCount: user.activeSessionCount,
      trustedDeviceCount: user.trustedDeviceCount,
      lockedUntil: toIso(user.lockedUntil),
      lockReason: user.lockReason,
      sharedVaultCount: user.sharedVaultCount,
    }));

    return paginated(rows, total, page, pageSize);
  },

  /**
   * Everything the console shows on one user's detail page.
   *
   * Assembled from several sources rather than one wide query: the counters
   * come from the same paginated listing used by the directory, so they stay
   * consistent with what the table showed a moment earlier.
   */
  async getDetail(userId: string): Promise<AdminUserDetail> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    const [listing, access, creator] = await Promise.all([
      userRepository.list({ page: 1, pageSize: 1, search: user.email }),
      sharedVaultRepository.accessForUser(userId),
      user.createdBy ? userRepository.findById(user.createdBy) : Promise.resolve(null),
    ]);

    const counters = listing.items.find((row) => row.id === userId);

    return {
      ...toPublicUser(user),
      activeSessionCount: counters?.activeSessionCount ?? 0,
      trustedDeviceCount: counters?.trustedDeviceCount ?? 0,
      lockedUntil: toIso(user.lockedUntil),
      lockReason: user.lockReason,
      sharedVaultCount: counters?.sharedVaultCount ?? 0,
      createdByUserId: user.createdBy,
      createdByName: creator ? `${creator.firstName} ${creator.lastName}`.trim() : null,
      lastLoginIp: user.lastLoginIp,
      access,
    };
  },

  async getById(userId: string): Promise<PublicUser> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');
    return toPublicUser(user);
  },

  /** Update non-privileged profile fields. */
  async updateProfile(
    userId: string,
    dto: UpdateUserDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<PublicUser> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    const affected = await userRepository.updateProfile(userId, dto);
    if (affected === 0) throw new BadRequestError('Nothing was updated.');

    await auditService.record({
      action: AUDIT_ACTIONS.USER_UPDATED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: userId,
      context,
      // Field *names* only: the values are personal data that does not belong in
      // an audit row that many people can read.
      metadata: {
        fields: Object.keys(dto).filter((key) => dto[key as keyof UpdateUserDto] !== undefined),
      },
    });

    const updated = await userRepository.findById(userId);
    if (!updated) throw new NotFoundError('User not found.');
    return toPublicUser(updated);
  },

  /**
   * Change a user's role.
   *
   * Sessions are revoked by default because permissions are embedded in the
   * access token: without revocation a demoted user keeps their old capabilities
   * until their token expires.
   */
  async changeRole(
    userId: string,
    dto: ChangeUserRoleDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<PublicUser> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    if (userId === actor.userId) {
      throw new ConflictError(
        'You cannot change your own role. Ask another administrator to do it.',
      );
    }

    if (user.role === dto.role) {
      throw new BadRequestError(`This user already has the "${dto.role}" role.`);
    }

    await this.assertNotLastAdmin(user.role, userId, 'change the role of');

    const roleId = await roleRepository.requireIdByName(dto.role as RoleName);
    await userRepository.updateRole(userId, roleId);

    const revokedSessions = dto.revokeSessions
      ? await sessionService.revokeAllForUser(userId, SESSION_REVOKE_REASON.ROLE_CHANGED)
      : 0;

    logger.info('User role changed', {
      userId,
      from: user.role,
      to: dto.role,
      actorUserId: actor.userId,
      revokedSessions,
    });

    await auditService.record({
      action: AUDIT_ACTIONS.USER_ROLE_CHANGED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: userId,
      context,
      metadata: { previousRole: user.role, newRole: dto.role, revokedSessions },
    });

    const updated = await userRepository.findById(userId);
    if (!updated) throw new NotFoundError('User not found.');
    return toPublicUser(updated);
  },

  /** Suspend or reactivate an account. */
  async changeStatus(
    userId: string,
    dto: ChangeUserStatusDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<PublicUser> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    if (userId === actor.userId && dto.status === USER_STATUS.SUSPENDED) {
      throw new ConflictError('You cannot suspend your own account.');
    }

    if (dto.status === USER_STATUS.SUSPENDED) {
      await this.assertNotLastAdmin(user.role, userId, 'suspend');
    }

    await userRepository.updateStatus(userId, dto.status);

    // A suspended user must lose access now, not when their token expires.
    const revokedSessions =
      dto.status === USER_STATUS.SUSPENDED
        ? await sessionService.revokeAllForUser(userId, SESSION_REVOKE_REASON.ACCOUNT_DISABLED)
        : 0;

    // Reactivating also lifts any lock, so the user can sign in at once.
    if (dto.status === USER_STATUS.ACTIVE) {
      await userRepository.releaseLock(userId);
    }

    await auditService.record({
      action:
        dto.status === USER_STATUS.SUSPENDED
          ? AUDIT_ACTIONS.USER_DISABLED
          : AUDIT_ACTIONS.USER_UPDATED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: userId,
      context,
      metadata: {
        previousStatus: user.status,
        newStatus: dto.status,
        revokedSessions,
        reason: dto.reason ?? null,
      },
    });

    logger.info('User status changed', {
      userId,
      from: user.status,
      to: dto.status,
      actorUserId: actor.userId,
    });

    const updated = await userRepository.findById(userId);
    if (!updated) throw new NotFoundError('User not found.');
    return toPublicUser(updated);
  },

  /**
   * Lock an account administratively.
   *
   * Distinct from the automatic failed-login lockout in two ways that matter: it
   * does not expire unless an end time is given, and it carries a reason that is
   * shown to whoever unlocks it later. Both exist because an administrative lock
   * is a decision somebody made, and the person lifting it weeks later needs to
   * know what that decision was.
   */
  async lock(
    userId: string,
    dto: LockUserDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ user: PublicUser; revokedSessions: number }> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    if (userId === actor.userId) {
      throw new ConflictError('You cannot lock your own account.');
    }

    await this.assertNotLastAdmin(user.role, userId, 'lock');

    // Indefinite is represented as a date far enough out that the login path's
    // existing "is the lock still in force" comparison covers both cases with
    // one rule, rather than a nullable column two code paths must agree on.
    const until = dto.until
      ? new Date(dto.until)
      : new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000);

    await userRepository.applyAdministrativeLock(userId, until, dto.reason, actor.userId);

    const revokedSessions = dto.revokeSessions
      ? await sessionService.revokeAllForUser(userId, SESSION_REVOKE_REASON.ADMIN_REVOKE)
      : 0;

    logger.warn('User locked by administrator', {
      userId,
      actorUserId: actor.userId,
      indefinite: dto.until === undefined,
      revokedSessions,
    });

    await auditService.record({
      action: AUDIT_ACTIONS.USER_LOCKED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: userId,
      context,
      metadata: {
        reason: dto.reason,
        until: dto.until ?? 'indefinite',
        revokedSessions,
      },
    });

    const updated = await userRepository.findById(userId);
    if (!updated) throw new NotFoundError('User not found.');
    return { user: toPublicUser(updated), revokedSessions };
  },

  /** Lift a lock of either kind. */
  async unlock(
    userId: string,
    dto: UnlockUserDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<PublicUser> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    if (user.status === USER_STATUS.SUSPENDED) {
      // Unlocking a suspended account would look like it worked and change
      // nothing, because suspension blocks sign-in independently.
      throw new ConflictError('This account is suspended, not locked. Reactivate it instead.');
    }

    await userRepository.releaseLock(userId);

    await auditService.record({
      action: AUDIT_ACTIONS.USER_UNLOCKED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: userId,
      context,
      metadata: {
        previousLockReason: user.lockReason ?? 'automatic lockout',
        note: dto.note ?? null,
      },
    });

    logger.info('User unlocked', { userId, actorUserId: actor.userId });

    const updated = await userRepository.findById(userId);
    if (!updated) throw new NotFoundError('User not found.');
    return toPublicUser(updated);
  },

  /** Sessions for any user (admin/manager oversight). */
  async listSessions(userId: string): Promise<SessionInfo[]> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');
    return sessionService.listForUser(userId);
  },

  /** Devices for any user (admin/manager oversight). */
  async listDevices(userId: string): Promise<DeviceInfo[]> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');
    return deviceService.listForUser(userId);
  },

  /** Force-sign-out every session of a user. */
  async revokeAllSessions(
    userId: string,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ revokedSessions: number }> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    const revokedSessions = await sessionService.revokeAllForUser(
      userId,
      SESSION_REVOKE_REASON.ADMIN_REVOKE,
    );

    await auditService.record({
      action: AUDIT_ACTIONS.SESSION_REVOKED_ALL,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: userId,
      context,
      metadata: { revokedSessions },
    });

    return { revokedSessions };
  },

  /**
   * Delete an account completely: sessions ended, grants revoked, the row
   * soft-deleted and its email freed.
   *
   * The passwords themselves are untouched - they belong to the organisation
   * and live in their groups. Only this person's access to them ends.
   */
  async deleteUser(
    userId: string,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ revokedSessions: number; revokedGrants: number }> {
    const user = await userRepository.findById(userId);
    if (!user) throw new NotFoundError('User not found.');

    if (user.id === actor.userId) {
      throw new BadRequestError(
        'You cannot delete your own account. Ask another administrator.',
      );
    }
    await this.assertNotLastAdmin(user.role, userId, 'delete');

    const revokedSessions = await sessionService.revokeAllForUser(
      userId,
      SESSION_REVOKE_REASON.ACCOUNT_DISABLED,
    );

    const { revokedGrants } = await withTransaction(async (tx) => {
      const removed = await sharedVaultRepository.removeAccessForUser(userId, tx);
      await userRepository.softDelete(userId, tx);
      return removed;
    });

    logger.warn('User deleted', {
      userId,
      email: user.email,
      role: user.role,
      actorUserId: actor.userId,
      revokedSessions,
      revokedGrants,
    });

    await auditService.record({
      action: AUDIT_ACTIONS.USER_DELETED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: userId,
      context,
      metadata: { email: user.email, role: user.role, revokedSessions, revokedGrants },
    });

    return { revokedSessions, revokedGrants };
  },

  // -------------------------------------------------------------------------
  // Guardrails
  // -------------------------------------------------------------------------

  /**
   * Refuse an operation that would remove the last usable administrator.
   *
   * @param currentRole Role the target holds *now*.
   * @param verb Used in the error message, e.g. "suspend".
   */
  async assertNotLastAdmin(
    currentRole: RoleName,
    _targetUserId: string,
    verb: string,
  ): Promise<void> {
    if (currentRole !== ROLES.ADMIN) return;

    const usableAdmins = await userRepository.countUsableByRole(ROLES.ADMIN);
    if (usableAdmins <= 1) {
      throw new ConflictError(
        `You cannot ${verb} the only administrator account. Promote another user to administrator first.`,
      );
    }
  },
};

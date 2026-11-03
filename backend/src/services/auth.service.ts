/**
 * Authentication orchestration: Google sign-in, refresh, logout, profile and
 * provisioning.
 *
 * This service composes the focused services (Google identity, token, session,
 * device, audit) and owns the *policy* decisions. Controllers
 * stay thin: they translate HTTP to a call here and a response back, nothing
 * more.
 *
 * ## Google is the only credential
 *
 * There is no PassM password. A Google ID token, verified against Google's
 * keys and restricted to the allowed Workspace domains, is the whole of sign-in;
 * brute-force protection, MFA and account recovery are Google's. What remains
 * here is everything that is PassM's own decision: whether the account is
 * locked or suspended, whether it may use the console, and the session that
 * follows.
 */

import {
  AUDIT_ACTIONS,
  ERROR_CODES,
  ROLES,
  SESSION_REVOKE_REASON,
  USER_STATUS,
  permissionsForRole,
  type LoginResponse,
  type ProfileResponse,
  type RefreshResponse,
  type RoleName,
} from '@passm/shared';

import { withTransaction, type SqlExecutor } from '../config/database';
import { env } from '../config/env';
import { logger } from '../config/logger';
import { personNameSchema } from '../dto/common.dto';
import { isDeviceTrusted } from '../models/device.model';
import { toPublicUser, type UserRecord } from '../models/user.model';
import { deviceRepository } from '../repositories/device.repository';
import { loginAttemptRepository } from '../repositories/login-attempt.repository';
import { roleRepository } from '../repositories/role.repository';
import { sharedVaultRepository } from '../repositories/shared-vault.repository';
import { sessionRepository } from '../repositories/session.repository';
import { userRepository } from '../repositories/user.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import type { GoogleLoginDto, RegisterDto } from '../dto/auth.dto';
import {
  AccountDisabledError,
  AccountLockedError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  UnauthorizedError,
} from '../utils/errors';
import { secondsUntil, toIso, toIsoRequired } from '../utils/date';
import { isDuplicateEntryError } from '../utils/sql';
import { auditService } from './audit.service';
import { deviceService } from './device.service';
import { googleIdentityService, type GoogleIdentity } from './google-identity.service';
import { notificationService } from './notification.service';
import { securitySettingsService } from './security-settings.service';
import { sessionService } from './session.service';
import { signAccessToken } from './token.service';

/** Reasons recorded in `login_attempts.failure_reason` and the audit trail. */
const FAILURE_REASON = {
  GOOGLE_REJECTED: 'google_rejected',
  GOOGLE_ACCOUNT_MISMATCH: 'google_account_mismatch',
  ACCOUNT_LOCKED: 'account_locked',
  ACCOUNT_SUSPENDED: 'account_suspended',
} as const;

/** A name from Google, if it passes the same rules a typed name must. */
function acceptableName(value: string): string | null {
  const parsed = personNameSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export interface LoginResult {
  response: LoginResponse;
  /** Set as an httpOnly cookie by the controller (or returned to the extension). */
  refreshToken: string;
  refreshTokenTtlSeconds: number;
  /** Present only when "remember this device" was granted during this login. */
  deviceTrust: { token: string; ttlSeconds: number } | null;
}

export interface RefreshResult {
  response: RefreshResponse;
  refreshToken: string;
  refreshTokenTtlSeconds: number;
}

export const authService = {
  // =========================================================================
  // POST /google
  // =========================================================================

  /**
   * Sign in with a Google ID token.
   *
   * The token is verified first (signature, audience, expiry, verified email,
   * allowed domain) - see `google-identity.service`. Only then is it resolved to
   * a PassM account: by the linked Google account id, else by email, linking it
   * on that first sign-in, else by creating a new account.
   *
   * After that the checks are the ones every sign-in has always faced - locks,
   * suspension, console access - and the session is issued the same way.
   */
  async loginWithGoogle(
    dto: GoogleLoginDto,
    context: RequestContext,
    options: {
      deviceIdentity?: import('@passm/shared').DeviceIdentity | null;
      trustCookie?: string;
      /** True when the caller identified itself as the browser extension. */
      fromExtension?: boolean;
    } = {},
  ): Promise<LoginResult> {
    let identity: GoogleIdentity;
    try {
      identity = await googleIdentityService.verifyIdToken(dto.credential);
    } catch (error) {
      await auditService.recordFailure({
        action: AUDIT_ACTIONS.LOGIN_FAILED,
        context,
        metadata: { reason: FAILURE_REASON.GOOGLE_REJECTED },
      });
      throw error;
    }

    const user = await this.resolveGoogleAccount(identity, context);
    const email = user.email;

    // --- Administrative lock ----------------------------------------------
    if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
      const retryAfter = secondsUntil(user.lockedUntil);

      await loginAttemptRepository.insert({
        email,
        ipAddress: context.ipAddress,
        userId: user.id,
        successful: false,
        failureReason: FAILURE_REASON.ACCOUNT_LOCKED,
        userAgent: context.userAgent,
      });
      await auditService.recordFailure({
        action: AUDIT_ACTIONS.LOGIN_BLOCKED_LOCKED,
        actorUserId: user.id,
        actorEmail: user.email,
        context,
        metadata: { retryAfterSeconds: retryAfter },
      });

      throw new AccountLockedError(retryAfter);
    }

    // A lock that has run out is lifted here rather than by a background job,
    // so nobody is kept out longer than the administrator asked for.
    if (user.lockedUntil) {
      await userRepository.releaseLock(user.id);
      await auditService.record({
        action: AUDIT_ACTIONS.USER_UNLOCKED,
        actorUserId: user.id,
        actorEmail: user.email,
        targetUserId: user.id,
        context,
        metadata: { reason: 'lock_expired' },
      });
    }

    // --- Administratively disabled ----------------------------------------
    if (user.status === USER_STATUS.SUSPENDED) {
      await loginAttemptRepository.insert({
        email,
        ipAddress: context.ipAddress,
        userId: user.id,
        successful: false,
        failureReason: FAILURE_REASON.ACCOUNT_SUSPENDED,
        userAgent: context.userAgent,
      });
      await auditService.recordFailure({
        action: AUDIT_ACTIONS.LOGIN_FAILED,
        actorUserId: user.id,
        actorEmail: user.email,
        context,
        metadata: { reason: FAILURE_REASON.ACCOUNT_SUSPENDED },
      });

      throw new AccountDisabledError();
    }

    /*
     * --- Console access ----------------------------------------------------
     *
     * Honest about what it is: the caller declares its own client type, so a
     * determined user could present themselves as the extension. It is an access
     * policy that keeps people out of a console with nothing in it for them, not
     * a boundary. The real containment is that a non-administrator cannot reveal
     * or copy anything they were not granted.
     */
    if (!options.fromExtension && user.role !== ROLES.ADMIN) {
      const adminsOnly = await securitySettingsService.get('webConsoleAdminsOnly');

      if (adminsOnly) {
        await auditService.recordFailure({
          action: AUDIT_ACTIONS.LOGIN_FAILED,
          actorUserId: user.id,
          actorEmail: user.email,
          context,
          metadata: { reason: 'web_console_admins_only', role: user.role },
        });

        throw new ForbiddenError(
          'The web console is for administrators. Use the PassM browser extension to sign in ' +
            'and fill your passwords.',
        );
      }
    }

    return this.completeLogin(user, dto, context, options);
  },

  /**
   * The PassM account a verified Google identity signs in to.
   *
   * Matched by Google account id first, because an email address can be
   * reassigned to a different person while the id cannot. A match by email is
   * linked on the spot; an account already linked to a *different* Google
   * account is refused rather than relinked, since that is exactly what a
   * recycled address looks like.
   */
  async resolveGoogleAccount(identity: GoogleIdentity, context: RequestContext): Promise<UserRecord> {
    const linked = await userRepository.findByGoogleSubject(identity.subject);
    if (linked) return linked;

    const existing = await userRepository.findByEmail(identity.email);
    if (!existing) return this.createFromGoogle(identity, context);

    if (existing.googleSubject) {
      await auditService.recordFailure({
        action: AUDIT_ACTIONS.LOGIN_FAILED,
        actorUserId: existing.id,
        actorEmail: existing.email,
        context,
        metadata: { reason: FAILURE_REASON.GOOGLE_ACCOUNT_MISMATCH },
      });
      throw new ForbiddenError(
        'This PassM account belongs to a different Google account. Ask an administrator to remove ' +
          'the old account so you can sign in fresh.',
      );
    }

    await userRepository.linkGoogleSubject(existing.id, identity.subject);
    logger.info('Linked a Google account on first Google sign-in', { userId: existing.id });

    return { ...existing, googleSubject: identity.subject };
  },

  /**
   * Create an account for a first-time Google sign-in from an allowed domain.
   *
   * Every new account is a member: an administrator raises the role from the
   * People page.
   */
  async createFromGoogle(identity: GoogleIdentity, context: RequestContext): Promise<UserRecord> {
    const roleId = await roleRepository.requireIdByName(ROLES.EMPLOYEE);
    const localPart = identity.email.slice(0, identity.email.indexOf('@')).split(/[._-]/)[0] ?? '';

    try {
      const userId = await withTransaction(async (tx) => {
        const createdId = await userRepository.create(
          {
            email: identity.email,
            firstName:
              acceptableName(identity.givenName) ??
              acceptableName(localPart.charAt(0).toUpperCase() + localPart.slice(1)) ??
              'Member',
            lastName: acceptableName(identity.familyName) ?? '',
            roleId,
            // `pending` until the sign-in that created it completes.
            status: USER_STATUS.PENDING,
          },
          tx,
        );

        await userRepository.linkGoogleSubject(createdId, identity.subject, tx);
        await this.grantDefaultGroups(createdId, identity.email, null, context, tx);

        await auditService.record(
          {
            action: AUDIT_ACTIONS.USER_AUTO_PROVISIONED,
            actorUserId: createdId,
            actorEmail: identity.email,
            targetUserId: createdId,
            context,
            metadata: { role: ROLES.EMPLOYEE, email: identity.email },
          },
          tx,
        );

        return createdId;
      });

      const created = await userRepository.findById(userId);
      if (!created) throw new NotFoundError('The account was created but could not be read back.');

      logger.info('Account created by first Google sign-in', { userId });
      return created;
    } catch (error) {
      if (isDuplicateEntryError(error)) {
        // Two first sign-ins racing, or a deleted account still holding the
        // address. Either way the address is taken.
        throw new ConflictError('An account with this email address already exists.');
      }
      throw error;
    }
  },

  /** Register the device, issue the session and tokens, and record the sign-in. */
  async completeLogin(
    user: UserRecord,
    dto: Pick<GoogleLoginDto, 'rememberDevice' | 'device'>,
    context: RequestContext,
    options: {
      deviceIdentity?: import('@passm/shared').DeviceIdentity | null;
      trustCookie?: string;
    },
  ): Promise<LoginResult> {
    await userRepository.recordSuccessfulLogin(user.id, context.ipAddress);

    const registered = await deviceService.registerForLogin({
      userId: user.id,
      identity: options.deviceIdentity ?? dto.device ?? null,
      context,
    });

    /**
     * A device the user has never signed in from before.
     *
     * This is the single most useful alert in the product: the server cannot
     * tell a stolen Google session from a legitimate one, but the person it
     * belongs to can, immediately, from "a Windows machine in the London office
     * signed in as you".
     */
    if (registered.isNew) {
      void notificationService.notifyNewDevice(
        user.id,
        registered.device.name,
        context.ipAddress,
      );
    }

    // Trust is granted only here, on a successful sign-in.
    let deviceTrust: LoginResult['deviceTrust'] = null;
    let trusted = false;
    let trustExpiresAt: Date | null = null;

    if (dto.rememberDevice) {
      const granted = await deviceService.grantTrust({
        userId: user.id,
        device: registered.device,
        context,
      });
      if (granted) {
        deviceTrust = { token: granted.trustToken, ttlSeconds: granted.expiresInSeconds };
        trusted = true;
        // Taken from the grant, not from `registered.device`: that record was
        // read before the grant was written and still carries a null expiry.
        trustExpiresAt = granted.expiresAt;
      }
    } else {
      // Not asked for, but an earlier grant may still be valid.
      trusted = await deviceService.verifyTrust({
        trustToken: options.trustCookie,
        userId: user.id,
        deviceRowId: registered.device.id,
      });
      if (trusted) trustExpiresAt = registered.device.trustExpiresAt;
    }

    const session = await sessionService.createSession({
      userId: user.id,
      deviceRowId: registered.device.id,
      context,
    });

    const accessToken = signAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: permissionsForRole(user.role),
      sessionId: session.sessionId,
      deviceRowId: registered.device.id,
      deviceTrusted: trusted,
    });

    await loginAttemptRepository.insert({
      email: user.email,
      ipAddress: context.ipAddress,
      userId: user.id,
      successful: true,
      userAgent: context.userAgent,
    });
    await auditService.record({
      action: AUDIT_ACTIONS.LOGIN_SUCCESS,
      actorUserId: user.id,
      actorEmail: user.email,
      sessionId: session.sessionId,
      deviceId: registered.device.id,
      context,
      metadata: {
        method: 'google',
        role: user.role,
        deviceTrusted: trusted,
        newDevice: registered.isNew,
        rememberDevice: dto.rememberDevice,
      },
    });

    // Reflect the writes made above without a second SELECT.
    const freshUser: UserRecord = {
      ...user,
      lastLoginAt: new Date(),
      status: user.status === USER_STATUS.PENDING ? USER_STATUS.ACTIVE : user.status,
    };

    return {
      response: {
        user: toPublicUser(freshUser),
        tokens: {
          accessToken: accessToken.token,
          expiresIn: accessToken.expiresInSeconds,
          tokenType: 'Bearer',
        },
        session: {
          id: session.sessionId,
          expiresAt: toIsoRequired(session.expiresAt),
        },
        device: {
          id: registered.device.id,
          deviceId: registered.deviceId,
          trusted,
          isNew: registered.isNew,
          trustExpiresAt: toIso(trustExpiresAt),
        },
      },
      refreshToken: session.refreshToken,
      refreshTokenTtlSeconds: env.jwt.refreshTtlSeconds,
      deviceTrust,
    };
  },

  // =========================================================================
  // POST /refresh
  // =========================================================================

  async refresh(refreshToken: string, context: RequestContext): Promise<RefreshResult> {
    // Verifies, detects replay and atomically rotates.
    const rotated = await sessionService.rotate(refreshToken, context);
    const session = rotated.session;

    const user = await userRepository.findById(session.userId);
    if (!user) {
      // The account was deleted while the session lived on.
      await sessionService.revoke(session.id, SESSION_REVOKE_REASON.ACCOUNT_DISABLED);
      throw new UnauthorizedError('Your account is no longer available.', ERROR_CODES.SESSION_REVOKED);
    }

    // Status is re-checked on every refresh, so suspending an account takes
    // effect within one access-token lifetime rather than at session expiry.
    if (user.status === USER_STATUS.SUSPENDED) {
      await sessionService.revokeAllForUser(user.id, SESSION_REVOKE_REASON.ACCOUNT_DISABLED);
      await auditService.recordFailure({
        action: AUDIT_ACTIONS.TOKEN_REFRESHED,
        actorUserId: user.id,
        actorEmail: user.email,
        sessionId: session.id,
        context,
        metadata: { reason: 'account_suspended' },
      });
      throw new AccountDisabledError();
    }

    const device = session.deviceRowId
      ? await deviceRepository.findById(session.deviceRowId)
      : null;
    const trusted = device !== null && isDeviceTrusted(device);

    if (device) {
      await deviceRepository.touch(device.id, context.ipAddress, context.userAgent);
    }

    const accessToken = signAccessToken({
      userId: user.id,
      email: user.email,
      // Re-read from the database: a role change is picked up on the next
      // refresh even for a session that was not revoked.
      role: user.role,
      permissions: permissionsForRole(user.role),
      sessionId: session.id,
      deviceRowId: device?.id ?? session.deviceRowId ?? '',
      deviceTrusted: trusted,
    });

    await auditService.record({
      action: AUDIT_ACTIONS.TOKEN_REFRESHED,
      actorUserId: user.id,
      actorEmail: user.email,
      sessionId: session.id,
      deviceId: device?.id ?? null,
      context,
      metadata: { generation: session.refreshTokenGeneration },
    });

    return {
      response: {
        user: toPublicUser(user),
        tokens: {
          accessToken: accessToken.token,
          expiresIn: accessToken.expiresInSeconds,
          tokenType: 'Bearer',
        },
        session: {
          id: session.id,
          expiresAt: toIsoRequired(session.expiresAt),
        },
        device: {
          id: device?.id ?? '',
          deviceId: device?.deviceId ?? '',
          trusted,
        },
      },
      refreshToken: rotated.refreshToken,
      refreshTokenTtlSeconds: env.jwt.refreshTtlSeconds,
    };
  },

  // =========================================================================
  // POST /logout
  // =========================================================================

  /**
   * End the current session, or every session for the user.
   *
   * Idempotent: logging out an already-revoked session succeeds. A logout that
   * can fail encourages clients to retry, or worse, to keep the token.
   */
  async logout(params: {
    auth: AuthContext;
    allDevices: boolean;
    context: RequestContext;
  }): Promise<{ revokedSessions: number }> {
    const { auth, allDevices, context } = params;

    const revokedSessions = allDevices
      ? await sessionService.revokeAllForUser(auth.userId, SESSION_REVOKE_REASON.USER_LOGOUT_ALL)
      : (await sessionService.revoke(auth.sessionId, SESSION_REVOKE_REASON.USER_LOGOUT))
        ? 1
        : 0;

    await auditService.record({
      action: allDevices ? AUDIT_ACTIONS.SESSION_REVOKED_ALL : AUDIT_ACTIONS.LOGOUT,
      actorUserId: auth.userId,
      actorEmail: auth.email,
      sessionId: auth.sessionId,
      deviceId: auth.deviceRowId,
      context,
      metadata: { allDevices, revokedSessions },
    });

    return { revokedSessions };
  },

  // =========================================================================
  // GET /profile
  // =========================================================================

  async profile(auth: AuthContext): Promise<ProfileResponse> {
    const user = await userRepository.findById(auth.userId);
    if (!user) throw new NotFoundError('Your account could not be found.');

    const session = await sessionRepository.findById(auth.sessionId);
    if (!session) {
      throw new UnauthorizedError('Your session is no longer valid.', ERROR_CODES.SESSION_REVOKED);
    }

    const device = auth.deviceRowId ? await deviceRepository.findById(auth.deviceRowId) : null;

    return {
      user: toPublicUser(user),
      session: {
        id: session.id,
        ipAddress: session.ipAddress,
        createdAt: toIsoRequired(session.createdAt),
        lastActivityAt: toIsoRequired(session.lastActivityAt),
        expiresAt: toIsoRequired(session.expiresAt),
      },
      device: device
        ? {
            id: device.id,
            deviceId: device.deviceId,
            name: device.name,
            platform: device.platform,
            trusted: isDeviceTrusted(device),
          }
        : null,
    };
  },

  // =========================================================================
  // POST /register  (admin only)
  // =========================================================================

  /**
   * Create an account ahead of its owner's first Google sign-in.
   *
   * Accounts from the allowed domain are created automatically when someone
   * first signs in, so this is for the cases that cannot wait for that: giving
   * someone the administrator role, or access to passwords before day one. The
   * route enforces the admin permission and the check is repeated here, so a
   * future routing mistake cannot open a registration hole.
   *
   * The user record and its audit entry are written in one transaction: an
   * account with no trace of who created it is not one to leave behind.
   */
  async register(
    dto: RegisterDto,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<import('@passm/shared').PublicUser> {
    if (actor.role !== ROLES.ADMIN) {
      throw new ForbiddenError(
        'Only administrators can create accounts.',
        ERROR_CODES.INSUFFICIENT_ROLE,
      );
    }

    const roleId = await roleRepository.requireIdByName(dto.role as RoleName);

    try {
      const userId = await withTransaction(async (tx) => {
        const createdId = await userRepository.create(
          {
            email: dto.email,
            firstName: dto.firstName,
            lastName: dto.lastName,
            roleId,
            // `pending` until the first Google sign-in promotes it to active.
            status: USER_STATUS.PENDING,
            jobTitle: dto.jobTitle,
            createdBy: actor.userId,
          },
          tx,
        );

        await this.grantDefaultGroups(createdId, dto.email, actor, context, tx);

        await auditService.record(
          {
            action: AUDIT_ACTIONS.USER_CREATED,
            actorUserId: actor.userId,
            actorEmail: actor.email,
            targetUserId: createdId,
            context,
            metadata: { role: dto.role, email: dto.email },
          },
          tx,
        );

        return createdId;
      });

      const created = await userRepository.findById(userId);
      if (!created) throw new NotFoundError('The account was created but could not be read back.');

      logger.info('User provisioned', {
        userId,
        role: dto.role,
        createdBy: actor.userId,
      });

      return toPublicUser(created);
    } catch (error) {
      // Relying on the unique index rather than a pre-check removes the race
      // window between "does it exist?" and "insert it".
      if (isDuplicateEntryError(error)) {
        throw new ConflictError('An account with that email address already exists.');
      }
      throw error;
    }
  },

  /**
   * Give a brand-new account every default group, and record each grant.
   *
   * Runs inside the account-creation transaction, so an account never exists
   * without the access the administrators said every new person gets.
   */
  async grantDefaultGroups(
    userId: string,
    email: string,
    actor: AuthContext | null,
    context: RequestContext,
    tx: SqlExecutor,
  ): Promise<void> {
    const granted = await sharedVaultRepository.grantDefaultGroups(userId, tx);

    for (const grant of granted) {
      await auditService.record(
        {
          action: AUDIT_ACTIONS.SHARED_VAULT_GRANT_ADDED,
          actorUserId: actor?.userId ?? userId,
          actorEmail: actor?.email ?? email,
          targetUserId: userId,
          context,
          metadata: {
            sharedVaultId: grant.vaultId,
            name: grant.name,
            role: grant.role,
            reason: 'default_group',
          },
        },
        tx,
      );
    }
  },
};

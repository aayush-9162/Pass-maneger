/**
 * Session lifecycle: creation, validation, refresh-token rotation, revocation.
 *
 * ## Design
 *
 * A session is a database row. Access tokens are stateless JWTs, but
 * {@link sessionService.validateForRequest} checks the row on every request, so
 * "sign out everywhere" and admin revocation take effect immediately instead of
 * waiting out the access token's TTL. The row is also what makes idle timeout
 * and per-user session caps enforceable.
 *
 * ## Refresh token rotation with reuse detection
 *
 * Each refresh mints a new token and demotes the old hash to
 * `previous_refresh_token_hash`. Presenting an already-redeemed token therefore
 * hits a known-but-superseded hash, which means the token leaked (a legitimate
 * client never replays one). The response is to revoke *every* session for that
 * user: the plausible leak vectors - stolen cookie, XSS, exfiltrated storage -
 * rarely affect only one session, so containment is worth the forced re-login.
 *
 * ## Caching
 *
 * Session lookups are cached for {@link SESSION_CACHE_TTL_SECONDS}. Revocation
 * invalidates the entry, so with Redis the effect is immediate cluster-wide.
 * With the in-process fallback cache a revocation on one PM2 worker is not seen
 * by its siblings, so a revoked session can survive up to the TTL there. That is
 * the concrete reason to run Redis in any multi-worker deployment.
 */

import {
  AUDIT_ACTIONS,
  SESSION_REVOKE_REASON,
  SESSION_STATUS,
  type SessionInfo,
  type SessionRevokeReason,
} from '@passm/shared';

import { CACHE_KEYS, getCache } from '../config/cache';
import { env } from '../config/env';
import { logger } from '../config/logger';
import {
  isSessionUsable,
  toCachedSession,
  toSessionInfo,
  type CachedSession,
  type SessionRecord,
} from '../models/session.model';
import { sessionRepository } from '../repositories/session.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import { NotFoundError, UnauthorizedError } from '../utils/errors';
import { ERROR_CODES } from '@passm/shared';
import { auditService } from './audit.service';
import { hashToken } from './crypto.service';
import { newId } from '../utils/ids';
import { secondsFromNow } from '../utils/date';
import { securitySettingsService } from './security-settings.service';
import { signRefreshToken, verifyRefreshToken } from './token.service';

/** Deliberately short: bounds how long a revoked session can survive a stale cache. */
const SESSION_CACHE_TTL_SECONDS = 15;

/** Minimum interval between `last_activity_at` writes for one session. */
const ACTIVITY_WRITE_THROTTLE_SECONDS = 60;

export interface CreatedSession {
  sessionId: string;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
  expiresAt: Date;
}

export interface RotatedSession {
  session: SessionRecord;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
}

async function cacheSession(session: SessionRecord): Promise<void> {
  try {
    await getCache().set(
      CACHE_KEYS.session(session.id),
      toCachedSession(session),
      SESSION_CACHE_TTL_SECONDS,
    );
  } catch (error) {
    // The cache is an optimisation; MySQL remains authoritative.
    logger.debug('Failed to cache session', { sessionId: session.id, error });
  }
}

async function invalidateSessionCache(sessionId: string): Promise<void> {
  try {
    await getCache().del(CACHE_KEYS.session(sessionId), CACHE_KEYS.sessionActivity(sessionId));
  } catch (error) {
    logger.warn('Failed to invalidate session cache', { sessionId, error });
  }
}

/**
 * Has the session been idle longer than policy allows?
 *
 * The limit is passed in rather than read here: it comes from the runtime
 * settings store, whose read is async, and these callers are on the hot path
 * for every authenticated request. Resolving it once at the top of the caller
 * keeps this a pure comparison.
 */
function isIdleExpired(lastActivityAtMs: number, idleLimitMinutes: number): boolean {
  return Date.now() - lastActivityAtMs > idleLimitMinutes * 60_000;
}

/**
 * Has the session been alive longer than the absolute limit, whatever the user
 * has been doing?
 *
 * `createdAtMs` is absent only on a snapshot cached by an older build. Skipping
 * the check in that case is deliberate: the alternative compares against `NaN`,
 * which would sign every user out the moment a deploy landed.
 */
function isAbsoluteExpired(createdAtMs: number | undefined, limitHours: number): boolean {
  if (createdAtMs === undefined) return false;
  return Date.now() - createdAtMs > limitHours * 3_600_000;
}

/** The two windows that end a session, as an administrator has configured them. */
interface SessionWindows {
  idleMinutes: number;
  absoluteHours: number;
}

/**
 * Read both windows in one settings load.
 *
 * `getSettings` falls back to the environment defaults when the settings
 * database cannot be read, so this never fails a request over a transient blip.
 */
async function sessionWindows(): Promise<SessionWindows> {
  const settings = await securitySettingsService.getSettings();
  return {
    idleMinutes: settings.sessionIdleTimeoutMinutes,
    absoluteHours: settings.sessionAbsoluteTimeoutHours,
  };
}

export const sessionService = {
  /**
   * Start a new session and issue its first refresh token.
   *
   * Enforces MAX_ACTIVE_SESSIONS_PER_USER by revoking the least recently used
   * sessions - failing the login instead would let an attacker lock a user out
   * simply by opening sessions until the cap is reached.
   */
  async createSession(params: {
    userId: string;
    deviceRowId: string;
    context: RequestContext;
  }): Promise<CreatedSession> {
    const { userId, deviceRowId, context } = params;

    const sessionCap = await securitySettingsService.get('maxActiveSessionsPerUser');

    const activeCount = await sessionRepository.countActiveForUser(userId);
    if (activeCount >= sessionCap) {
      const evictable = await sessionRepository.findOldestActiveSessionIds(userId, sessionCap - 1);
      for (const sessionId of evictable) {
        // Its own reason, not IDLE_TIMEOUT: "your session expired due to
        // inactivity" would be a lie - the user hit the per-account cap.
        await sessionRepository.revoke(sessionId, SESSION_REVOKE_REASON.SESSION_LIMIT);
        await invalidateSessionCache(sessionId);
      }
      logger.info('Evicted least-recently-used sessions to honour the per-user cap', {
        userId,
        evicted: evictable.length,
        cap: sessionCap,
      });
    }

    // Generated here because the id is a claim inside the token whose hash the
    // row will store.
    const sessionId = newId();
    const expiresAt = secondsFromNow(env.jwt.refreshTtlSeconds);

    const issued = signRefreshToken({
      userId,
      sessionId,
      deviceRowId,
      generation: 0,
    });

    await sessionRepository.create({
      id: sessionId,
      userId,
      deviceRowId,
      // Only the keyed hash is persisted: a database dump yields no usable token.
      refreshTokenHash: hashToken(issued.token),
      expiresAt,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });

    return {
      sessionId,
      refreshToken: issued.token,
      refreshTokenExpiresAt: issued.expiresAt,
      expiresAt,
    };
  },

  /**
   * Validate the session behind an access token.
   *
   * @throws {UnauthorizedError} when the session is unknown, revoked, expired or
   *   idle-timed-out, or when it belongs to a different user than the token
   *   claims (which would indicate a forged or swapped token).
   */
  async validateForRequest(sessionId: string, userId: string): Promise<void> {
    const cache = getCache();

    let cached: CachedSession | null = null;
    try {
      cached = await cache.get<CachedSession>(CACHE_KEYS.session(sessionId));
    } catch (error) {
      logger.debug('Session cache read failed; falling back to MySQL', { sessionId, error });
    }

    const windows = await sessionWindows();

    if (cached) {
      this.assertCachedSessionUsable(cached, userId, windows);
      return;
    }

    const session = await sessionRepository.findById(sessionId);
    if (!session) {
      throw new UnauthorizedError('Your session is no longer valid.', ERROR_CODES.SESSION_REVOKED);
    }

    this.assertCachedSessionUsable(toCachedSession(session), userId, windows);
    await cacheSession(session);
  },

  /** Shared checks for both the cached and freshly loaded paths. */
  assertCachedSessionUsable(session: CachedSession, userId: string, windows: SessionWindows): void {
    if (session.userId !== userId) {
      // Token and session disagree about the owner: treat as hostile.
      logger.warn('Session/token user mismatch', { sessionId: session.id });
      throw new UnauthorizedError('Your session is no longer valid.', ERROR_CODES.SESSION_REVOKED);
    }

    if (session.status !== SESSION_STATUS.ACTIVE) {
      throw new UnauthorizedError(
        'Your session has been signed out.',
        ERROR_CODES.SESSION_REVOKED,
      );
    }

    if (session.expiresAtMs <= Date.now()) {
      throw new UnauthorizedError('Your session has expired.', ERROR_CODES.TOKEN_EXPIRED);
    }

    if (isIdleExpired(session.lastActivityAtMs, windows.idleMinutes)) {
      // Revoked lazily, on the first request after the idle window elapses.
      void sessionService.revoke(session.id, SESSION_REVOKE_REASON.IDLE_TIMEOUT);
      throw new UnauthorizedError(
        'Your session expired due to inactivity.',
        ERROR_CODES.SESSION_REVOKED,
      );
    }

    if (isAbsoluteExpired(session.createdAtMs, windows.absoluteHours)) {
      void sessionService.revoke(session.id, SESSION_REVOKE_REASON.ABSOLUTE_TIMEOUT);
      throw new UnauthorizedError(
        'Your session has reached its maximum length. Please sign in again.',
        ERROR_CODES.SESSION_REVOKED,
      );
    }
  },

  /**
   * Record activity, throttled to at most one write per
   * {@link ACTIVITY_WRITE_THROTTLE_SECONDS} per session.
   *
   * Writing on every request would add a row lock to each authenticated call for
   * information that only needs minute-level resolution.
   */
  async touch(sessionId: string): Promise<void> {
    const cache = getCache();
    const throttleKey = CACHE_KEYS.sessionActivity(sessionId);

    try {
      if (await cache.has(throttleKey)) return;
      await cache.set(throttleKey, Date.now(), ACTIVITY_WRITE_THROTTLE_SECONDS);
    } catch (error) {
      logger.debug('Activity throttle check failed; writing through', { sessionId, error });
    }

    await sessionRepository.touch(sessionId);
    // The cached snapshot's lastActivityAtMs is now stale; drop it so the next
    // request reloads and the idle window is measured from the new timestamp.
    await invalidateSessionCache(sessionId);
  },

  /**
   * Rotate a refresh token.
   *
   * @throws {UnauthorizedError} with `REFRESH_TOKEN_REUSED` when replay is
   *   detected, after revoking every session for the user.
   */
  async rotate(refreshToken: string, context: RequestContext): Promise<RotatedSession> {
    // Signature, issuer, audience, expiry and token type.
    const claims = verifyRefreshToken(refreshToken);
    const presentedHash = hashToken(refreshToken);

    const session = await sessionRepository.findByRefreshTokenHash(presentedHash);

    if (!session) {
      // Not the current token. If it is a *superseded* one, this is replay.
      const replayed = await sessionRepository.findByPreviousRefreshTokenHash(presentedHash);
      if (replayed) {
        await this.handleReuseDetected(replayed, context);
      }
      throw new UnauthorizedError(
        'Your session is no longer valid. Please sign in again.',
        ERROR_CODES.TOKEN_INVALID,
      );
    }

    // Claims must describe the session they were found through.
    if (session.id !== claims.sessionId || session.userId !== claims.userId) {
      logger.warn('Refresh token claims do not match the stored session', {
        sessionId: session.id,
        requestId: context.requestId,
      });
      await this.revoke(session.id, SESSION_REVOKE_REASON.REFRESH_REUSE_DETECTED);
      throw new UnauthorizedError('Your session is no longer valid.', ERROR_CODES.TOKEN_INVALID);
    }

    // A stale generation means an older copy of the token is in play.
    if (claims.generation !== session.refreshTokenGeneration) {
      await this.handleReuseDetected(session, context);
      throw new UnauthorizedError(
        'Your session was ended for security reasons. Please sign in again.',
        ERROR_CODES.REFRESH_TOKEN_REUSED,
      );
    }

    if (!isSessionUsable(session)) {
      throw new UnauthorizedError(
        'Your session has expired. Please sign in again.',
        ERROR_CODES.SESSION_REVOKED,
      );
    }

    const windows = await sessionWindows();

    if (isIdleExpired(session.lastActivityAt.getTime(), windows.idleMinutes)) {
      await this.revoke(session.id, SESSION_REVOKE_REASON.IDLE_TIMEOUT);
      throw new UnauthorizedError(
        'Your session expired due to inactivity.',
        ERROR_CODES.SESSION_REVOKED,
      );
    }

    // Checked on rotation as well as on request: this is the deadline that a
    // sliding refresh expiry would otherwise never reach, which is the whole
    // point of having an absolute limit.
    if (isAbsoluteExpired(session.createdAt.getTime(), windows.absoluteHours)) {
      await this.revoke(session.id, SESSION_REVOKE_REASON.ABSOLUTE_TIMEOUT);
      throw new UnauthorizedError(
        'Your session has reached its maximum length. Please sign in again.',
        ERROR_CODES.SESSION_REVOKED,
      );
    }

    const nextGeneration = session.refreshTokenGeneration + 1;
    const issued = signRefreshToken({
      userId: session.userId,
      sessionId: session.id,
      deviceRowId: session.deviceRowId ?? claims.deviceRowId,
      generation: nextGeneration,
    });

    // Sliding absolute expiry: an actively used session keeps working, an
    // abandoned one still dies at REFRESH_TOKEN_TTL after its last use.
    const newExpiresAt = secondsFromNow(env.jwt.refreshTtlSeconds);

    const won = await sessionRepository.rotate(
      session.id,
      presentedHash,
      hashToken(issued.token),
      newExpiresAt,
      context.ipAddress,
      context.userAgent,
    );

    if (!won) {
      // Another request rotated this token first: two holders of one token.
      await this.handleReuseDetected(session, context);
      throw new UnauthorizedError(
        'Your session was ended for security reasons. Please sign in again.',
        ERROR_CODES.REFRESH_TOKEN_REUSED,
      );
    }

    await invalidateSessionCache(session.id);

    const refreshed = await sessionRepository.findById(session.id);

    return {
      session: refreshed ?? session,
      refreshToken: issued.token,
      refreshTokenExpiresAt: issued.expiresAt,
    };
  },

  /**
   * Containment for a detected refresh-token replay.
   *
   * Kept separate so the policy - and the reasoning behind its severity - lives
   * in one place. The audit entry is written by the caller in `auth.service`,
   * which has the actor's email to hand.
   */
  async handleReuseDetected(session: SessionRecord, context: RequestContext): Promise<void> {
    logger.error('Refresh token reuse detected; revoking all sessions for the user', {
      userId: session.userId,
      sessionId: session.id,
      ipAddress: context.ipAddress,
      requestId: context.requestId,
    });

    const revoked = await sessionRepository.revokeAllForUser(
      session.userId,
      SESSION_REVOKE_REASON.REFRESH_REUSE_DETECTED,
    );

    await invalidateSessionCache(session.id);
    try {
      await getCache().delByPrefix(CACHE_KEYS.userSessions(session.userId));
    } catch (error) {
      logger.warn('Failed to clear cached sessions after reuse detection', {
        userId: session.userId,
        error,
      });
    }

    logger.warn('Sessions revoked after reuse detection', {
      userId: session.userId,
      revoked,
    });
  },

  /** Revoke a single session. */
  async revoke(sessionId: string, reason: SessionRevokeReason): Promise<boolean> {
    const revoked = await sessionRepository.revoke(sessionId, reason);
    await invalidateSessionCache(sessionId);
    return revoked;
  },

  /**
   * Administrative revocation of one session, by id alone.
   *
   * The owner is read from the session row rather than accepted from the
   * caller: taking a user id from the request would let a caller attribute the
   * revocation - and its audit entry - to somebody who had nothing to do with
   * it.
   */
  async revokeById(
    sessionId: string,
    actor: AuthContext,
    context: RequestContext,
  ): Promise<{ revoked: boolean; userId: string | null }> {
    const session = await sessionRepository.findById(sessionId);
    if (!session) throw new NotFoundError('Session not found.');

    const revoked = await this.revoke(sessionId, SESSION_REVOKE_REASON.ADMIN_REVOKE);

    await auditService.record({
      action: AUDIT_ACTIONS.SESSION_REVOKED,
      actorUserId: actor.userId,
      actorEmail: actor.email,
      targetUserId: session.userId,
      sessionId,
      context,
      metadata: { administrative: true, ipAddress: session.ipAddress ?? null },
    });

    return { revoked, userId: session.userId };
  },

  /** Revoke every session for a user, optionally sparing the current one. */
  async revokeAllForUser(
    userId: string,
    reason: SessionRevokeReason,
    exceptSessionId?: string,
  ): Promise<number> {
    // Read the ids first so their cache entries can be dropped individually -
    // `delByPrefix` alone would not cover the per-session keys.
    const sessions = await sessionRepository.listByUser(userId, { activeOnly: true });
    const count = await sessionRepository.revokeAllForUser(userId, reason, exceptSessionId);

    await Promise.all(
      sessions
        .filter((session) => session.id !== exceptSessionId)
        .map((session) => invalidateSessionCache(session.id)),
    );

    return count;
  },

  /** Revoke every session bound to a device (used when trust is withdrawn). */
  async revokeAllForDevice(deviceRowId: string, reason: SessionRevokeReason): Promise<number> {
    return sessionRepository.revokeAllForDevice(deviceRowId, reason);
  },

  /**
   * Revoke every active session except those held by one role.
   *
   * The emergency lock's "throw everyone out" option. Administrators are spared
   * so the person responding to the incident is not signed out by their own
   * response - which would leave the lock on with nobody able to lift it.
   */
  async revokeAllExceptRole(exemptRole: string, reason: SessionRevokeReason): Promise<number> {
    const sessions = await sessionRepository.listActiveExceptRole(exemptRole);

    let revoked = 0;
    for (const session of sessions) {
      const done = await sessionRepository.revoke(session.id, reason);
      if (done) {
        revoked += 1;
        await invalidateSessionCache(session.id);
      }
    }

    return revoked;
  },

  /** Client-safe session list for the "where am I signed in" view. */
  async listForUser(userId: string, currentSessionId?: string): Promise<SessionInfo[]> {
    const sessions = await sessionRepository.listByUser(userId, { activeOnly: true });
    return sessions.map((session) => toSessionInfo(session, currentSessionId));
  },

  /** Fetch one session scoped to its owner (prevents cross-user access). */
  async findForUser(sessionId: string, userId: string): Promise<SessionRecord | null> {
    const session = await sessionRepository.findById(sessionId);
    if (!session || session.userId !== userId) return null;
    return session;
  },
};

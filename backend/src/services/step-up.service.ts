/**
 * Two-step verification: confirm it is you with Google before something
 * consequential.
 *
 * ## The protocol
 *
 *   1. Client asks for a challenge for some action.
 *   2. Server stores a single-use nonce and returns it.
 *   3. The client asks Google for a fresh ID token with that nonce as its
 *      `nonce` claim - the user picks their account in Google's dialog.
 *   4. Server verifies the token as it would a sign-in, and additionally that
 *      it belongs to this account and carries this challenge's nonce.
 *
 * The nonce makes it replay-proof: neither the sign-in token nor one from an
 * earlier confirmation can satisfy a new challenge.
 *
 * ## Honest limits
 *
 * It proves the person at the keyboard can complete a Google sign-in as this
 * account *now*. If the browser holds a live Google session, that can be a
 * single click - so step-up defends a hijacked PassM session (stolen tokens
 * without the Google session) better than an unattended unlocked screen.
 * Google's own re-authentication settings decide how much more it asks.
 */

import { randomBytes } from 'node:crypto';

import {
  AUDIT_ACTIONS,
  STEP_UP_ACTION,
  type SecuritySettings,
  type StepUpAction,
  type StepUpChallenge,
  type StepUpStatus,
} from '@passm/shared';

import { stepUpRepository } from '../repositories/step-up.repository';
import { userRepository } from '../repositories/user.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import {
  BadRequestError,
  ServiceUnavailableError,
  StepUpFailedError,
  StepUpRequiredError,
} from '../utils/errors';
import { auditService } from './audit.service';
import { googleIdentityService } from './google-identity.service';
import { securitySettingsService } from './security-settings.service';

/** How long an unanswered challenge lives. Long enough to get through Google's prompt. */
const CHALLENGE_TTL_MS = 5 * 60_000;

/** Wrong answers before the challenge is burned and a new one is needed. */
const MAX_ATTEMPTS = 5;

/** Which policy switch governs each action. */
const POLICY_KEY: Record<StepUpAction, keyof SecuritySettings> = {
  [STEP_UP_ACTION.REVEAL]: 'stepUpForReveal',
  [STEP_UP_ACTION.EXPORT]: 'stepUpForExport',
  [STEP_UP_ACTION.ADMIN_ACTION]: 'stepUpForAdminAction',
  [STEP_UP_ACTION.SETTINGS_CHANGE]: 'stepUpForSettingsChange',
};

export const stepUpService = {
  /**
   * Does this action currently need a check, and is one already in force?
   *
   * Read by the middleware before every guarded action, and by the client so it
   * can show the padlock before the user clicks rather than after.
   */
  async status(auth: AuthContext, action: StepUpAction): Promise<StepUpStatus> {
    const settings = await securitySettingsService.getSettings();

    const requiredFor = (Object.keys(POLICY_KEY) as StepUpAction[]).filter(
      (candidate) => settings[POLICY_KEY[candidate]] === true,
    );

    const active = await stepUpRepository.findActiveVerification(auth.userId, action);

    return {
      verified: active !== null,
      expiresAt: active?.verifiedUntil?.toISOString() ?? null,
      requiredFor,
    };
  },

  /**
   * Throw unless the caller has a current verification for `action`.
   *
   * The gate used by controllers. Returns quietly when the policy does not
   * require a check at all, so call sites can invoke it unconditionally.
   */
  async require(auth: AuthContext, action: StepUpAction): Promise<void> {
    const settings = await securitySettingsService.getSettings();
    if (settings[POLICY_KEY[action]] !== true) return;

    const active = await stepUpRepository.findActiveVerification(auth.userId, action);
    if (active) return;

    throw new StepUpRequiredError(action);
  },

  /** Issue a challenge. */
  async createChallenge(
    auth: AuthContext,
    action: StepUpAction,
  ): Promise<StepUpChallenge> {
    // Housekeeping on the way past: cheaper than a scheduled job for a table
    // this small, and keeps expired rows from accumulating.
    await stepUpRepository.deleteExpired(auth.userId);

    const nonce = randomBytes(64).toString('base64url');
    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);

    const challengeId = await stepUpRepository.create({
      userId: auth.userId,
      sessionId: auth.sessionId,
      action,
      nonce,
      expiresAt,
    });

    return {
      challengeId,
      action,
      // Travels in the clear: the client hands it to Google, and it is not a
      // secret - it exists only to make the confirmation single-use.
      nonce,
      expiresAt: expiresAt.toISOString(),
    };
  },

  /**
   * Check a Google confirmation.
   *
   * On success the challenge row becomes the record of a recent verification,
   * good for `stepUpValidityMinutes`. On failure the attempt count rises and the
   * challenge burns out after {@link MAX_ATTEMPTS}.
   */
  async verify(
    auth: AuthContext,
    challengeId: string,
    credential: string,
    context: RequestContext,
  ): Promise<{ verifiedUntil: Date; action: StepUpAction }> {
    const challenge = await stepUpRepository.findById(challengeId);

    // One error for every failure mode: wrong id, someone else's challenge,
    // expired, already used. Distinguishing them would tell a prober which of
    // those it hit.
    if (
      !challenge ||
      challenge.userId !== auth.userId ||
      challenge.expiresAt.getTime() < Date.now()
    ) {
      throw new StepUpFailedError('That confirmation request has expired. Please try again.');
    }

    if (challenge.attempts >= MAX_ATTEMPTS) {
      throw new StepUpFailedError('Too many attempts. Start again.');
    }

    // Single use. Without this a captured proof could be replayed against the
    // same challenge to extend a verification indefinitely, which defeats the
    // point of having a validity window at all.
    if (challenge.verifiedAt !== null) {
      throw new StepUpFailedError('That confirmation has already been used. Please try again.');
    }

    const user = await userRepository.findById(auth.userId);
    if (!user) throw new BadRequestError('Your account could not be found.');

    // Same verification as sign-in, plus the nonce. Then it must be *this*
    // account: a colleague completing the Google prompt on your unlocked
    // screen proves nothing about you.
    let confirmed = false;
    try {
      const identity = await googleIdentityService.verifyIdToken(credential, {
        nonce: challenge.nonce,
      });
      confirmed =
        user.googleSubject !== null
          ? identity.subject === user.googleSubject
          : identity.email === user.email;
    } catch (error) {
      // An outage is not a wrong answer; let it surface as itself.
      if (error instanceof ServiceUnavailableError) throw error;
    }

    if (!confirmed) {
      await stepUpRepository.incrementAttempts(challengeId);

      await auditService.recordFailure({
        action: AUDIT_ACTIONS.STEP_UP_FAILED,
        actorUserId: auth.userId,
        actorEmail: auth.email,
        sessionId: auth.sessionId,
        context,
        isSharedResource: true,
        metadata: { stepUpAction: challenge.action, attempt: challenge.attempts + 1 },
      });

      throw new StepUpFailedError();
    }

    const validityMinutes = await securitySettingsService.get('stepUpValidityMinutes');
    const verifiedUntil = new Date(Date.now() + validityMinutes * 60_000);

    await stepUpRepository.markVerified(challengeId, verifiedUntil);

    await auditService.record({
      action: AUDIT_ACTIONS.STEP_UP_SUCCEEDED,
      actorUserId: auth.userId,
      actorEmail: auth.email,
      sessionId: auth.sessionId,
      context,
      isSharedResource: true,
      metadata: { stepUpAction: challenge.action, validityMinutes },
    });

    return { verifiedUntil, action: challenge.action as StepUpAction };
  },

  /** Drop every verification for a user, e.g. after a password change. */
  async revokeAll(userId: string): Promise<void> {
    await stepUpRepository.deleteForUser(userId);
  },
};

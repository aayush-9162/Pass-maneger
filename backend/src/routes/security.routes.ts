/**
 * Per-user security routes.
 *
 * Everything here is scoped to the caller by their own session - there is no id
 * in any path that identifies a *different* user, which is what keeps these
 * endpoints safe to expose to every authenticated account.
 */

import { Router } from 'express';

import {
  createStepUpChallenge,
  deleteNotification,
  getClientPolicy,
  getCsrfToken,
  listNotifications,
  markNotificationsRead,
  stepUpStatus,
  verifyStepUp,
} from '../controllers/security.controller';
import { idParamSchema } from '../dto/common.dto';
import {
  listNotificationsQuerySchema,
  markNotificationsReadSchema,
  stepUpChallengeSchema,
  stepUpStatusQuerySchema,
  stepUpVerifySchema,
} from '../dto/security.dto';
import { authenticate } from '../middleware/authenticate.middleware';
import { csrfProtection } from '../middleware/csrf.middleware';
import { stepUpLimiter } from '../middleware/rate-limit.middleware';
import { validate } from '../middleware/validate.middleware';
import { asyncHandler } from '../utils/async-handler';

export const securityRoutes = Router();

securityRoutes.use(authenticate);

/**
 * CSRF applies to everything below.
 *
 * Mounted after `authenticate` so the token can be bound to the session id, and
 * after the token endpoint above - which is on the exemption list anyway, since
 * the endpoint that issues a token cannot require one.
 */
securityRoutes.use(csrfProtection());

/**
 * GET /security/csrf-token
 *
 * Authenticated, and it has to be. The token is signed with the caller's
 * session id bound in, which is what stops a token minted for one session being
 * replayed on another. Issuing it before `authenticate` would bind every token
 * to `anonymous`, and it would then fail on every authenticated route - the
 * protection would look present and refuse all legitimate traffic.
 *
 * No client needs a token before signing in: login, register and refresh are
 * all on the CSRF exemption list precisely because there is no session to bind
 * to yet. So the first token a client needs is the one it fetches after
 * sign-in.
 */
securityRoutes.get('/csrf-token', getCsrfToken);

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

securityRoutes.get('/policy', asyncHandler(getClientPolicy));

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

securityRoutes.get(
  '/notifications',
  validate({ query: listNotificationsQuerySchema }),
  asyncHandler(listNotifications),
);

securityRoutes.post(
  '/notifications/read',
  validate({ body: markNotificationsReadSchema }),
  asyncHandler(markNotificationsRead),
);

securityRoutes.delete(
  '/notifications/:id',
  validate({ params: idParamSchema }),
  asyncHandler(deleteNotification),
);

// ---------------------------------------------------------------------------
// Step-up verification
// ---------------------------------------------------------------------------

/**
 * Rate-limited despite the per-challenge attempt cap.
 *
 * The cap stops guessing against *one* nonce; the limiter stops an attacker
 * cycling through fresh challenges to get unlimited attempts overall.
 */
securityRoutes.post(
  '/step-up/challenge',
  stepUpLimiter,
  validate({ body: stepUpChallengeSchema }),
  asyncHandler(createStepUpChallenge),
);

securityRoutes.post(
  '/step-up/verify',
  stepUpLimiter,
  validate({ body: stepUpVerifySchema }),
  asyncHandler(verifyStepUp),
);

securityRoutes.get(
  '/step-up/status',
  validate({ query: stepUpStatusQuerySchema }),
  asyncHandler(stepUpStatus),
);

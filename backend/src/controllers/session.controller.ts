/**
 * Self-service session management: "where am I signed in, and sign that out".
 *
 * Every handler scopes its query to `req.auth.userId`, so a caller can only ever
 * see or revoke their own sessions regardless of the id they pass.
 */

import { AUDIT_ACTIONS, SESSION_REVOKE_REASON } from '@passm/shared';
import type { Response } from 'express';

import type { SessionIdParamDto } from '../dto/device.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import type { TypedRequest } from '../middleware/validate.middleware';
import { auditService } from '../services/audit.service';
import { sessionService } from '../services/session.service';
import { sendSuccess } from '../utils/api-response';
import { NotFoundError } from '../utils/errors';

/** GET /auth/sessions */
export async function listMySessions(req: TypedRequest, res: Response): Promise<void> {
  const auth = requireAuth(req);
  const sessions = await sessionService.listForUser(auth.userId, auth.sessionId);

  sendSuccess(res, { sessions });
}

/**
 * DELETE /auth/sessions/:sessionId
 *
 * Revoking the current session is allowed - it is simply a logout - so the
 * response reports whether the caller just signed themselves out, letting the
 * client redirect appropriately.
 */
export async function revokeMySession(
  req: TypedRequest<unknown, SessionIdParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const { sessionId } = req.params;

  // Ownership check: an id belonging to someone else reads as "not found",
  // which avoids confirming that another user's session exists.
  const session = await sessionService.findForUser(sessionId, auth.userId);
  if (!session) throw new NotFoundError('Session not found.');

  const revoked = await sessionService.revoke(sessionId, SESSION_REVOKE_REASON.USER_LOGOUT);

  await auditService.record({
    action: AUDIT_ACTIONS.SESSION_REVOKED,
    actorUserId: auth.userId,
    actorEmail: auth.email,
    targetUserId: auth.userId,
    sessionId,
    context: req.context,
    metadata: { selfService: true, wasCurrentSession: sessionId === auth.sessionId },
  });

  sendSuccess(res, {
    revoked,
    wasCurrentSession: sessionId === auth.sessionId,
  });
}

export const sessionController = {
  listMySessions,
  revokeMySession,
};

/**
 * Security policy, IP rules, notifications, step-up and the emergency lock.
 *
 * Two audiences in one file, separated by the routes that mount them:
 *
 *  - **Administrator surfaces** (settings, IP rules, score, emergency lock) sit
 *    behind permissions and, where the policy says so, behind a step-up check.
 *  - **User surfaces** (policy read, notifications, step-up) need only a valid
 *    session; they are scoped to the caller by their own user id, never by an
 *    id in the request.
 */

import type { Response } from 'express';

import {
  AUDIT_ACTIONS,
  CLIENT_VISIBLE_SETTING_KEYS,
  SESSION_REVOKE_REASON,
  STEP_UP_ACTION,
  type ClientSecuritySettings,
  type EmergencyLockState,
  type SecuritySettings,
} from '@passm/shared';

import { env } from '../config/env';
import type {
  CheckIpDto,
  CreateIpRuleDto,
  EmergencyLockDto,
  ListNotificationsQueryDto,
  MarkNotificationsReadDto,
  ResetSettingDto,
  ScoreHistoryQueryDto,
  StepUpChallengeDto,
  StepUpStatusQueryDto,
  StepUpVerifyDto,
  UpdateIpRuleDto,
  UpdateSettingsDto,
} from '../dto/security.dto';
import type { IdParamDto } from '../dto/common.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import { issueCsrfToken } from '../middleware/csrf.middleware';
import type { TypedQueryRequest, TypedRequest } from '../middleware/validate.middleware';
import { ipRuleRepository } from '../repositories/ip-rule.repository';
import { auditService } from '../services/audit.service';
import { ipAccessService } from '../services/ip-access.service';
import { notificationService } from '../services/notification.service';
import { securityScoreService } from '../services/security-score.service';
import { securitySettingsService } from '../services/security-settings.service';
import { sessionService } from '../services/session.service';
import { stepUpService } from '../services/step-up.service';
import { userRepository } from '../repositories/user.repository';
import { paginated, sendCreated, sendNoContent, sendSuccess } from '../utils/api-response';
import { ConflictError, NotFoundError } from '../utils/errors';
import { getClientIp } from '../utils/request-context';

/**
 * Is this deployment actually served over TLS?
 *
 * Mirrors the reasoning in `security.middleware`: either this process terminates
 * TLS, or a trusted proxy in front does and plaintext has not been explicitly
 * enabled for a LAN.
 */
const tlsActive = env.tls.enabled || (env.trustProxyHops > 0 && !env.allowInsecureHttp);

// ===========================================================================
// Settings
// ===========================================================================

/** GET /admin/settings */
export async function getSettings(req: TypedRequest<unknown>, res: Response): Promise<void> {
  requireAuth(req);

  const { settings, entries, lockedKeys } = await securitySettingsService.getWithProvenance();

  sendSuccess(res, { settings, entries, lockedKeys, tlsActive });
}

/**
 * PATCH /admin/settings
 *
 * The diff, not the whole object, goes in the audit entry - "changed
 * failedLoginThreshold from 5 to 20" is the sentence an auditor needs, and
 * dumping sixty unchanged values around it would bury it.
 */
export async function updateSettings(
  req: TypedRequest<UpdateSettingsDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  await stepUpService.require(auth, STEP_UP_ACTION.SETTINGS_CHANGE);

  const { settings, changed } = await securitySettingsService.update(
    req.body.settings as Partial<SecuritySettings>,
    auth.userId,
  );

  if (changed.length > 0) {
    await auditService.record({
      action: AUDIT_ACTIONS.SETTINGS_CHANGED,
      actorUserId: auth.userId,
      actorEmail: auth.email,
      context: req.context,
      isSharedResource: true,
      metadata: {
        ...(req.body.reason ? { changeReason: req.body.reason } : {}),
        changeCount: changed.length,
        // Values are policy thresholds, not secrets, so recording them is safe
        // and makes the trail self-contained.
        changes: changed.map((entry) => `${entry.key}: ${String(entry.from)} -> ${String(entry.to)}`),
      },
    });
  }

  sendSuccess(res, {
    settings,
    changed: changed.map((entry) => entry.key),
    message:
      changed.length === 0
        ? 'No changes - those values were already set.'
        : `Saved ${changed.length} change${changed.length === 1 ? '' : 's'}.`,
  });
}

/** POST /admin/settings/reset */
export async function resetSettings(
  req: TypedRequest<Partial<ResetSettingDto>>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  await stepUpService.require(auth, STEP_UP_ACTION.SETTINGS_CHANGE);

  // One key when named, everything when not.
  if (req.body.key) {
    await securitySettingsService.resetKey(req.body.key);
  } else {
    await securitySettingsService.resetToDefaults();
  }

  await auditService.record({
    action: AUDIT_ACTIONS.SETTINGS_RESET,
    actorUserId: auth.userId,
    actorEmail: auth.email,
    context: req.context,
    isSharedResource: true,
    metadata: req.body.key ? { settingKey: req.body.key } : { scope: 'all' },
  });

  const settings = await securitySettingsService.getSettings();
  sendSuccess(res, {
    settings,
    message: req.body.key ? 'Setting returned to its default.' : 'All settings returned to defaults.',
  });
}

/**
 * GET /security/policy
 *
 * The slice of policy a signed-in client needs in order to behave correctly:
 * auto-lock timing, clipboard clearing, password rules for the change form.
 * Deliberately a subset - a normal user has no reason to learn the IP allow list
 * configuration, and telling them would be handing out reconnaissance.
 */
export async function getClientPolicy(req: TypedRequest<unknown>, res: Response): Promise<void> {
  requireAuth(req);

  const settings = await securitySettingsService.getSettings();

  const policy = Object.fromEntries(
    CLIENT_VISIBLE_SETTING_KEYS.map((key) => [key, settings[key]]),
  ) as unknown as ClientSecuritySettings;

  sendSuccess(res, { policy, tlsActive });
}

// ===========================================================================
// IP rules
// ===========================================================================

/** GET /admin/ip-rules */
export async function listIpRules(req: TypedRequest<unknown>, res: Response): Promise<void> {
  requireAuth(req);

  const [rules, settings] = await Promise.all([
    ipAccessService.listRules(),
    securitySettingsService.getSettings(),
  ]);

  sendSuccess(res, {
    rules,
    mode: settings.ipAllowListMode,
    appliesToAdmins: settings.ipAllowListAppliesToAdmins,
    /**
     * The caller's own address, so the console can warn "the rule you are about
     * to enforce does not include you" before it is too late.
     */
    callerIp: getClientIp(req),
  });
}

/** POST /admin/ip-rules */
export async function createIpRule(
  req: TypedRequest<CreateIpRuleDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const duplicate = await ipRuleRepository.existsForTarget(
    req.body.cidr,
    req.body.scope,
    req.body.userId ?? null,
    req.body.roleName ?? null,
  );
  if (duplicate) {
    throw new ConflictError('That range is already covered by an identical rule.');
  }

  const id = await ipRuleRepository.create({
    cidr: req.body.cidr,
    label: req.body.label,
    scope: req.body.scope,
    userId: req.body.userId ?? null,
    roleName: req.body.roleName ?? null,
    createdByUserId: auth.userId,
  });

  ipAccessService.invalidateCache();

  await auditService.record({
    action: AUDIT_ACTIONS.IP_RULE_CREATED,
    actorUserId: auth.userId,
    actorEmail: auth.email,
    context: req.context,
    resourceType: 'ip_rule',
    resourceId: id,
    isSharedResource: true,
    metadata: { cidr: req.body.cidr, scope: req.body.scope, label: req.body.label },
  });

  const rule = await ipRuleRepository.findById(id);
  sendCreated(res, { rule });
}

/** PATCH /admin/ip-rules/:id */
export async function updateIpRule(
  req: TypedRequest<UpdateIpRuleDto, IdParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const updated = await ipRuleRepository.setEnabled(req.params.id, req.body.enabled);
  if (!updated) throw new NotFoundError('That rule no longer exists.');

  ipAccessService.invalidateCache();

  await auditService.record({
    action: AUDIT_ACTIONS.IP_RULE_UPDATED,
    actorUserId: auth.userId,
    actorEmail: auth.email,
    context: req.context,
    resourceType: 'ip_rule',
    resourceId: req.params.id,
    isSharedResource: true,
    metadata: { enabled: req.body.enabled },
  });

  sendSuccess(res, { rule: await ipRuleRepository.findById(req.params.id) });
}

/** DELETE /admin/ip-rules/:id */
export async function deleteIpRule(
  req: TypedRequest<unknown, IdParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const rule = await ipRuleRepository.findById(req.params.id);
  if (!rule) throw new NotFoundError('That rule no longer exists.');

  await ipRuleRepository.remove(req.params.id);
  ipAccessService.invalidateCache();

  await auditService.record({
    action: AUDIT_ACTIONS.IP_RULE_DELETED,
    actorUserId: auth.userId,
    actorEmail: auth.email,
    context: req.context,
    resourceType: 'ip_rule',
    resourceId: req.params.id,
    isSharedResource: true,
    metadata: { cidr: rule.cidr, label: rule.label },
  });

  sendNoContent(res);
}

/**
 * POST /admin/ip-rules/check
 *
 * Runs the real evaluation rather than a reimplementation, so the preview cannot
 * disagree with enforcement. That is the entire value of the feature.
 */
export async function checkIp(req: TypedRequest<CheckIpDto>, res: Response): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, await ipAccessService.check(req.body.ip, auth));
}

// ===========================================================================
// Step-up verification
// ===========================================================================

/** POST /security/step-up/challenge */
export async function createStepUpChallenge(
  req: TypedRequest<StepUpChallengeDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, await stepUpService.createChallenge(auth, req.body.action));
}

/** POST /security/step-up/verify */
export async function verifyStepUp(
  req: TypedRequest<StepUpVerifyDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const result = await stepUpService.verify(
    auth,
    req.body.challengeId,
    req.body.credential,
    req.context,
  );

  sendSuccess(res, {
    verified: true,
    action: result.action,
    expiresAt: result.verifiedUntil.toISOString(),
  });
}

/** GET /security/step-up/status */
export async function stepUpStatus(
  req: TypedQueryRequest<StepUpStatusQueryDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, await stepUpService.status(auth, req.query.action));
}

// ===========================================================================
// Notifications
// ===========================================================================

/** GET /security/notifications */
export async function listNotifications(
  req: TypedQueryRequest<ListNotificationsQueryDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const { page, pageSize, unreadOnly } = req.query;
  const result = await notificationService.list(auth.userId, {
    limit: pageSize,
    offset: (page - 1) * pageSize,
    unreadOnly,
  });

  sendSuccess(res, {
    ...paginated(result.items, result.total, page, pageSize),
    unreadCount: result.unreadCount,
  });
}

/** POST /security/notifications/read */
export async function markNotificationsRead(
  req: TypedRequest<MarkNotificationsReadDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const marked = await notificationService.markRead(auth.userId, req.body.ids);
  sendSuccess(res, { marked });
}

/** DELETE /security/notifications/:id */
export async function deleteNotification(
  req: TypedRequest<unknown, IdParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const removed = await notificationService.remove(auth.userId, req.params.id);
  if (!removed) throw new NotFoundError('That notification no longer exists.');

  sendNoContent(res);
}

// ===========================================================================
// Security score
// ===========================================================================

/** GET /admin/security-score */
export async function getSecurityScore(req: TypedRequest<unknown>, res: Response): Promise<void> {
  requireAuth(req);
  sendSuccess(res, await securityScoreService.compute(tlsActive));
}

/** GET /admin/security-score/history */
export async function getScoreHistory(
  req: TypedQueryRequest<ScoreHistoryQueryDto>,
  res: Response,
): Promise<void> {
  requireAuth(req);
  sendSuccess(res, { points: await securityScoreService.history(req.query.days) });
}

// ===========================================================================
// Emergency lock
// ===========================================================================

/** GET /admin/emergency-lock */
export async function getEmergencyLock(req: TypedRequest<unknown>, res: Response): Promise<void> {
  requireAuth(req);

  const settings = await securitySettingsService.getSettings();

  const state: EmergencyLockState = {
    active: settings.emergencyLockActive,
    message: settings.emergencyLockMessage,
    // Provenance lives in the audit trail rather than being duplicated here;
    // the console links straight to the filtered log.
    activatedAt: null,
    activatedByName: null,
    reason: null,
    sessionsTerminated: 0,
  };

  sendSuccess(res, state);
}

/**
 * POST /admin/emergency-lock
 *
 * Switching it on optionally ends every session. That is a separate flag rather
 * than automatic, because the two are genuinely different responses: "stop
 * anyone opening a vault" is the lock, and "throw everyone out right now" is a
 * stronger action with a real cost to people mid-task.
 */
export async function setEmergencyLock(
  req: TypedRequest<EmergencyLockDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  await stepUpService.require(auth, STEP_UP_ACTION.ADMIN_ACTION);

  const patch: Partial<SecuritySettings> = { emergencyLockActive: req.body.active };
  if (req.body.message) patch.emergencyLockMessage = req.body.message;

  await securitySettingsService.update(patch, auth.userId);

  let sessionsTerminated = 0;
  if (req.body.active && req.body.terminateSessions) {
    // Administrators keep their sessions: whoever is handling the incident must
    // not be thrown out by their own response to it.
    sessionsTerminated = await sessionService.revokeAllExceptRole('admin', SESSION_REVOKE_REASON.EMERGENCY_LOCK);
  }

  const settings = await securitySettingsService.getSettings();

  if (req.body.active) {
    const affected = await userRepository.findActiveNonAdminIds();
    void notificationService.notifyEmergencyLock(affected, settings.emergencyLockMessage);
  }

  await auditService.record({
    action: req.body.active
      ? AUDIT_ACTIONS.EMERGENCY_LOCK_ENABLED
      : AUDIT_ACTIONS.EMERGENCY_LOCK_DISABLED,
    actorUserId: auth.userId,
    actorEmail: auth.email,
    context: req.context,
    isSharedResource: true,
    metadata: {
      lockReason: req.body.reason,
      sessionsTerminated,
    },
  });

  sendSuccess(res, {
    active: settings.emergencyLockActive,
    message: settings.emergencyLockMessage,
    sessionsTerminated,
    notice: req.body.active
      ? `Access suspended for everyone except administrators.${
          sessionsTerminated > 0 ? ` ${sessionsTerminated} session(s) ended.` : ''
        }`
      : 'Access restored.',
  });
}

// ===========================================================================
// CSRF
// ===========================================================================

/**
 * GET /security/csrf-token
 *
 * How a client obtains its first token, and how it recovers from a rejected
 * one. Exempt from the CSRF check itself for the obvious reason.
 */
export function getCsrfToken(req: TypedRequest<unknown>, res: Response): void {
  const token = issueCsrfToken(req, res);
  sendSuccess(res, { token });
}

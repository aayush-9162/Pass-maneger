/**
 * Administration routes.
 *
 * Every route in this router is authenticated and past the forced-rotation
 * guard - applied once with `router.use`, so a newly added route cannot
 * accidentally be left public.
 *
 * Authorization is expressed per route as a *permission*, not a role. Managers
 * get read access and admins get write access purely through the permission
 * matrix in `@passm/shared`; this file never mentions who holds what.
 */

import { PERMISSIONS } from '@passm/shared';
import { Router } from 'express';

import { adminController } from '../controllers/admin.controller';
import { analyticsController } from '../controllers/analytics.controller';
import * as securityController from '../controllers/security.controller';
import { collaborationController } from '../controllers/collaboration.controller';
import { sharedVaultController } from '../controllers/shared-vault.controller';
import {
  auditExportQuerySchema,
  auditFacetsQuerySchema,
  auditSearchQuerySchema,
  listRequestsQuerySchema,
} from '../dto/collaboration.dto';
import {
  dashboardQuerySchema,
  deviceParamSchema,
  listDevicesQuerySchema,
  listHealthReportsQuerySchema,
  listSessionsQuerySchema,
  lockUserSchema,
  sessionParamSchema,
  unlockUserSchema,
} from '../dto/admin.dto';
import { idParamSchema } from '../dto/common.dto';
import {
  checkIpSchema,
  createIpRuleSchema,
  emergencyLockSchema,
  resetSettingSchema,
  scoreHistoryQuerySchema,
  updateIpRuleSchema,
  updateSettingsSchema,
} from '../dto/security.dto';
import { userDeviceParamSchema, userScopeParamSchema } from '../dto/device.dto';
import { listSharedVaultsQuerySchema, sharedVaultParamSchema } from '../dto/sharing.dto';
import {
  changeUserRoleSchema,
  changeUserStatusSchema,
  listAuditLogsQuerySchema,
  listUsersQuerySchema,
  updateUserSchema,
} from '../dto/user.dto';
import { authenticate } from '../middleware/authenticate.middleware';
import { postAuthSecurityGates } from '../middleware';
import {
  requirePermission,
  requireSelfOrPermission,
} from '../middleware/authorize.middleware';
import { configurationLimiter, sensitiveOperationLimiter } from '../middleware/rate-limit.middleware';
import { validate } from '../middleware/validate.middleware';
import { asyncHandler } from '../utils/async-handler';

export const adminRoutes = Router();

// Applies to every route below, including ones added later.
adminRoutes.use(authenticate, ...postAuthSecurityGates());

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

adminRoutes.get(
  '/roles',
  requirePermission(PERMISSIONS.ROLE_READ),
  asyncHandler(adminController.listRoles),
);

// ---------------------------------------------------------------------------
// User directory
// ---------------------------------------------------------------------------

adminRoutes.get(
  '/users',
  requirePermission(PERMISSIONS.USER_READ),
  validate({ query: listUsersQuerySchema }),
  asyncHandler(adminController.listUsers),
);

adminRoutes.get(
  '/users/:id',
  requirePermission(PERMISSIONS.USER_READ),
  validate({ params: userScopeParamSchema }),
  asyncHandler(adminController.getUser),
);

adminRoutes.patch(
  '/users/:id',
  requirePermission(PERMISSIONS.USER_UPDATE),
  validate({ params: userScopeParamSchema, body: updateUserSchema }),
  asyncHandler(adminController.updateUser),
);

/**
 * PUT /users/:id/role
 *
 * Needs `role:assign`, which only admins hold. The service additionally refuses
 * self-demotion and refuses to remove the last administrator.
 */
adminRoutes.put(
  '/users/:id/role',
  requirePermission(PERMISSIONS.ROLE_ASSIGN),
  validate({ params: userScopeParamSchema, body: changeUserRoleSchema }),
  asyncHandler(adminController.changeUserRole),
);

adminRoutes.put(
  '/users/:id/status',
  requirePermission(PERMISSIONS.USER_DISABLE),
  validate({ params: userScopeParamSchema, body: changeUserStatusSchema }),
  asyncHandler(adminController.changeUserStatus),
);

/** DELETE /users/:id - full account deletion, not a suspension. */
adminRoutes.delete(
  '/users/:id',
  requirePermission(PERMISSIONS.USER_DISABLE),
  sensitiveOperationLimiter,
  validate({ params: userScopeParamSchema }),
  asyncHandler(adminController.deleteUser),
);

adminRoutes.put(
  '/users/:id/lock',
  requirePermission(PERMISSIONS.USER_LOCK),
  validate({ params: userScopeParamSchema, body: lockUserSchema }),
  asyncHandler(adminController.lockUser),
);

adminRoutes.put(
  '/users/:id/unlock',
  requirePermission(PERMISSIONS.USER_LOCK),
  validate({ params: userScopeParamSchema, body: unlockUserSchema }),
  asyncHandler(adminController.unlockUser),
);

// People-groups are gone: a "group" is now a set of passwords (a shared vault
// of kind `group`), managed through /shared/vaults and the admin vault routes.

// ---------------------------------------------------------------------------
// Shared vault governance
//
// Read and administer only. Reading *contents* is not reachable from any admin
// route, by construction: it would need a key envelope, and there is no endpoint
// that produces one for a caller who is not a member.
// ---------------------------------------------------------------------------

adminRoutes.get(
  '/shared-vaults',
  requirePermission(PERMISSIONS.SHARED_VAULT_MANAGE),
  validate({ query: listSharedVaultsQuerySchema }),
  asyncHandler(sharedVaultController.listAllVaults),
);

adminRoutes.get(
  '/shared-vaults/:vaultId',
  requirePermission(PERMISSIONS.SHARED_VAULT_MANAGE),
  validate({ params: sharedVaultParamSchema }),
  asyncHandler(sharedVaultController.getVault),
);

adminRoutes.get(
  '/shared-vaults/:vaultId/access',
  requirePermission(PERMISSIONS.SHARED_VAULT_MANAGE),
  validate({ params: sharedVaultParamSchema }),
  asyncHandler(sharedVaultController.getAccess),
);

// ---------------------------------------------------------------------------
// Dashboard, security and tenant-wide sessions/devices
// ---------------------------------------------------------------------------

adminRoutes.get(
  '/dashboard',
  requirePermission(PERMISSIONS.ANALYTICS_READ),
  validate({ query: dashboardQuerySchema }),
  asyncHandler(analyticsController.dashboard),
);

adminRoutes.get(
  '/security',
  requirePermission(PERMISSIONS.ANALYTICS_READ),
  validate({ query: dashboardQuerySchema }),
  asyncHandler(analyticsController.security),
);

adminRoutes.get(
  '/sessions',
  requirePermission(PERMISSIONS.SESSION_READ_ANY),
  validate({ query: listSessionsQuerySchema }),
  asyncHandler(analyticsController.listSessions),
);

adminRoutes.delete(
  '/sessions/:sessionId',
  requirePermission(PERMISSIONS.SESSION_REVOKE_ANY),
  validate({ params: sessionParamSchema }),
  asyncHandler(analyticsController.revokeSession),
);

adminRoutes.get(
  '/devices',
  requirePermission(PERMISSIONS.DEVICE_READ_ANY),
  validate({ query: listDevicesQuerySchema }),
  asyncHandler(analyticsController.listDevices),
);

adminRoutes.delete(
  '/devices/:deviceId',
  requirePermission(PERMISSIONS.DEVICE_REVOKE_ANY),
  validate({ params: deviceParamSchema }),
  asyncHandler(analyticsController.revokeDevice),
);

// ---------------------------------------------------------------------------
// Password health
// ---------------------------------------------------------------------------

adminRoutes.get(
  '/password-health/summary',
  requirePermission(PERMISSIONS.PASSWORD_HEALTH_READ_ANY),
  asyncHandler(analyticsController.healthSummary),
);

adminRoutes.get(
  '/password-health',
  requirePermission(PERMISSIONS.PASSWORD_HEALTH_READ_ANY),
  validate({ query: listHealthReportsQuerySchema }),
  asyncHandler(analyticsController.listHealthReports),
);

adminRoutes.get(
  '/password-health/:id',
  requirePermission(PERMISSIONS.PASSWORD_HEALTH_READ_ANY),
  validate({ params: idParamSchema }),
  asyncHandler(analyticsController.userHealthReport),
);

// ---------------------------------------------------------------------------
// Sessions and devices of other users
// ---------------------------------------------------------------------------

/**
 * `requireSelfOrPermission` lets an employee read their own record through the
 * admin path too, which keeps the frontend simple: one endpoint, and the API
 * decides. Reading someone else's requires `session:read:any`.
 */
adminRoutes.get(
  '/users/:id/sessions',
  requireSelfOrPermission(PERMISSIONS.SESSION_READ_ANY, 'id'),
  validate({ params: userScopeParamSchema }),
  asyncHandler(adminController.listUserSessions),
);

adminRoutes.delete(
  '/users/:id/sessions',
  requirePermission(PERMISSIONS.SESSION_REVOKE_ANY),
  validate({ params: userScopeParamSchema }),
  asyncHandler(adminController.revokeUserSessions),
);

adminRoutes.get(
  '/users/:id/devices',
  requireSelfOrPermission(PERMISSIONS.DEVICE_READ_ANY, 'id'),
  validate({ params: userScopeParamSchema }),
  asyncHandler(adminController.listUserDevices),
);

adminRoutes.delete(
  '/users/:userId/devices/:deviceId',
  requirePermission(PERMISSIONS.DEVICE_REVOKE_ANY),
  validate({ params: userDeviceParamSchema }),
  asyncHandler(adminController.revokeUserDevice),
);

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

/**
 * Audit search.
 *
 * Registered before `/audit-logs` so the more specific paths win, and separate
 * from the plain listing because it resolves names and applies the
 * personal-activity screen.
 */
adminRoutes.get(
  '/audit-logs/facets',
  requirePermission(PERMISSIONS.AUDIT_READ),
  validate({ query: auditFacetsQuerySchema }),
  asyncHandler(collaborationController.auditFacets),
);

adminRoutes.get(
  '/audit-logs/search',
  requirePermission(PERMISSIONS.AUDIT_READ),
  validate({ query: auditSearchQuerySchema }),
  asyncHandler(collaborationController.searchAudit),
);

/**
 * Export. Administrators only, and the export is itself an audited event.
 *
 * There is no counterpart for vault contents - see `EXPORT_POLICY` in
 * `@passm/shared`. The audit trail is exportable; passwords are not.
 */
adminRoutes.get(
  '/audit-logs/export',
  requirePermission(PERMISSIONS.AUDIT_EXPORT),
  sensitiveOperationLimiter,
  validate({ query: auditExportQuerySchema }),
  asyncHandler(collaborationController.exportAudit),
);

adminRoutes.get(
  '/audit-logs',
  requirePermission(PERMISSIONS.AUDIT_READ),
  validate({ query: listAuditLogsQuerySchema }),
  asyncHandler(adminController.listAuditLogs),
);

/** Every pending approval across the tenant. */
adminRoutes.get(
  '/approvals',
  requirePermission(PERMISSIONS.APPROVAL_DECIDE_ANY),
  validate({ query: listRequestsQuerySchema }),
  asyncHandler(collaborationController.listRequests),
);

// ---------------------------------------------------------------------------
// Security policy (Phase 6)
// ---------------------------------------------------------------------------

/**
 * Runtime policy.
 *
 * Read is split from write so a manager can see the thresholds that locked
 * somebody out without being able to move them. The write path additionally
 * demands a step-up check when policy says so - enforced in the controller,
 * because whether it is required is itself a setting.
 */
adminRoutes.get(
  '/settings',
  requirePermission(PERMISSIONS.SETTINGS_READ),
  asyncHandler(securityController.getSettings),
);

adminRoutes.patch(
  '/settings',
  requirePermission(PERMISSIONS.SETTINGS_WRITE),
  configurationLimiter,
  validate({ body: updateSettingsSchema }),
  asyncHandler(securityController.updateSettings),
);

adminRoutes.post(
  '/settings/reset',
  requirePermission(PERMISSIONS.SETTINGS_WRITE),
  configurationLimiter,
  validate({ body: resetSettingSchema.partial() }),
  asyncHandler(securityController.resetSettings),
);

// --- IP allow list ---------------------------------------------------------

adminRoutes.get(
  '/ip-rules',
  requirePermission(PERMISSIONS.IP_RULE_MANAGE),
  asyncHandler(securityController.listIpRules),
);

adminRoutes.post(
  '/ip-rules',
  requirePermission(PERMISSIONS.IP_RULE_MANAGE),
  validate({ body: createIpRuleSchema }),
  asyncHandler(securityController.createIpRule),
);

/**
 * The tester. A POST because it takes a body, not because it changes anything -
 * it is deliberately read-only so an administrator can probe freely before
 * committing to enforcement.
 */
adminRoutes.post(
  '/ip-rules/check',
  requirePermission(PERMISSIONS.IP_RULE_MANAGE),
  validate({ body: checkIpSchema }),
  asyncHandler(securityController.checkIp),
);

adminRoutes.patch(
  '/ip-rules/:id',
  requirePermission(PERMISSIONS.IP_RULE_MANAGE),
  validate({ params: idParamSchema, body: updateIpRuleSchema }),
  asyncHandler(securityController.updateIpRule),
);

adminRoutes.delete(
  '/ip-rules/:id',
  requirePermission(PERMISSIONS.IP_RULE_MANAGE),
  validate({ params: idParamSchema }),
  asyncHandler(securityController.deleteIpRule),
);

// --- Security score --------------------------------------------------------

adminRoutes.get(
  '/security-score',
  requirePermission(PERMISSIONS.ANALYTICS_READ),
  asyncHandler(securityController.getSecurityScore),
);

adminRoutes.get(
  '/security-score/history',
  requirePermission(PERMISSIONS.ANALYTICS_READ),
  validate({ query: scoreHistoryQuerySchema }),
  asyncHandler(securityController.getScoreHistory),
);

// --- Emergency lock --------------------------------------------------------

adminRoutes.get(
  '/emergency-lock',
  requirePermission(PERMISSIONS.SETTINGS_READ),
  asyncHandler(securityController.getEmergencyLock),
);

/**
 * The break-glass switch.
 *
 * Its own permission rather than `SETTINGS_WRITE`: this is the one control that
 * stops the whole company working, and it should be possible to grant policy
 * editing without granting that.
 */
adminRoutes.post(
  '/emergency-lock',
  requirePermission(PERMISSIONS.EMERGENCY_LOCK),
  sensitiveOperationLimiter,
  validate({ body: emergencyLockSchema }),
  asyncHandler(securityController.setEmergencyLock),
);

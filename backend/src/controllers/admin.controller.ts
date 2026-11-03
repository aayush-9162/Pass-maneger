/**
 * Administrative controller: user directory, role and status changes, oversight
 * of other people's sessions and devices, and the audit trail.
 *
 * Authorization is declared on the routes with `requirePermission`, so this file
 * contains no permission checks of its own. The service layer adds the guardrails
 * that permissions cannot express - "not the last admin", "not yourself".
 */

import { permissionsForRole } from '@passm/shared';
import type { Response } from 'express';

import type {
  LockUserDto,
  UnlockUserDto,
} from '../dto/admin.dto';
import type {
  ChangeUserRoleDto,
  ChangeUserStatusDto,
  ListAuditLogsQueryDto,
  ListUsersQueryDto,
  UpdateUserDto,
} from '../dto/user.dto';
import type { UserDeviceParamDto, UserScopeParamDto } from '../dto/device.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import type { TypedQueryRequest, TypedRequest } from '../middleware/validate.middleware';
import { toAuditLogEntry } from '../models/audit-log.model';
import { roleRepository } from '../repositories/role.repository';
import { userRepository } from '../repositories/user.repository';
import { auditService } from '../services/audit.service';
import { deviceService } from '../services/device.service';
import { userService } from '../services/user.service';
import { paginated, sendSuccess } from '../utils/api-response';

/** GET /admin/users */
export async function listUsers(
  req: TypedQueryRequest<ListUsersQueryDto>,
  res: Response,
): Promise<void> {
  const result = await userService.list({
    page: req.query.page,
    pageSize: req.query.pageSize,
    sortBy: req.query.sortBy,
    sortDir: req.query.sortDir,
    search: req.query.search,
    role: req.query.role,
    status: req.query.status,
    groupId: req.query.groupId,
  });

  sendSuccess(res, result);
}

/** GET /admin/users/:id */
export async function getUser(
  req: TypedRequest<unknown, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, { user: await userService.getDetail(req.params.id) });
}

/** PATCH /admin/users/:id */
export async function updateUser(
  req: TypedRequest<UpdateUserDto, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const user = await userService.updateProfile(req.params.id, req.body, auth, req.context);

  sendSuccess(res, { user });
}

/** PUT /admin/users/:id/role */
export async function changeUserRole(
  req: TypedRequest<ChangeUserRoleDto, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const user = await userService.changeRole(req.params.id, req.body, auth, req.context);

  sendSuccess(res, { user });
}

/** PUT /admin/users/:id/status */
export async function changeUserStatus(
  req: TypedRequest<ChangeUserStatusDto, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const user = await userService.changeStatus(req.params.id, req.body, auth, req.context);

  sendSuccess(res, { user });
}

/** DELETE /admin/users/:id - the account, its sessions and its access, in one motion. */
export async function deleteUser(
  req: TypedRequest<unknown, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const result = await userService.deleteUser(req.params.id, auth, req.context);

  sendSuccess(res, {
    ...result,
    message: 'User deleted. Their sessions were ended and their access removed.',
  });
}

/** GET /admin/users/:id/sessions */
export async function listUserSessions(
  req: TypedRequest<unknown, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, { sessions: await userService.listSessions(req.params.id) });
}

/** DELETE /admin/users/:id/sessions */
export async function revokeUserSessions(
  req: TypedRequest<unknown, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const result = await userService.revokeAllSessions(req.params.id, auth, req.context);

  sendSuccess(res, result);
}

/** GET /admin/users/:id/devices */
export async function listUserDevices(
  req: TypedRequest<unknown, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, { devices: await userService.listDevices(req.params.id) });
}

/**
 * DELETE /admin/users/:userId/devices/:deviceId
 *
 * Admin kill switch for a lost or compromised device: revokes trust and every
 * session bound to it.
 */
export async function revokeUserDevice(
  req: TypedRequest<unknown, UserDeviceParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const device = await deviceService.revokeTrust({
    deviceRowId: req.params.deviceId,
    ownerUserId: req.params.userId,
    actorUserId: auth.userId,
    context: req.context,
    blockDevice: true,
  });

  sendSuccess(res, { device });
}

/**
 * PUT /admin/users/:id/lock
 *
 * Distinct from suspension: a lock is reversible and carries a reason, and is
 * the right tool for "while we investigate". Suspension is the end of an
 * account's working life.
 */
export async function lockUser(
  req: TypedRequest<LockUserDto, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const result = await userService.lock(req.params.id, req.body, auth, req.context);

  sendSuccess(res, result);
}

/** PUT /admin/users/:id/unlock */
export async function unlockUser(
  req: TypedRequest<UnlockUserDto, UserScopeParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    user: await userService.unlock(req.params.id, req.body, auth, req.context),
  });
}

/** GET /admin/roles */
export async function listRoles(_req: TypedRequest, res: Response): Promise<void> {
  const [roles, roleCounts] = await Promise.all([
    roleRepository.findAll(),
    userRepository.countByRole(),
  ]);

  sendSuccess(res, {
    roles: roles.map((role) => ({
      id: role.id,
      name: role.name,
      label: role.label,
      description: role.description,
      level: role.level,
      isSystem: role.isSystem,
      userCount: roleCounts[role.name] ?? 0,
      // Resolved from the shared matrix rather than the database: the matrix is
      // the authority, and showing anything else would let the console display
      // permissions the API does not actually enforce.
      permissions: [...permissionsForRole(role.name)],
    })),
  });
}

/** GET /admin/audit-logs */
export async function listAuditLogs(
  req: TypedQueryRequest<ListAuditLogsQueryDto>,
  res: Response,
): Promise<void> {
  const result = await auditService.list({
    page: req.query.page,
    pageSize: req.query.pageSize,
    sortDir: req.query.sortDir,
    action: req.query.action,
    outcome: req.query.outcome,
    actorUserId: req.query.actorUserId,
    targetUserId: req.query.targetUserId,
    from: req.query.from,
    to: req.query.to,
  });

  sendSuccess(
    res,
    paginated(result.items.map(toAuditLogEntry), result.total, result.page, result.pageSize),
  );
}

export const adminController = {
  listUsers,
  getUser,
  updateUser,
  changeUserRole,
  changeUserStatus,
  deleteUser,
  lockUser,
  unlockUser,
  listUserSessions,
  revokeUserSessions,
  listUserDevices,
  revokeUserDevice,
  listRoles,
  listAuditLogs,
};

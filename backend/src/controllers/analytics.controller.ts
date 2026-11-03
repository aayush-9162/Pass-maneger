/**
 * Dashboard, security reporting, tenant-wide sessions and devices, and the
 * password-health surface.
 *
 * All read-only except for the session and device kill switches, and the health
 * upload - which is a write by the *owner* of the data, not by an administrator.
 */

import type { Response } from 'express';

import type {
  DashboardQueryDto,
  DeviceParamDto,
  ListDevicesQueryDto,
  ListHealthReportsQueryDto,
  ListSessionsQueryDto,
  SessionParamDto,
  SubmitHealthReportDto,
} from '../dto/admin.dto';
import type { IdParamDto } from '../dto/common.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import type { TypedQueryRequest, TypedRequest } from '../middleware/validate.middleware';
import { analyticsRepository } from '../repositories/analytics.repository';
import { analyticsService } from '../services/analytics.service';
import { deviceService } from '../services/device.service';
import { passwordHealthService } from '../services/password-health.service';
import { sessionService } from '../services/session.service';
import { paginated, sendSuccess } from '../utils/api-response';

/** GET /admin/dashboard */
export async function dashboard(
  req: TypedQueryRequest<DashboardQueryDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, await analyticsService.dashboard(req.query.windowDays));
}

/** GET /admin/security */
export async function security(
  req: TypedQueryRequest<DashboardQueryDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, await analyticsService.security(req.query.windowDays));
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/** GET /admin/sessions - every session in the tenant. */
export async function listSessions(
  req: TypedQueryRequest<ListSessionsQueryDto>,
  res: Response,
): Promise<void> {
  const result = await analyticsRepository.listSessions({
    page: req.query.page,
    pageSize: req.query.pageSize,
    sortBy: req.query.sortBy,
    sortDir: req.query.sortDir,
    ...(req.query.search ? { search: req.query.search } : {}),
    ...(req.query.userId ? { userId: req.query.userId } : {}),
    ...(req.query.status ? { status: req.query.status } : {}),
  });

  sendSuccess(res, paginated(result.items, result.total, result.page, result.pageSize));
}

/**
 * DELETE /admin/sessions/:sessionId
 *
 * The single-session kill switch. Revoking one session rather than all of them
 * matters when an administrator can see exactly which connection is suspect and
 * does not want to sign the person out of their laptop as well.
 */
export async function revokeSession(
  req: TypedRequest<unknown, SessionParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const result = await sessionService.revokeById(req.params.sessionId, auth, req.context);

  sendSuccess(res, result);
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

/** GET /admin/devices - every device in the tenant. */
export async function listDevices(
  req: TypedQueryRequest<ListDevicesQueryDto>,
  res: Response,
): Promise<void> {
  const result = await analyticsRepository.listDevices({
    page: req.query.page,
    pageSize: req.query.pageSize,
    sortBy: req.query.sortBy,
    sortDir: req.query.sortDir,
    ...(req.query.search ? { search: req.query.search } : {}),
    ...(req.query.userId ? { userId: req.query.userId } : {}),
    ...(req.query.status ? { status: req.query.status } : {}),
    ...(req.query.platform ? { platform: req.query.platform } : {}),
  });

  sendSuccess(res, paginated(result.items, result.total, result.page, result.pageSize));
}

/**
 * DELETE /admin/devices/:deviceId
 *
 * Revokes trust and every session bound to the device. The owner is resolved
 * from the device row rather than taken from the request, so a caller cannot
 * name someone else's device and have it attributed to a user they chose.
 */
export async function revokeDevice(
  req: TypedRequest<unknown, DeviceParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const device = await deviceService.revokeTrustById({
    deviceRowId: req.params.deviceId,
    actorUserId: auth.userId,
    context: req.context,
    blockDevice: true,
  });

  sendSuccess(res, { device });
}

// ---------------------------------------------------------------------------
// Password health
// ---------------------------------------------------------------------------

/**
 * POST /vault/password-health
 *
 * The caller uploads findings about their own vault. There is no administrative
 * equivalent, and there cannot be: the server has no plaintext to assess.
 */
export async function submitHealthReport(
  req: TypedRequest<SubmitHealthReportDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, { report: await passwordHealthService.submit(req.body, auth, req.context) });
}

/** GET /vault/password-health - the caller's own report. */
export async function ownHealthReport(req: TypedRequest, res: Response): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, await passwordHealthService.ownReport(auth.userId));
}

/** GET /admin/password-health - org-wide list. */
export async function listHealthReports(
  req: TypedQueryRequest<ListHealthReportsQueryDto>,
  res: Response,
): Promise<void> {
  sendSuccess(
    res,
    await passwordHealthService.list({
      page: req.query.page,
      pageSize: req.query.pageSize,
      sortBy: req.query.sortBy,
      sortDir: req.query.sortDir,
      ...(req.query.search ? { search: req.query.search } : {}),
      ...(req.query.maxScore !== undefined ? { maxScore: req.query.maxScore } : {}),
      ...(req.query.issue ? { issue: req.query.issue } : {}),
    }),
  );
}

/** GET /admin/password-health/summary */
export async function healthSummary(_req: TypedRequest, res: Response): Promise<void> {
  sendSuccess(res, await passwordHealthService.summary());
}

/** GET /admin/password-health/:id - one user's findings. */
export async function userHealthReport(
  req: TypedRequest<unknown, IdParamDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, await passwordHealthService.reportFor(req.params.id));
}

export const analyticsController = {
  dashboard,
  security,
  listSessions,
  revokeSession,
  listDevices,
  revokeDevice,
  submitHealthReport,
  ownHealthReport,
  listHealthReports,
  healthSummary,
  userHealthReport,
};

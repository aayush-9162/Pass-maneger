/**
 * Self-service device management ("remember this device" administration).
 *
 * Note what is *absent*: there is no endpoint that grants trust. Trust is only
 * established by a successful password login with `rememberDevice`, so an
 * attacker holding an access token cannot promote their own device to trusted.
 * These endpoints can only list, rename, and take trust away.
 */

import type { Response } from 'express';

import type { DeviceIdParamDto, RenameDeviceDto } from '../dto/device.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import type { TypedRequest } from '../middleware/validate.middleware';
import { deviceService } from '../services/device.service';
import { sendSuccess } from '../utils/api-response';
import { clearDeviceTrustCookie } from '../utils/cookies';

/** GET /auth/devices */
export async function listMyDevices(req: TypedRequest, res: Response): Promise<void> {
  const auth = requireAuth(req);
  const devices = await deviceService.listForUser(auth.userId, auth.deviceRowId);

  sendSuccess(res, { devices });
}

/** PATCH /auth/devices/:deviceId */
export async function renameMyDevice(
  req: TypedRequest<RenameDeviceDto, DeviceIdParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const device = await deviceService.rename({
    deviceRowId: req.params.deviceId,
    userId: auth.userId,
    name: req.body.name,
  });

  sendSuccess(res, { device });
}

/**
 * DELETE /auth/devices/:deviceId
 *
 * Withdraws trust and revokes the device's sessions. When the caller is revoking
 * the device they are currently using, the trust cookie is cleared too - leaving
 * it in place would present a cookie whose server-side record no longer exists.
 */
export async function revokeMyDevice(
  req: TypedRequest<unknown, DeviceIdParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const { deviceId } = req.params;

  const device = await deviceService.revokeTrust({
    deviceRowId: deviceId,
    ownerUserId: auth.userId,
    actorUserId: auth.userId,
    context: req.context,
    blockDevice: true,
  });

  if (deviceId === auth.deviceRowId) {
    clearDeviceTrustCookie(res);
  }

  sendSuccess(res, {
    device,
    wasCurrentDevice: deviceId === auth.deviceRowId,
  });
}

export const deviceController = {
  listMyDevices,
  renameMyDevice,
  revokeMyDevice,
};

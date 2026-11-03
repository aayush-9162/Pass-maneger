/**
 * Per-user vault routes: the caller's own password health report.
 *
 * Everything else about passwords - groups, items, access - lives in the
 * shared routes, because every credential belongs to a shared vault.
 */

import { PERMISSIONS } from '@passm/shared';
import { Router } from 'express';

import { analyticsController } from '../controllers/analytics.controller';
import { submitHealthReportSchema } from '../dto/admin.dto';
import { authenticate } from '../middleware/authenticate.middleware';
import { postAuthSecurityGates } from '../middleware';
import { requirePermission } from '../middleware/authorize.middleware';
import { validate } from '../middleware/validate.middleware';
import { asyncHandler } from '../utils/async-handler';

export const vaultRoutes = Router();

// Applies to every route below, including any added later.
vaultRoutes.use(authenticate, ...postAuthSecurityGates());

vaultRoutes.get(
  '/password-health',
  requirePermission(PERMISSIONS.VAULT_READ),
  asyncHandler(analyticsController.ownHealthReport),
);

vaultRoutes.post(
  '/password-health',
  requirePermission(PERMISSIONS.VAULT_READ),
  validate({ body: submitHealthReportSchema }),
  asyncHandler(analyticsController.submitHealthReport),
);

/**
 * Shared vault routes, scoped by *membership* rather than by role.
 *
 * Notice how little permission middleware appears here. That is deliberate: a
 * route-level `requirePermission` can only ask "does this role hold X", and the
 * question that matters for a shared vault is "does this person have a grant on
 * *this* vault" - which depends on the id in the path. So the checks live in
 * `sharedVaultService`, close to the data they consult, and this file only
 * guarantees the caller is authenticated and past the security gates.
 *
 * The exceptions are creating a vault or an individual password, which need no
 * per-object check because there is no object yet.
 */

import { PERMISSIONS } from '@passm/shared';
import { Router } from 'express';

import { collaborationController } from '../controllers/collaboration.controller';
import { sharedVaultController } from '../controllers/shared-vault.controller';
import {
  createAccessRequestSchema,
  decideAccessRequestSchema,
  listRequestsQuerySchema,
  reportAccessEventsSchema,
  requestParamSchema,
} from '../dto/collaboration.dto';
import {
  createGrantSchema,
  createSharedItemSchema,
  createSharedVaultSchema,
  grantParamSchema,
  itemSecretQuerySchema,
  listSharedItemsQuerySchema,
  moveSharedItemSchema,
  sharedItemParamSchema,
  sharedVaultParamSchema,
  updateGrantSchema,
  updateSharedItemSchema,
  updateSharedVaultSchema,
} from '../dto/sharing.dto';
import { authenticate } from '../middleware/authenticate.middleware';
import { postAuthSecurityGates } from '../middleware';
import { requirePermission } from '../middleware/authorize.middleware';
import { validate } from '../middleware/validate.middleware';
import { asyncHandler } from '../utils/async-handler';

export const sharedRoutes = Router();

sharedRoutes.use(authenticate, ...postAuthSecurityGates());

// ---------------------------------------------------------------------------
// Vaults
// ---------------------------------------------------------------------------

/** GET /shared/vaults - the caller's own, with their rights on each. */
sharedRoutes.get(
  '/vaults',
  requirePermission(PERMISSIONS.SHARED_VAULT_READ),
  asyncHandler(sharedVaultController.listMyVaults),
);

sharedRoutes.post(
  '/vaults',
  requirePermission(PERMISSIONS.SHARED_VAULT_READ),
  validate({ body: createSharedVaultSchema }),
  asyncHandler(sharedVaultController.createVault),
);

sharedRoutes.get(
  '/vaults/:vaultId',
  validate({ params: sharedVaultParamSchema }),
  asyncHandler(sharedVaultController.getVault),
);

sharedRoutes.patch(
  '/vaults/:vaultId',
  validate({ params: sharedVaultParamSchema, body: updateSharedVaultSchema }),
  asyncHandler(sharedVaultController.updateVault),
);

sharedRoutes.delete(
  '/vaults/:vaultId',
  validate({ params: sharedVaultParamSchema }),
  asyncHandler(sharedVaultController.deleteVault),
);

// ---------------------------------------------------------------------------
// Access
// ---------------------------------------------------------------------------

sharedRoutes.get(
  '/vaults/:vaultId/access',
  validate({ params: sharedVaultParamSchema }),
  asyncHandler(sharedVaultController.getAccess),
);

sharedRoutes.post(
  '/vaults/:vaultId/grants',
  validate({ params: sharedVaultParamSchema, body: createGrantSchema }),
  asyncHandler(sharedVaultController.addGrant),
);

sharedRoutes.patch(
  '/vaults/:vaultId/grants/:grantId',
  validate({ params: grantParamSchema, body: updateGrantSchema }),
  asyncHandler(sharedVaultController.updateGrant),
);

sharedRoutes.delete(
  '/vaults/:vaultId/grants/:grantId',
  validate({ params: grantParamSchema }),
  asyncHandler(sharedVaultController.revokeGrant),
);

// ---------------------------------------------------------------------------
// Approval workflow
//
// Requests are membership-scoped like everything else here: who may decide one
// depends on the vault it names, so the check lives in `approvalService` rather
// than in route middleware that can only see the caller's role.
// ---------------------------------------------------------------------------

sharedRoutes.get(
  '/requests/pending-count',
  asyncHandler(collaborationController.pendingRequestCount),
);

sharedRoutes.get(
  '/requests',
  validate({ query: listRequestsQuerySchema }),
  asyncHandler(collaborationController.listRequests),
);

sharedRoutes.post(
  '/requests/:requestId/decide',
  validate({ params: requestParamSchema, body: decideAccessRequestSchema }),
  asyncHandler(collaborationController.decideRequest),
);

sharedRoutes.delete(
  '/requests/:requestId',
  validate({ params: requestParamSchema }),
  asyncHandler(collaborationController.cancelRequest),
);

sharedRoutes.post(
  '/vaults/:vaultId/requests',
  validate({ params: sharedVaultParamSchema, body: createAccessRequestSchema }),
  asyncHandler(collaborationController.createRequest),
);

/**
 * Client-observed access events: refused reveals, tampered fills.
 *
 * Not rate limited into uselessness - dropping events would put holes in the
 * trail. The batch cap in the DTO is what bounds the write volume instead.
 */
sharedRoutes.post(
  '/access-events',
  validate({ body: reportAccessEventsSchema }),
  asyncHandler(collaborationController.reportAccessEvents),
);

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

sharedRoutes.get(
  '/vaults/:vaultId/items',
  validate({ params: sharedVaultParamSchema, query: listSharedItemsQuerySchema }),
  asyncHandler(sharedVaultController.listItems),
);

sharedRoutes.post(
  '/vaults/:vaultId/items',
  validate({ params: sharedVaultParamSchema, body: createSharedItemSchema }),
  asyncHandler(sharedVaultController.createItem),
);

/** An individual password: the server wraps it in a vault of its own. */
sharedRoutes.post(
  '/items',
  requirePermission(PERMISSIONS.SHARED_VAULT_READ),
  validate({ body: createSharedItemSchema }),
  asyncHandler(sharedVaultController.createIndividualItem),
);

sharedRoutes.get(
  '/vaults/:vaultId/items/:itemId',
  validate({ params: sharedItemParamSchema }),
  asyncHandler(sharedVaultController.getItem),
);

/** The one route a password leaves the server by. Audited per call. */
sharedRoutes.get(
  '/vaults/:vaultId/items/:itemId/secret',
  validate({ params: sharedItemParamSchema, query: itemSecretQuerySchema }),
  asyncHandler(sharedVaultController.getSecret),
);

sharedRoutes.patch(
  '/vaults/:vaultId/items/:itemId',
  validate({ params: sharedItemParamSchema, body: updateSharedItemSchema }),
  asyncHandler(sharedVaultController.updateItem),
);

sharedRoutes.delete(
  '/vaults/:vaultId/items/:itemId',
  validate({ params: sharedItemParamSchema }),
  asyncHandler(sharedVaultController.deleteItem),
);

sharedRoutes.post(
  '/vaults/:vaultId/items/:itemId/move',
  validate({ params: sharedItemParamSchema, body: moveSharedItemSchema }),
  asyncHandler(sharedVaultController.moveItem),
);

sharedRoutes.post(
  '/vaults/:vaultId/items/:itemId/restore',
  validate({ params: sharedItemParamSchema }),
  asyncHandler(sharedVaultController.restoreItem),
);

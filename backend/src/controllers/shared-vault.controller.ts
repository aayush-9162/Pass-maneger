/**
 * Shared vault endpoints.
 *
 * Split across two routers by *authority*, not by resource:
 *
 *  - `/admin/shared-vaults/*` - governance. Requires `shared_vault:manage`.
 *  - `/shared/vaults/*`       - membership. Requires a grant on the vault.
 *
 * Both land in this controller because the service enforces the distinction, and
 * duplicating the handlers would mean two places to get the checks right.
 */

import type { Response } from 'express';

import type { SecretPurpose } from '@passm/shared';

import type {
  CreateGrantDto,
  CreateSharedItemDto,
  CreateSharedVaultDto,
  GrantParamDto,
  ItemSecretQueryDto,
  ListSharedItemsQueryDto,
  ListSharedVaultsQueryDto,
  MoveSharedItemDto,
  SharedItemParamDto,
  SharedVaultParamDto,
  UpdateGrantDto,
  UpdateSharedItemDto,
  UpdateSharedVaultDto,
} from '../dto/sharing.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import type { TypedQueryRequest, TypedRequest } from '../middleware/validate.middleware';
import { sharedVaultService } from '../services/shared-vault.service';
import { sendCreated, sendSuccess } from '../utils/api-response';

// ---------------------------------------------------------------------------
// Vaults
// ---------------------------------------------------------------------------

/** GET /admin/shared-vaults */
export async function listAllVaults(
  req: TypedQueryRequest<ListSharedVaultsQueryDto>,
  res: Response,
): Promise<void> {
  sendSuccess(
    res,
    await sharedVaultService.listAll({
      page: req.query.page,
      pageSize: req.query.pageSize,
      sortBy: req.query.sortBy,
      sortDir: req.query.sortDir,
      ...(req.query.search ? { search: req.query.search } : {}),
      ...(req.query.status ? { status: req.query.status } : {}),
      ...(req.query.kind ? { kind: req.query.kind } : {}),
    }),
  );
}

/** GET /shared/vaults - the caller's own, with their rights on each. */
export async function listMyVaults(req: TypedRequest, res: Response): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, { vaults: await sharedVaultService.listForMember(auth.userId) });
}

/** GET /admin/shared-vaults/:vaultId | GET /shared/vaults/:vaultId */
export async function getVault(
  req: TypedRequest<unknown, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, { vault: await sharedVaultService.getById(req.params.vaultId) });
}

/** POST /shared/vaults */
export async function createVault(
  req: TypedRequest<CreateSharedVaultDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const vault = await sharedVaultService.create(req.body, auth, req.context);

  sendCreated(res, { vault }, `/api/v1/shared/vaults/${vault.id}`);
}

/** PATCH /shared/vaults/:vaultId */
export async function updateVault(
  req: TypedRequest<UpdateSharedVaultDto, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    vault: await sharedVaultService.update(req.params.vaultId, req.body, auth, req.context),
  });
}

/** DELETE /shared/vaults/:vaultId */
export async function deleteVault(
  req: TypedRequest<unknown, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const result = await sharedVaultService.remove(req.params.vaultId, auth, req.context);

  sendSuccess(res, {
    ...result,
    message:
      'Deleted, and everyone has lost access. Rotate any credentials it held - anyone who read them still knows them.',
  });
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/** GET /shared/vaults/:vaultId/access */
export async function getAccess(
  req: TypedRequest<unknown, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, { grants: await sharedVaultService.listGrants(req.params.vaultId, auth) });
}

/** POST /shared/vaults/:vaultId/grants */
export async function addGrant(
  req: TypedRequest<CreateGrantDto, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    grants: await sharedVaultService.addGrant(req.params.vaultId, req.body, auth, req.context),
  });
}

/** PATCH /shared/vaults/:vaultId/grants/:grantId */
export async function updateGrant(
  req: TypedRequest<UpdateGrantDto, GrantParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    grants: await sharedVaultService.updateGrant(
      req.params.vaultId,
      req.params.grantId,
      req.body,
      auth,
      req.context,
    ),
  });
}

/** DELETE /shared/vaults/:vaultId/grants/:grantId */
export async function revokeGrant(
  req: TypedRequest<unknown, GrantParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const result = await sharedVaultService.revokeGrant(
    req.params.vaultId,
    req.params.grantId,
    auth,
    req.context,
  );

  sendSuccess(res, {
    ...result,
    message:
      'Access revoked. Rotate the credentials in this vault - revoking access does not un-know a password they have already read.',
  });
}

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

/** GET /shared/vaults/:vaultId/items */
export async function listItems(
  req: TypedQueryRequest<ListSharedItemsQueryDto, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, await sharedVaultService.listItems(req.params.vaultId, req.query, auth));
}

/** GET /shared/vaults/:vaultId/items/:itemId */
export async function getItem(
  req: TypedRequest<unknown, SharedItemParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    item: await sharedVaultService.getItem(req.params.vaultId, req.params.itemId, auth),
  });
}

/** GET /shared/vaults/:vaultId/items/:itemId/secret?purpose=view|copy|fill|edit */
export async function getSecret(
  req: TypedQueryRequest<ItemSecretQueryDto, SharedItemParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  // Never cached anywhere between here and the client.
  res.setHeader('Cache-Control', 'no-store');
  sendSuccess(res, {
    secret: await sharedVaultService.getSecret(
      req.params.vaultId,
      req.params.itemId,
      req.query.purpose as SecretPurpose,
      auth,
      req.context,
    ),
  });
}

/** POST /shared/vaults/:vaultId/items */
export async function createItem(
  req: TypedRequest<CreateSharedItemDto, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const item = await sharedVaultService.createItem(req.params.vaultId, req.body, auth, req.context);

  sendCreated(res, { item });
}

/** POST /shared/items - an individual password, in a wrapper of its own. */
export async function createIndividualItem(
  req: TypedRequest<CreateSharedItemDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const item = await sharedVaultService.createIndividualItem(req.body, auth, req.context);

  sendCreated(res, { item });
}

/** PATCH /shared/vaults/:vaultId/items/:itemId */
export async function updateItem(
  req: TypedRequest<UpdateSharedItemDto, SharedItemParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    item: await sharedVaultService.updateItem(
      req.params.vaultId,
      req.params.itemId,
      req.body,
      auth,
      req.context,
    ),
  });
}

/** POST /shared/vaults/:vaultId/items/:itemId/move */
export async function moveItem(
  req: TypedRequest<MoveSharedItemDto, SharedItemParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    item: await sharedVaultService.moveItem(
      req.params.vaultId,
      req.params.itemId,
      req.body,
      auth,
      req.context,
    ),
  });
}

/** DELETE /shared/vaults/:vaultId/items/:itemId?permanent=true */
export async function deleteItem(
  req: TypedRequest<unknown, SharedItemParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const permanent = req.query.permanent === 'true';

  sendSuccess(
    res,
    await sharedVaultService.deleteItem(
      req.params.vaultId, req.params.itemId, permanent, auth, req.context,
    ),
  );
}

/** POST /shared/vaults/:vaultId/items/:itemId/restore */
export async function restoreItem(
  req: TypedRequest<unknown, SharedItemParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    item: await sharedVaultService.restoreItem(
      req.params.vaultId,
      req.params.itemId,
      auth,
      req.context,
    ),
  });
}

export const sharedVaultController = {
  listAllVaults,
  listMyVaults,
  getVault,
  createVault,
  updateVault,
  deleteVault,
  getAccess,
  addGrant,
  updateGrant,
  revokeGrant,
  listItems,
  getItem,
  getSecret,
  createItem,
  createIndividualItem,
  updateItem,
  moveItem,
  deleteItem,
  restoreItem,
};

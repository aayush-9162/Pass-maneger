/**
 * Approvals, audit search and export, and client-reported access events.
 */

import type { Response } from 'express';

import type {
  AuditExportQueryDto,
  AuditFacetsQueryDto,
  AuditSearchQueryDto,
  CreateAccessRequestDto,
  DecideAccessRequestDto,
  ListRequestsQueryDto,
  ReportAccessEventsDto,
  RequestParamDto,
} from '../dto/collaboration.dto';
import type { SharedVaultParamDto } from '../dto/sharing.dto';
import { requireAuth } from '../middleware/authenticate.middleware';
import type { TypedQueryRequest, TypedRequest } from '../middleware/validate.middleware';
import { approvalService } from '../services/approval.service';
import { auditSearchService } from '../services/audit-search.service';
import { sendCreated, sendSuccess } from '../utils/api-response';

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

/** POST /shared/vaults/:vaultId/requests */
export async function createRequest(
  req: TypedRequest<CreateAccessRequestDto, SharedVaultParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  const request = await approvalService.create(req.params.vaultId, req.body, auth, req.context);

  sendCreated(res, { request });
}

/**
 * GET /shared/requests
 *
 * `view=inbox` returns requests awaiting the caller's decision; `view=mine`
 * returns the ones they raised. Two views of one table rather than two
 * endpoints, because the console shows them side by side.
 */
export async function listRequests(
  req: TypedQueryRequest<ListRequestsQueryDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const filter = {
    page: req.query.page,
    pageSize: req.query.pageSize,
    sortDir: req.query.sortDir,
    ...(req.query.status ? { status: req.query.status } : {}),
    ...(req.query.sharedVaultId ? { sharedVaultId: req.query.sharedVaultId } : {}),
  };

  sendSuccess(
    res,
    req.query.view === 'mine'
      ? await approvalService.listMine(auth, filter)
      : await approvalService.listForApprover(auth, filter),
  );
}

/** GET /shared/requests/pending-count - drives the console's navigation badge. */
export async function pendingRequestCount(req: TypedRequest, res: Response): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, { pending: await approvalService.pendingCount(auth) });
}

/** POST /shared/requests/:requestId/decide */
export async function decideRequest(
  req: TypedRequest<DecideAccessRequestDto, RequestParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(
    res,
    await approvalService.decide(req.params.requestId, req.body, auth, req.context),
  );
}

/** DELETE /shared/requests/:requestId - withdraw one's own request. */
export async function cancelRequest(
  req: TypedRequest<unknown, RequestParamDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, {
    request: await approvalService.cancel(req.params.requestId, auth, req.context),
  });
}

// ---------------------------------------------------------------------------
// Access events
// ---------------------------------------------------------------------------

/**
 * POST /shared/access-events
 *
 * The client reporting what it did after decryption. Attribution comes from the
 * token, never from the body.
 */
export async function reportAccessEvents(
  req: TypedRequest<ReportAccessEventsDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  sendSuccess(res, await auditSearchService.reportAccessEvents(req.body, auth, req.context));
}

// ---------------------------------------------------------------------------
// Audit search and export
// ---------------------------------------------------------------------------

/** GET /admin/audit-logs/search */
export async function searchAudit(
  req: TypedQueryRequest<AuditSearchQueryDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);
  sendSuccess(res, await auditSearchService.search(req.query, auth));
}

/** GET /admin/audit-logs/facets */
export async function auditFacets(
  req: TypedQueryRequest<AuditFacetsQueryDto>,
  res: Response,
): Promise<void> {
  sendSuccess(res, await auditSearchService.facets(req.query.windowDays));
}

/**
 * GET /admin/audit-logs/export
 *
 * Streamed rather than assembled: a year of history is tens of megabytes, and
 * building that in memory to send in one piece is how an export endpoint takes
 * the process down.
 *
 * Headers go out before the first chunk, so an error after streaming has begun
 * cannot become a JSON error response - the connection is simply cut, and the
 * truncated file is the signal. That is the usual trade for streaming, and the
 * reason the permission check happens before any of it.
 */
export async function exportAudit(
  req: TypedQueryRequest<AuditExportQueryDto>,
  res: Response,
): Promise<void> {
  const auth = requireAuth(req);

  const stamp = new Date().toISOString().slice(0, 10);
  const extension = req.query.format === 'json' ? 'json' : 'csv';

  res.setHeader(
    'Content-Type',
    extension === 'json' ? 'application/json; charset=utf-8' : 'text/csv; charset=utf-8',
  );
  res.setHeader('Content-Disposition', `attachment; filename="passm-audit-${stamp}.${extension}"`);
  // The export contains personal data; no cache should keep a copy.
  res.setHeader('Cache-Control', 'no-store');

  for await (const chunk of auditSearchService.exportStream(req.query, auth, req.context)) {
    res.write(chunk);
  }

  res.end();
}

export const collaborationController = {
  createRequest,
  listRequests,
  pendingRequestCount,
  decideRequest,
  cancelRequest,
  reportAccessEvents,
  searchAudit,
  auditFacets,
  exportAudit,
};

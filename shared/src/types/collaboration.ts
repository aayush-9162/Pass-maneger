/**
 * Collaboration contracts: approval requests, and the audit surface Phase 5
 * requires.
 */

import type {
  RequestStatus,
  RequestType,
  VaultRole,
} from '../constants/collaboration';
import type { AuditAction, AuditOutcome } from './audit';

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

export interface AccessRequest {
  id: string;
  sharedVaultId: string;
  vaultName: string;
  requesterUserId: string;
  requesterName: string;
  requesterEmail: string;
  requestType: RequestType;
  requestedRole: VaultRole | null;
  itemId: string | null;
  reason: string;
  status: RequestStatus;
  decidedByUserId: string | null;
  decidedByName: string | null;
  decidedAt: string | null;
  decisionNote: string | null;
  expiresAt: string;
  createdAt: string;
}

export interface CreateAccessRequestBody {
  requestType: RequestType;
  requestedRole?: VaultRole;
  itemId?: string;
  reason: string;
}

export interface DecideAccessRequestBody {
  /** `true` approves, `false` denies. Both are recorded; neither is silent. */
  approve: boolean;
  note?: string;
}

/**
 * The outcome of approving a request.
 *
 * Approving a *reveal* takes effect at once: the server releases the vault's
 * passwords to the requester from the next request on.
 */
export interface AccessRequestDecision {
  request: AccessRequest;
  grantCreated: boolean;
  message: string;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/**
 * An audit row with every reference resolved for display.
 *
 * Resolved server-side rather than by the client joining on ids, because the
 * subject of an audit row may have been deleted since - and a compliance trail
 * that renders "user 4f2a…" for a departed employee is not much of a trail.
 */
export interface AuditEntryView {
  id: string;
  action: AuditAction;
  outcome: AuditOutcome;

  actorUserId: string | null;
  actorEmail: string | null;
  actorName: string | null;

  targetUserId: string | null;
  targetEmail: string | null;
  targetName: string | null;

  resourceType: string | null;
  resourceId: string | null;
  /** Human label for the resource, e.g. the shared vault's name. */
  resourceName: string | null;
  isSharedResource: boolean;

  ipAddress: string | null;
  userAgent: string | null;
  deviceId: string | null;
  deviceName: string | null;
  sessionId: string | null;
  requestId: string | null;

  metadata: Record<string, unknown> | null;
  createdAt: string;
}

/** Every filter the audit search supports. */
export interface AuditSearchQuery {
  page?: number;
  pageSize?: number;
  sortDir?: 'asc' | 'desc';
  /** Free text over actor email, actor name and IP address. */
  search?: string;
  /** Exact actor. */
  actorUserId?: string;
  /** Exact subject. */
  targetUserId?: string;
  /** One action, or a category prefix such as `shared_vault`. */
  action?: string;
  outcome?: AuditOutcome;
  ipAddress?: string;
  deviceId?: string;
  resourceId?: string;
  from?: string;
  to?: string;
  /** Restrict to organisational events, excluding personal-vault activity. */
  sharedOnly?: boolean;
}

/**
 * A client-observed event, reported so it can be audited.
 *
 * The server cannot see a password being viewed or copied: both happen entirely
 * in the browser, after decryption. So the client reports them.
 *
 * This is a *cooperative* trail, and worth being precise about: it records what
 * an honest client did. A modified client can decline to report, and no design
 * that decrypts in the browser can prevent that. It is still worth having -
 * every real access by every normal user is captured, which is what an
 * investigation and an access review actually need.
 */
export interface ReportAccessEventBody {
  /** One of the item-access audit actions. */
  action: 'viewed' | 'copied' | 'filled' | 'exported_attempt' | 'reveal_blocked';
  itemId: string;
  /** Present when the item is in a shared vault. */
  sharedVaultId?: string;
  /** Which field was touched. Never the value. */
  field?: 'password' | 'totp' | 'note' | 'card_number' | 'private_key' | 'api_secret';
  /**
   * Hostname the browser was on, for events that happen on a third-party site.
   *
   * The browser extension reports this when a filled password field is
   * tampered with. Without it the trail says only that *an* item was involved,
   * and the item id names a row the reader cannot decrypt - so the hostname is
   * the only part that tells an investigator which account was targeted.
   *
   * Hostname only. Never a full URL: paths and query strings routinely carry
   * tokens, and this is written to a log an administrator exports.
   */
  host?: string;
}

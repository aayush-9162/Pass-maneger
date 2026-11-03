/** Server-side authentication types. */

import type { Permission, RoleName } from '@passm/shared';

/**
 * Everything the server knows about the caller after `authenticate` succeeds.
 *
 * Sourced from the verified access token *plus* a session validity check, so a
 * revoked session cannot keep acting on a still-unexpired token.
 */
export interface AuthContext {
  userId: string;
  email: string;
  role: RoleName;
  /** Effective permissions, re-resolved from the role on every request. */
  permissions: readonly Permission[];
  sessionId: string;
  /** `devices.id` (internal row id), not the client-generated `device_id`. */
  deviceRowId: string;
  /** Whether the request's device carries a valid trust grant. */
  deviceTrusted: boolean;
  /** `jti` of the presented access token. */
  tokenId: string;
}

/**
 * Request-scoped facts needed by the audit trail and by security decisions.
 * Assembled once per request so services need not receive `req` itself, which
 * keeps them framework-independent and testable.
 */
export interface RequestContext {
  requestId: string;
  ipAddress: string;
  userAgent: string | null;
  /**
   * The browser extension made this request. It may only use passwords, never
   * change them - see `sharedVaultService.assertMayChange`.
   */
  fromExtension?: boolean;
}

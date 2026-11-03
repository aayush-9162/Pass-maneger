/**
 * Typed message protocol.
 *
 * ## The trust boundary
 *
 * All privileged work happens in the service worker. Two different callers talk
 * to it, and they are trusted differently:
 *
 *  - **Extension pages** (popup, side panel) are trusted. They may unlock the
 *    vault, read the index and request a secret.
 *  - **Content scripts** run inside whatever page the user visited, including
 *    hostile ones. They may only *report* what they observed and *request* an
 *    action the user has already initiated. They never receive the tokens,
 *    never receive the item index, and never receive a secret they did not ask
 *    for on behalf of a user gesture.
 *
 * `isContentRequest` below marks which messages a content script may send; the
 * worker rejects anything else arriving from a tab.
 *
 * Every message is a discriminated union member, so adding a case without
 * handling it is a compile error rather than a silent runtime no-op.
 */

import type { PublicUser, VaultItemType } from '@passm/shared';

import type { VaultIndexEntry } from './storage';
import type { MatchConfidence } from './uri-match';

// ---------------------------------------------------------------------------
// Shared payloads
// ---------------------------------------------------------------------------

export interface AuthStatePayload {
  authenticated: boolean;
  user: PublicUser | null;
  sessionId: string | null;
  accessTokenExpiresAt: number | null;
}

/** `locked`: signed in, but the item list is not loaded (yet, or it failed). */
export type VaultLockState = 'no_session' | 'locked' | 'unlocked';

export interface VaultStatePayload {
  state: VaultLockState;
  itemCount: number;
  syncedAt: string | null;
  /** Epoch ms at which the vault auto-locks. */
  lockAt: number | null;
}

/** A credential offered for a page. Contains no secret. */
export interface CredentialSuggestion {
  itemId: string;
  name: string;
  username: string | null;
  confidence: MatchConfidence;
  confidenceLabel: string;
}

/** The secret half, released only in response to a user action. */
export interface CredentialSecret {
  itemId: string;
  username: string | null;
  password: string | null;
  totp: string | null;
}

/** What a content script observed about the page. */
// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

export type BackgroundRequest =
  // --- Authentication (extension pages only) -------------------------------
  | { type: 'AUTH_STATE' }
  /** Opens Google's sign-in window from the worker; the popup may close meanwhile. */
  | { type: 'LOGIN'; rememberDevice: boolean }
  | { type: 'LOGOUT' }

  // --- Vault lifecycle (extension pages only) ------------------------------
  | { type: 'VAULT_STATE' }
  | { type: 'VAULT_UNLOCK' }
  /** The server address changed: reload everything from the new one. */
  | { type: 'SERVER_CHANGED' }
  | { type: 'VAULT_LOCK' }
  | { type: 'VAULT_SYNC' }
  | { type: 'VAULT_SEARCH'; query: string; limit?: number }
  | { type: 'VAULT_RECENT'; limit?: number }
  | { type: 'VAULT_FAVORITES'; limit?: number }
  /** Star or unstar an item. Stored on this device only - see `lib/favorites`. */
  | { type: 'TOGGLE_FAVORITE'; itemId: string }
  /** The ids this device has starred, so the list can render the stars. */
  | { type: 'GET_FAVORITES' }

  /*
   * No message asks the worker for a stored password.
   *
   * `GET_SECRET` and `COPY_SECRET` were removed with the copy buttons they
   * served. A password now leaves the worker only via `REQUEST_FILL`, which
   * checks the item belongs to the page asking, and goes straight into the
   * form - never to an extension page, and never to the clipboard.
   */

  // --- Content-script messages ---------------------------------------------
  /** "This page has a login form; what do you have for it?" - no secrets returned. */
  | { type: 'PAGE_SUGGESTIONS'; url: string }
  /** "The user clicked fill on this suggestion." Releases the secret to the tab. */
  | { type: 'REQUEST_FILL'; itemId: string; url: string }
  /**
   * "Someone unmasked a filled password field."
   *
   * The content script has already put the mask back; this exists so the attempt
   * reaches the audit trail rather than being invisible.
   */
  | { type: 'REPORT_FIELD_TAMPER'; itemId: string; host: string }
  /** Fill the active tab from the popup, side panel or context menu. */
  | { type: 'FILL_ACTIVE_TAB'; itemId: string }
  /**
   * Open the item's site, wait for it to load, fill and sign in.
   *
   * One action from the popup instead of "copy username, switch tab, paste,
   * copy password, paste, click". The credential travels to the content script
   * only after the page has loaded, so it is never held anywhere longer than the
   * fill itself.
   */
  | { type: 'LAUNCH_AND_FILL'; itemId: string }
  | { type: 'OPEN_SIDE_PANEL' }
  | { type: 'GENERATE_PASSWORD'; length?: number; pronounceable?: boolean };

/**
 * Messages a content script is permitted to send.
 *
 * Anything else arriving from a tab is refused: a compromised page could
 * otherwise ask the worker to hand over the whole index or a secret it was never
 * offered.
 */
const CONTENT_ALLOWED = new Set<BackgroundRequest['type']>([
  'PAGE_SUGGESTIONS',
  'REQUEST_FILL',
  'REPORT_FIELD_TAMPER',
]);

export function isContentRequest(type: BackgroundRequest['type']): boolean {
  return CONTENT_ALLOWED.has(type);
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

export type BackgroundResponse<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; code?: string };

export interface SuggestionsPayload {
  suggestions: CredentialSuggestion[];
  vaultState: VaultLockState;
  /**
   * Whether the content script should fill without being asked.
   *
   * Carried here rather than read directly: the content script runs in the
   * page's world and deliberately has no storage access, so every setting it
   * needs arrives through the worker.
   */
  autoFillOnLoad: boolean;
}

export interface SearchResultPayload {
  items: VaultIndexEntry[];
}

// ---------------------------------------------------------------------------
// Background -> content script
// ---------------------------------------------------------------------------

export type ContentRequest =
  /** Fill these values into the recognised fields. */
  | {
      type: 'CONTENT_FILL';
      /**
       * The vault item this came from.
       *
       * Carried so the content script can guard the filled password field and
       * name the item if the mask is tampered with. Without it this path filled
       * a password that nothing was watching - which is exactly what happened
       * when the popup filled rather than the inline button.
       */
      itemId: string;
      username: string | null;
      password: string | null;
      totp: string | null;
      /** Submit the form after filling, as if the user pressed Enter. */
      submit?: boolean;
    }
  /** Refresh the inline button state after the vault locked or unlocked. */
  | { type: 'CONTENT_VAULT_STATE'; state: VaultLockState; suggestionCount: number }
  | { type: 'CONTENT_PROBE' };

export interface ContentProbeResult {
  hasPasswordField: boolean;
  hasLoginForm: boolean;
  origin: string;
}

export interface FillResultPayload {
  filled: boolean;
  reason?: string;
}

/** Send a typed request to the service worker. */
export async function sendToBackground<T>(
  request: BackgroundRequest,
): Promise<BackgroundResponse<T>> {
  try {
    return (await chrome.runtime.sendMessage(request)) as BackgroundResponse<T>;
  } catch (error) {
    // Thrown while the worker is starting, or when the extension context was
    // invalidated by a reload.
    return {
      ok: false,
      error:
        error instanceof Error ? error.message : 'The extension background is unavailable.',
    };
  }
}

/** Item types that can carry a fillable credential. */
export const FILLABLE_TYPES: readonly VaultItemType[] = ['login', 'api_key', 'ssh_key'];

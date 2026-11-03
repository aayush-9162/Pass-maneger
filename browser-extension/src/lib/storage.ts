/**
 * Extension storage.
 *
 * ## Why `chrome.storage.session` and not module variables
 *
 * An MV3 service worker is suspended after roughly 30 seconds of inactivity and
 * every module-level variable dies with it. The item index would have to be
 * fetched again every time the user paused for half a minute.
 *
 * `chrome.storage.session` is memory-backed, never written to disk, cleared when
 * the browser closes, and - with the access level pinned below - unreachable
 * from content scripts.
 *
 * ## What is stored, and what is not
 *
 * | Data | Store | Reasoning |
 * | --- | --- | --- |
 * | Auth tokens | local | Survive a browser restart, like a signed-in website's cookies. |
 * | Item **index** | session | Names, usernames and sites. Fetched again on demand. |
 * | Item **passwords** | nowhere | Fetched from the server one at a time, for the moment it takes to fill or copy. |
 * | Device id, settings | local | Not secret, and should survive a restart. |
 *
 * The refresh token on disk is what "stay signed in" costs: anyone with this OS
 * profile can use it until it expires or the session is revoked from the
 * console. Signing out erases it.
 */

import type { PublicUser, VaultItemType } from '@passm/shared';

const AUTH_SESSION_KEY = 'passm.session';
const VAULT_SESSION_KEY = 'passm.vault';
const DEVICE_ID_KEY = 'passm.deviceId';

// ---------------------------------------------------------------------------
// Authentication session
// ---------------------------------------------------------------------------

export interface StoredSession {
  accessToken: string;
  refreshToken: string;
  /** Epoch milliseconds at which `accessToken` expires. */
  accessTokenExpiresAt: number;
  user: PublicUser;
  sessionId: string;
}

/**
 * Restrict session storage to trusted contexts (popup, side panel, worker).
 *
 * Content scripts share the extension id but must never reach tokens or the
 * index, and they are the part of the extension that runs on hostile pages.
 */
export async function lockDownSessionStorage(): Promise<void> {
  try {
    await chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  } catch {
    // Older Chrome: TRUSTED_CONTEXTS is already the default.
  }
}

export async function readSession(): Promise<StoredSession | null> {
  const stored = await chrome.storage.local.get(AUTH_SESSION_KEY);
  return (stored[AUTH_SESSION_KEY] as StoredSession | undefined) ?? null;
}

export async function writeSession(session: StoredSession): Promise<void> {
  await chrome.storage.local.set({ [AUTH_SESSION_KEY]: session });
}

export async function clearSession(): Promise<void> {
  await chrome.storage.local.remove(AUTH_SESSION_KEY);
  // Any session cached in the memory store under an older build goes too.
  await chrome.storage.session.remove(AUTH_SESSION_KEY);
}

// ---------------------------------------------------------------------------
// Vault session
// ---------------------------------------------------------------------------

/**
 * One searchable item, with every secret removed.
 *
 * This is what the popup and side panel search against. Filling or copying a
 * password goes back to the worker, which fetches it at that moment.
 */
export interface VaultIndexEntry {
  id: string;
  vaultId: string;
  type: VaultItemType;
  name: string;
  /** Shown as the subtitle and used for matching; not a secret. */
  username: string | null;
  uris: string[];
  tags: string[];
  favorite: boolean;
  updatedAt: string;
  /** True when the item actually carries a password worth filling. */
  hasPassword: boolean;
}

export interface VaultSession {
  index: VaultIndexEntry[];
  /** When to discard the index and sign out, or {@link NEVER_LOCK}. */
  lockAt: number;
  syncedAt: string;
}

/** Sentinel `lockAt` meaning "do not lock while signed in". */
export const NEVER_LOCK = 0;

export async function readVaultSession(): Promise<VaultSession | null> {
  const stored = await chrome.storage.session.get(VAULT_SESSION_KEY);
  const session = (stored[VAULT_SESSION_KEY] as VaultSession | undefined) ?? null;
  if (!session) return null;

  // Expiry is enforced on read as well as by the alarm: an alarm can be delayed,
  // and a stale index must not be usable just because the timer has not fired.
  if (session.lockAt !== NEVER_LOCK && Date.now() >= session.lockAt) {
    await clearVaultSession();
    return null;
  }

  return session;
}

export async function writeVaultSession(session: VaultSession): Promise<void> {
  await chrome.storage.session.set({ [VAULT_SESSION_KEY]: session });
}

export async function clearVaultSession(): Promise<void> {
  await chrome.storage.session.remove(VAULT_SESSION_KEY);
}

/** Push the auto-lock deadline out after genuine user activity. */
export async function touchVaultSession(autoLockMinutes: number): Promise<void> {
  const session = await readVaultSession();
  if (!session) return;

  await writeVaultSession({ ...session, lockAt: lockDeadline(autoLockMinutes) });
}

/**
 * When the vault should lock, or {@link NEVER_LOCK}.
 *
 * The arithmetic matters: `Date.now() + 0 * 60_000` is *now*, so treating zero
 * as an ordinary duration would lock the vault on the very next read rather
 * than never - the exact opposite of what the setting says.
 */
export function lockDeadline(autoLockMinutes: number): number {
  if (autoLockMinutes <= 0) return NEVER_LOCK;
  return Date.now() + autoLockMinutes * 60_000;
}

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

/**
 * Stable device id, persisted across restarts. Not a secret - it identifies the
 * installation so the account's device list stays meaningful.
 */
export async function getOrCreateDeviceId(): Promise<string> {
  const stored = await chrome.storage.local.get(DEVICE_ID_KEY);
  const existing = stored[DEVICE_ID_KEY] as string | undefined;
  if (existing && existing.length >= 8) return existing;

  const created = crypto.randomUUID();
  await chrome.storage.local.set({ [DEVICE_ID_KEY]: created });
  return created;
}

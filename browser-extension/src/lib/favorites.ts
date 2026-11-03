/**
 * Favourites, stored on this device.
 *
 * ## Why local rather than server-side
 *
 * The vault already has a `favorite` flag, but writing it means an authenticated
 * request and, for a shared vault, the *edit* permission - so a viewer could
 * never star anything, and starring would show up in the audit trail as an edit
 * to organisational property. Neither is right for what is really a personal
 * shortcut.
 *
 * Keeping them here makes favourites a per-device preference: instant, needing
 * no permission, and invisible to everyone else.
 *
 * ## What this stores
 *
 * Item ids only. An id is not a secret - it identifies a row whose contents
 * remain encrypted - so `chrome.storage.local` is appropriate. No name, no
 * username, no URL, because those *would* leak what the user has accounts with
 * to anything that could read extension storage.
 *
 * The list is per user, so two people sharing a browser profile do not see each
 * other's shortcuts.
 */

const KEY = 'passm.favorites';

/** `userId -> item ids`. */
type FavoritesMap = Record<string, string[]>;

async function readMap(): Promise<FavoritesMap> {
  try {
    const stored = await chrome.storage.local.get(KEY);
    const map = stored[KEY] as unknown;
    return typeof map === 'object' && map !== null ? (map as FavoritesMap) : {};
  } catch {
    return {};
  }
}

/** This user's favourite item ids. */
export async function readFavorites(userId: string): Promise<Set<string>> {
  const map = await readMap();
  return new Set(map[userId] ?? []);
}

/**
 * Toggle one item, returning its new state.
 *
 * Read-modify-write rather than a blind set, so two rapid clicks cannot drop an
 * unrelated entry.
 */
export async function toggleFavorite(userId: string, itemId: string): Promise<boolean> {
  const map = await readMap();
  const current = new Set(map[userId] ?? []);

  const nowFavorite = !current.has(itemId);
  if (nowFavorite) current.add(itemId);
  else current.delete(itemId);

  // Capped so a runaway loop cannot fill the extension's storage quota.
  map[userId] = [...current].slice(0, 500);

  try {
    await chrome.storage.local.set({ [KEY]: map });
  } catch {
    // Quota or storage unavailable. The starred state simply does not persist;
    // nothing else depends on it.
  }

  return nowFavorite;
}

/** Forget this user's favourites. Called on sign-out. */
export async function clearFavorites(userId: string): Promise<void> {
  const map = await readMap();
  delete map[userId];
  try {
    await chrome.storage.local.set({ [KEY]: map });
  } catch {
    // Nothing meaningful to do.
  }
}

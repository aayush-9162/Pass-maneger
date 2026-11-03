/**
 * Vault state inside the service worker.
 *
 * ## The shape of the problem
 *
 * The worker is suspended constantly, so nothing survives in module scope. Every
 * function here therefore reads its state from `chrome.storage.session` and
 * writes it back - which is slower than holding objects in memory, but is the
 * only approach that actually works under MV3.
 *
 * ## What is held, and when
 *
 * On opening, the worker lists every vault this account can use and stores a
 * **password-free index** (names, usernames, URIs). Search, matching and the
 * popup all run against that index.
 *
 * Passwords are never in the index. {@link vaultSession.revealSecret} asks the
 * server for one item's password at the moment the user fills or copies it, and
 * the server records that in the audit trail.
 *
 * Read-only by design: the extension never creates or changes a password.
 * That is an administrator's job, in the console - and the server refuses
 * writes from an extension client regardless.
 */

import type { SecretPurpose } from '@passm/shared';

import { extensionApi } from '../lib/api';
import { readFavorites } from '../lib/favorites';
import { readSettings } from '../lib/settings';
import {
  clearVaultSession,
  lockDeadline,
  readVaultSession,
  writeVaultSession,
  type VaultIndexEntry,
  type VaultSession,
} from '../lib/storage';
import { bestMatch, confidenceRank, describeMatch } from '../lib/uri-match';
import type { CredentialSecret, CredentialSuggestion, VaultLockState } from '../lib/messages';

export const vaultSession = {
  /** Current state, without needing the caller to know how it is stored. */
  async getState(accessToken: string | null): Promise<VaultLockState> {
    if (!accessToken) return 'no_session';
    return (await readVaultSession()) ? 'unlocked' : 'locked';
  },

  async read(): Promise<VaultSession | null> {
    return readVaultSession();
  },

  /**
   * Build the index from every vault this account can use.
   *
   * One vault failing to load must not blank the rest - an unlocked-but-partial
   * list the user can work with beats an error.
   */
  async open(accessToken: string): Promise<VaultSession> {
    const index: VaultIndexEntry[] = [];
    const { vaults } = await extensionApi.sharedVaults(accessToken);

    for (const vault of vaults) {
      try {
        const { items } = await extensionApi.sharedItems(accessToken, vault.id);

        for (const item of items) {
          if (item.deletedAt) continue;

          index.push({
            id: item.id,
            vaultId: vault.id,
            type: item.type,
            name: item.data.name || 'Untitled',
            username: item.data.username ?? null,
            uris: item.data.uris ?? [],
            tags: item.data.tags ?? [],
            favorite: item.favorite,
            updatedAt: item.updatedAt,
            // Fillable only when there is a password and the server will
            // release it to this member.
            hasPassword: item.hasSecret && vault.canReadSecrets,
          });
        }
      } catch {
        console.warn(`PassM: could not load shared vault ${vault.id}`);
      }
    }

    const { autoLockMinutes } = await readSettings();
    const session: VaultSession = {
      index,
      lockAt: lockDeadline(autoLockMinutes),
      syncedAt: new Date().toISOString(),
    };

    await writeVaultSession(session);
    return session;
  },

  /** Rebuild the index, so an item added on another device appears. */
  async resync(accessToken: string): Promise<VaultSession> {
    return this.open(accessToken);
  },

  async lock(): Promise<void> {
    await clearVaultSession();
  },

  // -------------------------------------------------------------------------
  // Reading the index
  // -------------------------------------------------------------------------

  /**
   * Rank index entries against a query.
   *
   * Same ordering as the console: an exact or prefix name match outranks a
   * containment match, which outranks a hit in a secondary field.
   */
  async search(query: string, limit = 20): Promise<VaultIndexEntry[]> {
    const session = await readVaultSession();
    if (!session) return [];

    const needle = query.trim().toLowerCase();

    if (needle.length === 0) {
      return [...session.index]
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
        .slice(0, limit);
    }

    const scored: { entry: VaultIndexEntry; score: number }[] = [];

    for (const entry of session.index) {
      const name = entry.name.toLowerCase();
      let score = 0;

      if (name === needle) score = 100;
      else if (name.startsWith(needle)) score = 80;
      else if (name.includes(needle)) score = 60;
      else if ((entry.username ?? '').toLowerCase().includes(needle)) score = 40;
      else if (entry.uris.some((uri) => uri.toLowerCase().includes(needle))) score = 30;
      else if (entry.tags.some((tag) => tag.toLowerCase().includes(needle))) score = 20;

      if (score > 0) scored.push({ entry, score });
    }

    return scored
      .sort((a, b) => b.score - a.score || b.entry.updatedAt.localeCompare(a.entry.updatedAt))
      .slice(0, limit)
      .map((result) => result.entry);
  },

  /**
   * Favourites, from this device's own list.
   *
   * The vault's `favorite` column is deliberately not consulted: starring is a
   * personal shortcut, and writing it server-side would need edit permission on
   * a shared vault and would appear in the audit trail as an edit to
   * organisational property.
   */
  async favorites(userId: string, limit = 20): Promise<VaultIndexEntry[]> {
    const session = await readVaultSession();
    if (!session) return [];

    const starred = await readFavorites(userId);

    return session.index
      .filter((entry) => starred.has(entry.id))
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit);
  },

  async recent(limit = 10): Promise<VaultIndexEntry[]> {
    const session = await readVaultSession();
    if (!session) return [];

    return [...session.index]
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
      .slice(0, limit);
  },

  /**
   * Credentials that match a page, best first.
   *
   * Returns suggestions without secrets - the content script sees names and
   * usernames only until the user picks one.
   */
  async suggestionsFor(url: string): Promise<CredentialSuggestion[]> {
    const session = await readVaultSession();
    if (!session) return [];

    const matches: { entry: VaultIndexEntry; rank: number; confidence: ReturnType<typeof bestMatch> }[] =
      [];

    for (const entry of session.index) {
      if (!entry.hasPassword) continue;

      const confidence = bestMatch(entry.uris, url);
      if (confidence === 'none') continue;

      matches.push({ entry, rank: confidenceRank(confidence), confidence });
    }

    return matches
      .sort((a, b) => b.rank - a.rank || a.entry.name.localeCompare(b.entry.name))
      .slice(0, 10)
      .map((match) => ({
        itemId: match.entry.id,
        name: match.entry.name,
        username: match.entry.username,
        confidence: match.confidence,
        confidenceLabel: describeMatch(match.confidence),
      }));
  },

  /** The index entry for an id, if the vault is open. */
  async findEntry(itemId: string): Promise<VaultIndexEntry | null> {
    const session = await readVaultSession();
    return session?.index.find((entry) => entry.id === itemId) ?? null;
  },

  // -------------------------------------------------------------------------
  // Secrets
  // -------------------------------------------------------------------------

  /**
   * One item's password, fetched from the server for this moment only.
   *
   * `purpose` lands in the audit trail beside the release - "filled", "copied".
   */
  async revealSecret(
    accessToken: string,
    itemId: string,
    purpose: SecretPurpose,
  ): Promise<CredentialSecret> {
    const entry = await this.findEntry(itemId);
    if (!entry) throw new Error('That item is not in your vault.');
    if (!entry.hasPassword) {
      throw new Error(
        'Passwords in this group are hidden from you. Ask an administrator if you need access.',
      );
    }

    const secret = await extensionApi.itemSecret(accessToken, entry.vaultId, itemId, purpose);

    return {
      itemId,
      username: entry.username,
      password: secret.password ?? null,
      totp: secret.totp ?? null,
    };
  },
};

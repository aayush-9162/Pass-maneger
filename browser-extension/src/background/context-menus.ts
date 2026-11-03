/**
 * Right-click menu.
 *
 * Rebuilt whenever the vault's lock state changes, so the menu never offers an
 * action that would fail. Chrome persists menu items across worker suspensions,
 * which is why every rebuild starts with `removeAll` - otherwise items would
 * accumulate on each restart.
 *
 * Menu items are scoped to `editable` contexts for filling and to `all` for the
 * generator, because generating a password is useful anywhere while filling only
 * makes sense in a field.
 */

import { generatePassword } from '@passm/shared';

import { readSettings } from '../lib/settings';
import type { VaultIndexEntry } from '../lib/storage';
import { clipboard } from './clipboard';

const IDS = {
  root: 'passm-root',
  fillSeparator: 'passm-fill-separator',
  fillPrefix: 'passm-fill:',
  generate: 'passm-generate',
  generatePronounceable: 'passm-generate-pronounceable',
  openVault: 'passm-open-vault',
  unlock: 'passm-unlock',
} as const;

/** Maximum credentials listed directly in the menu. */
const MAX_MENU_SUGGESTIONS = 5;

async function removeAll(): Promise<void> {
  return new Promise((resolve) => {
    chrome.contextMenus.removeAll(() => {
      // Reading lastError suppresses the "unchecked runtime.lastError" warning
      // that Chrome logs when the menu was already empty.
      void chrome.runtime.lastError;
      resolve();
    });
  });
}

export const contextMenus = {
  /**
   * Rebuild the menu for the current state.
   *
   * @param suggestions Credentials matching the active tab, if the vault is
   *   unlocked. Passing them in keeps this module free of vault logic.
   */
  async rebuild(options: {
    unlocked: boolean;
    signedIn: boolean;
    suggestions: Pick<VaultIndexEntry, 'id' | 'name' | 'username'>[];
  }): Promise<void> {
    await removeAll();

    chrome.contextMenus.create({
      id: IDS.root,
      title: 'PassM',
      contexts: ['all'],
    });

    if (!options.signedIn) {
      chrome.contextMenus.create({
        id: IDS.unlock,
        parentId: IDS.root,
        title: 'Sign in to PassM',
        contexts: ['all'],
      });
      return;
    }

    if (!options.unlocked) {
      chrome.contextMenus.create({
        id: IDS.unlock,
        parentId: IDS.root,
        title: 'Unlock your vault',
        contexts: ['all'],
      });
    } else if (options.suggestions.length > 0) {
      for (const suggestion of options.suggestions.slice(0, MAX_MENU_SUGGESTIONS)) {
        chrome.contextMenus.create({
          id: `${IDS.fillPrefix}${suggestion.id}`,
          parentId: IDS.root,
          // The username disambiguates two accounts on the same site, which is
          // the case this menu is most useful for.
          title: suggestion.username
            ? `Fill "${suggestion.name}" (${suggestion.username})`
            : `Fill "${suggestion.name}"`,
          contexts: ['editable'],
        });
      }

      chrome.contextMenus.create({
        id: IDS.fillSeparator,
        parentId: IDS.root,
        type: 'separator',
        contexts: ['all'],
      });
    }

    chrome.contextMenus.create({
      id: IDS.generate,
      parentId: IDS.root,
      title: 'Generate password and copy',
      contexts: ['all'],
    });

    chrome.contextMenus.create({
      id: IDS.generatePronounceable,
      parentId: IDS.root,
      title: 'Generate pronounceable password and copy',
      contexts: ['all'],
    });

    chrome.contextMenus.create({
      id: IDS.openVault,
      parentId: IDS.root,
      title: 'Open vault',
      contexts: ['all'],
    });
  },

  /**
   * Handle a click.
   *
   * @returns an action for the worker to perform, so this module stays free of
   *   vault and tab logic.
   */
  async handleClick(
    info: chrome.contextMenus.OnClickData,
    tab: chrome.tabs.Tab | undefined,
  ): Promise<
    | { action: 'fill'; itemId: string; tabId: number }
    | { action: 'open-vault'; tabId: number | undefined }
    | { action: 'none' }
  > {
    const menuItemId = String(info.menuItemId);

    if (menuItemId.startsWith(IDS.fillPrefix) && tab?.id !== undefined) {
      return { action: 'fill', itemId: menuItemId.slice(IDS.fillPrefix.length), tabId: tab.id };
    }

    if (menuItemId === IDS.generate || menuItemId === IDS.generatePronounceable) {
      const settings = await readSettings();
      const password = generatePassword({
        length: 20,
        pronounceable: menuItemId === IDS.generatePronounceable,
      });

      // Treated as a secret: a generated password is about to become one, and
      // leaving it in the clipboard is the same risk as leaving a stored one.
      await clipboard.copySecret(password, settings.clipboardClearSeconds);
      return { action: 'none' };
    }

    if (menuItemId === IDS.openVault || menuItemId === IDS.unlock) {
      return { action: 'open-vault', tabId: tab?.id };
    }

    return { action: 'none' };
  },
};

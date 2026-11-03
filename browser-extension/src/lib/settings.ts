/**
 * User-configurable behaviour.
 *
 * Kept in `chrome.storage.local` because these are preferences, not secrets, and
 * they should survive a browser restart. Anything sensitive lives in
 * `chrome.storage.session` instead - see `storage.ts`.
 */

export interface ExtensionSettings {
  /**
   * Seconds before a copied secret is overwritten in the clipboard.
   *
   * 0 disables auto-clear. The clipboard is readable by any application on the
   * machine and, on some platforms, syncs to other devices - so leaving a
   * password there indefinitely is the riskiest part of "copy password".
   */
  clipboardClearSeconds: number;

  /**
   * Minutes of inactivity before the vault locks and keys are discarded.
   *
   * `0` never locks while signed in. Worth supporting because, under a single
   * password, re-unlocking only ever asks for the password the user signed in
   * with - so the lock guards an unattended machine and nothing else, which the
   * session timeout already covers.
   */
  autoLockMinutes: number;

  /** Show the inline PassM button beside recognised username/password fields. */
  showInlineButton: boolean;

  /**
   * Fill the best match automatically when a page has exactly one candidate.
   *
   * Automatic filling is what makes clickjacking and hidden-form attacks worth
   * attempting, which is why it fires only on an unambiguous single match and
   * never submits on its own.
   */
  autoFillOnLoad: boolean;
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  clipboardClearSeconds: 30,
  /*
   * Never locks on idle.
   *
   * This used to be eight hours. Under the single-password model the prompt it
   * produced asked for the same password the user had just signed in with, so
   * it bought nothing an attacker had to defeat - it just trained people to
   * retype their password. Closing the browser still clears the keys, because
   * they live in `chrome.storage.session`, which is memory-backed.
   */
  autoLockMinutes: 0,
  showInlineButton: true,
  /*
   * On by default.
   *
   * It only fires when exactly one saved credential matches the site and the
   * vault is already unlocked, and it never submits - so the failure mode is a
   * pre-filled form the user can ignore, not an action taken on their behalf.
   */
  autoFillOnLoad: true,
};

const SETTINGS_KEY = 'passm.settings';

/** Bounds, enforced on write so a bad value cannot disable a protection. */
const LIMITS = {
  clipboardClearSeconds: { min: 0, max: 600 },
  // 0 is meaningful here - it disables locking - so the floor is 0, not 1.
  autoLockMinutes: { min: 0, max: 1440 },
} as const;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(Math.floor(value), min), max);
}

export async function readSettings(): Promise<ExtensionSettings> {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  const saved = (stored[SETTINGS_KEY] ?? {}) as Partial<ExtensionSettings>;

  // Merged with defaults so a settings object written by an older version is
  // still complete after an upgrade.
  return {
    ...DEFAULT_SETTINGS,
    ...saved,
    clipboardClearSeconds: clamp(
      saved.clipboardClearSeconds ?? DEFAULT_SETTINGS.clipboardClearSeconds,
      LIMITS.clipboardClearSeconds.min,
      LIMITS.clipboardClearSeconds.max,
    ),
    // Forced, not defaulted: profiles that saved a value under the old build
    // would otherwise keep idle-locking forever, because saved settings win
    // over defaults. The idle lock is removed as a feature - the keys still
    // die with the browser, which is the boundary that actually matters.
    autoLockMinutes: 0,
  };
}

export async function writeSettings(patch: Partial<ExtensionSettings>): Promise<ExtensionSettings> {
  const next = { ...(await readSettings()), ...patch };
  const validated = {
    ...next,
    clipboardClearSeconds: clamp(
      next.clipboardClearSeconds,
      LIMITS.clipboardClearSeconds.min,
      LIMITS.clipboardClearSeconds.max,
    ),
    autoLockMinutes: 0,
  };

  await chrome.storage.local.set({ [SETTINGS_KEY]: validated });
  return validated;
}

/**
 * Clipboard writes and auto-clear.
 *
 * ## Why the clipboard is the weakest link in "copy password"
 *
 * The clipboard is a system-wide, unauthenticated channel. Any application on
 * the machine can read it, some platforms sync it to other devices, and a web
 * page can read it during a paste. A password left there after use is a password
 * sitting in the open.
 *
 * So every copy schedules its own erasure, and the erasure is driven by
 * `chrome.alarms` rather than `setTimeout`: the service worker is suspended
 * within seconds, and a timer would simply never fire - leaving the password in
 * the clipboard indefinitely while appearing to have been handled.
 *
 * ## Overwriting, not emptying
 *
 * The clear writes a single space rather than an empty string. Some platforms
 * treat an empty write as a no-op and leave the previous contents intact, which
 * would silently defeat the whole mechanism.
 */

const OFFSCREEN_PATH = 'offscreen.html';
const CLEAR_ALARM = 'passm:clipboard-clear';

/** Sentinel written on clear; a space is reliably accepted by every platform. */
const CLEARED_VALUE = ' ';

let creatingOffscreen: Promise<void> | null = null;

/** Create the offscreen document if it is not already open. */
async function ensureOffscreenDocument(): Promise<void> {
  const existing = await chrome.runtime.getContexts({
    contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
  });

  if (existing.length > 0) return;

  // Collapse concurrent creations: Chrome throws if two are attempted at once.
  creatingOffscreen ??= chrome.offscreen
    .createDocument({
      url: OFFSCREEN_PATH,
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification:
        'Copy a credential to the clipboard, and overwrite it again once the auto-clear delay elapses.',
    })
    .finally(() => {
      creatingOffscreen = null;
    });

  await creatingOffscreen;
}

/** Write text through the offscreen document. */
async function write(text: string): Promise<boolean> {
  try {
    await ensureOffscreenDocument();
    const response = (await chrome.runtime.sendMessage({
      target: 'offscreen-clipboard',
      text,
    })) as { copied?: boolean } | undefined;

    return response?.copied === true;
  } catch {
    return false;
  }
}

export const clipboard = {
  /**
   * Copy a secret and schedule its removal.
   *
   * @param clearAfterSeconds 0 disables auto-clear, which the settings screen
   *   presents as an explicit choice rather than a default.
   * @returns whether the copy succeeded.
   */
  async copySecret(text: string, clearAfterSeconds: number): Promise<boolean> {
    const copied = await write(text);
    if (!copied) return false;

    // Any previously scheduled clear is replaced, so copying twice in quick
    // succession does not wipe the second value on the first one's schedule.
    await chrome.alarms.clear(CLEAR_ALARM);

    if (clearAfterSeconds > 0) {
      await chrome.alarms.create(CLEAR_ALARM, {
        // Chrome's minimum granularity is a minute for repeating alarms, but a
        // one-shot `when` honours any future instant.
        when: Date.now() + clearAfterSeconds * 1000,
      });
    }

    return true;
  },

  /*
   * `copyPlain` was removed with `COPY_SECRET`, its only caller. The one thing
   * that still reaches the clipboard is a freshly *generated* password, which
   * goes through `copySecret` and is wiped on schedule.
   */

  /** Overwrite the clipboard. Called by the alarm handler. */
  async clear(): Promise<void> {
    await write(CLEARED_VALUE);

    // The offscreen document has done its job; closing it releases the context
    // rather than leaving a hidden page alive for the session.
    try {
      await chrome.offscreen.closeDocument();
    } catch {
      // Already closed, or never opened.
    }
  },

  /** True when this alarm belongs to the clipboard. */
  isClearAlarm(alarmName: string): boolean {
    return alarmName === CLEAR_ALARM;
  },
};

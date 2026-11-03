/**
 * Clipboard access that also works over plain HTTP.
 *
 * `navigator.clipboard` is gated behind a *secure context*. `localhost` counts
 * as one; a bare LAN address such as `http://192.168.68.11:4000` does not - so
 * on an HTTP LAN deployment the modern API is simply `undefined`, and a copy
 * button that only used it would fail with no explanation.
 *
 * The fallback uses the deprecated `document.execCommand('copy')`, which has no
 * secure-context requirement. It is deprecated, not removed, and remains the
 * only option for this case.
 */

/**
 * Copy `text`, preferring the async Clipboard API.
 *
 * @returns `true` when the text reached the clipboard.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  // Available and permitted: the good path.
  if (typeof navigator !== 'undefined' && navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied or the document is not focused; fall through.
    }
  }

  return legacyCopy(text);
}

/**
 * `execCommand` fallback.
 *
 * The textarea must be in the document and selectable for the command to work,
 * so it is positioned off-screen rather than hidden - `display: none` elements
 * cannot hold a selection.
 */
function legacyCopy(text: string): boolean {
  if (typeof document === 'undefined') return false;

  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.setAttribute('aria-hidden', 'true');
  textarea.style.position = 'fixed';
  textarea.style.top = '-1000px';
  textarea.style.left = '-1000px';
  textarea.style.opacity = '0';

  document.body.appendChild(textarea);

  try {
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    // Remove it whatever happened: the element holds the secret in the DOM.
    document.body.removeChild(textarea);
  }
}

/**
 * True when the page is running in a secure context.
 *
 * Used to warn that some browser features are degraded on an HTTP deployment.
 */
export function isSecureContext(): boolean {
  return typeof window !== 'undefined' && window.isSecureContext;
}

// ---------------------------------------------------------------------------
// Automatic clearing
// ---------------------------------------------------------------------------

/**
 * Pending clear, module-scoped so a second copy replaces the first.
 *
 * Without this, copying password A then password B would leave A's timer
 * running, and it would wipe B from the clipboard early - which reads as the
 * feature being broken.
 */
let clearTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * What we put on the clipboard, so we only clear our own value.
 *
 * If the user copies something else in the meantime, wiping it would be rude and
 * confusing. The clipboard is shared with every other application on the
 * machine; this only takes responsibility for what it wrote.
 */
let lastCopied: string | null = null;

/**
 * Copy `text` and schedule it to be wiped.
 *
 * ## The honest limit
 *
 * This clears the *system clipboard as this page can see it*. It cannot reach
 * Windows clipboard history (Win+V), a clipboard manager, or a phone syncing via
 * Nearby Share - all of which may retain their own copy that no web page can
 * touch. The interface says so where it matters rather than implying the secret
 * is gone everywhere.
 *
 * @param seconds How long to wait. `0` disables clearing entirely.
 * @returns `true` when the text reached the clipboard.
 */
export async function copyWithAutoClear(text: string, seconds: number): Promise<boolean> {
  const copied = await copyToClipboard(text);
  if (!copied) return false;

  if (clearTimer) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }

  lastCopied = text;

  if (seconds <= 0) return true;

  clearTimer = setTimeout(() => {
    void (async () => {
      // Only clear if the clipboard still holds what we put there. Reading
      // requires permission that a plain-HTTP context does not grant, so when we
      // cannot check, we clear anyway - the alternative is leaving a password
      // on the clipboard indefinitely, which is the thing this exists to stop.
      try {
        if (navigator.clipboard?.readText) {
          const current = await navigator.clipboard.readText();
          if (current !== lastCopied) return;
        }
      } catch {
        // Permission denied or unavailable. Fall through and clear.
      }

      await copyToClipboard('');
      lastCopied = null;
      clearTimer = null;
    })();
  }, seconds * 1000);

  return true;
}

/** Cancel any pending clear. Used when the vault locks and wipes it immediately. */
export function cancelScheduledClear(): void {
  if (clearTimer) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
  lastCopied = null;
}

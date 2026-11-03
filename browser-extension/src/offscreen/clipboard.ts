/**
 * Offscreen clipboard worker.
 *
 * A service worker has no DOM, and neither `navigator.clipboard` nor
 * `document.execCommand` exists there - so an MV3 extension physically cannot
 * write to the clipboard from its background context. Chrome's answer is an
 * offscreen document: a hidden page with a DOM, created for a declared reason
 * and torn down when finished.
 *
 * This is also what makes *auto-clear* possible. The clearing write happens long
 * after the user's gesture, from an alarm, with no page in focus - the one
 * situation where an offscreen document is not just convenient but required.
 *
 * `execCommand('copy')` is used rather than `navigator.clipboard.writeText`
 * because the latter requires document focus, which an offscreen document never
 * has.
 */

interface ClipboardMessage {
  target: 'offscreen-clipboard';
  text: string;
}

/**
 * Copy `text` via a temporary textarea.
 *
 * The element must be in the document and selectable - `display: none` cannot
 * hold a selection - so it is positioned off-screen instead, and removed in a
 * `finally` so the value never lingers in the DOM.
 */
function writeToClipboard(text: string): boolean {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
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
    textarea.value = '';
    textarea.remove();
  }
}

chrome.runtime.onMessage.addListener(
  (message: ClipboardMessage, sender, sendResponse: (response: unknown) => void) => {
    // Only this extension's own worker may drive the clipboard.
    if (sender.id !== chrome.runtime.id) return false;
    if (message?.target !== 'offscreen-clipboard') return false;

    sendResponse({ copied: writeToClipboard(message.text) });
    return false;
  },
);

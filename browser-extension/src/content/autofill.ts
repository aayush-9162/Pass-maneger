/**
 * Content script.
 *
 * Runs in the page's isolated world: it shares the DOM but not the page's
 * JavaScript context, so page script cannot call into it or read its variables.
 *
 * ## What it is trusted with - deliberately very little
 *
 * This code runs on every page the user visits, including hostile ones, so it is
 * built to be worth compromising as little as possible:
 *
 *  - It never holds the auth tokens, the item index, or any credential it was not
 *    just handed for a fill the user clicked.
 *  - It only *reports* observations; the worker decides what to do with them.
 *  - It refuses instructions from any sender other than this extension.
 *
 * The credential it does receive lives in a local variable for the duration of
 * one fill and is never stored.
 */

import {
  sendToBackground,
  type BackgroundResponse,
  type ContentRequest,
  type CredentialSecret,
  type SuggestionsPayload,
} from '../lib/messages';
import { detectForms, detectIdentifierOnlyField, type DetectedForm } from './form-detector';
import { guardPasswordField } from './field-guard';
import { fillCredential, setFieldValue, submitForm } from './filler';
import {
  attachFieldButton,
  closePanel,
  showSuggestions,
  teardown,
} from './inline-ui';
import { adapterForHost, advanceStep, querySelectors } from './site-adapters';

/** Cleanup handles for buttons currently attached, keyed by field. */
const attached = new Map<HTMLInputElement, () => void>();

/** Forms seen in the current DOM, refreshed as the page changes. */
let currentForms: DetectedForm[] = [];

const adapter = adapterForHost(window.location.hostname);

// ---------------------------------------------------------------------------
// Detection and button attachment
// ---------------------------------------------------------------------------

/**
 * Resolve the fields to work with, preferring a site adapter's selectors.
 *
 * The adapters exist because the generic detector cannot find a username field
 * that is on a different screen from the password.
 */
function resolveFields(form: DetectedForm | null): {
  usernameField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
} {
  const adapterUsername = querySelectors(adapter?.usernameSelectors);
  const adapterPassword = querySelectors(adapter?.passwordSelectors);

  return {
    usernameField: adapterUsername ?? form?.usernameField ?? detectIdentifierOnlyField(),
    passwordField: adapterPassword ?? form?.passwordField ?? null,
  };
}

/** Ask the worker what it has for this page, then show the list. */
async function openSuggestions(anchor: HTMLInputElement): Promise<void> {
  const response = await sendToBackground<SuggestionsPayload>({
    type: 'PAGE_SUGGESTIONS',
    url: window.location.href,
  });

  if (!response.ok) return;

  if (response.data.vaultState !== 'unlocked') {
    // Nothing useful to show, and the popup is where unlocking happens.
    showSuggestions(anchor, [], {
      onPick: () => undefined,
      onOpenVault: () => void sendToBackground({ type: 'OPEN_SIDE_PANEL' }),
    });
    return;
  }

  showSuggestions(anchor, response.data.suggestions, {
    onPick: (itemId) => void requestFill(itemId),
    onOpenVault: () => void sendToBackground({ type: 'OPEN_SIDE_PANEL' }),
  });
}

/**
 * Ask the worker for a secret and fill it.
 *
 * This is the only path by which a credential enters the page, and it runs only
 * from a click the user made on our own UI.
 */
async function requestFill(itemId: string): Promise<void> {
  const response = await sendToBackground<CredentialSecret>({
    type: 'REQUEST_FILL',
    itemId,
    url: window.location.href,
  });

  if (!response.ok) return;

  const secret = response.data;
  const form = currentForms[0] ?? null;
  const fields = resolveFields(form);

  const result = fillCredential(fields, {
    username: secret.username,
    password: secret.password,
  });

  if (result.filledPassword && fields.passwordField) {
    guardFilled(fields.passwordField, itemId);
  }

  // Two-step sign-in: the password field is on the next screen, so advance and
  // fill again once it appears. Only after an explicit user action.
  if (adapter?.multiStep && result.filledUsername && !result.filledPassword) {
    if (advanceStep(adapter)) {
      window.setTimeout(() => {
        const next = querySelectors(adapter.passwordSelectors) ?? detectForms()[0]?.passwordField;
        if (next && secret.password) {
          setFieldValue(next, secret.password);
          guardFilled(next, itemId);
        }
      }, adapter.stepDelayMs ?? 800);
    }
  }
}

/**
 * Re-mask a filled password field if someone flips its type, and report it.
 *
 * Deterrent plus tripwire, not a boundary - see `field-guard.ts` for what this
 * genuinely stops and what it cannot.
 */
function guardFilled(field: HTMLInputElement, itemId: string): void {
  guardPasswordField(field, itemId, (detail) => {
    void sendToBackground({
      type: 'REPORT_FIELD_TAMPER',
      itemId: detail.itemId,
      host: detail.host,
    });
  });
}

/** Attach the inline button to every field worth offering a fill on. */
function attachButtons(showInlineButton: boolean): void {
  if (!showInlineButton) return;

  const targets = new Set<HTMLInputElement>();

  for (const form of currentForms) {
    if (form.usernameField) targets.add(form.usernameField);
    if (form.passwordField) targets.add(form.passwordField);
  }

  // A first-step identifier field with no password on the page at all.
  const identifierOnly = detectIdentifierOnlyField();
  if (identifierOnly) targets.add(identifierOnly);

  const adapterUsername = querySelectors(adapter?.usernameSelectors);
  if (adapterUsername) targets.add(adapterUsername);

  // Detach buttons whose field has left the DOM - single-page apps replace forms
  // constantly, and orphaned buttons would pile up.
  for (const [field, cleanup] of attached) {
    if (!field.isConnected || !targets.has(field)) {
      cleanup();
      attached.delete(field);
    }
  }

  for (const field of targets) {
    if (attached.has(field)) continue;
    attached.set(
      field,
      attachFieldButton(field, (anchor) => void openSuggestions(anchor)),
    );
  }
}

/**
 * Page teardown.
 *
 * `pagehide`, deliberately not `unload`.
 *
 * `unload` is deprecated and is now blocked by Permissions-Policy on a growing
 * set of documents - the browser's own new-tab page among them - which produced
 * a console violation on every such page this script touched. It is also
 * unreliable: it does not fire when a page enters the back/forward cache.
 *
 * When the page goes into the back/forward cache (`persisted: true`) it may come
 * back, so the injected host is removed - otherwise a restored page shows a
 * stale panel anchored to fields that have since moved.
 */
window.addEventListener('pagehide', (event) => {
  if (event.persisted) teardown();
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

let rescanTimer: number | undefined;

/** Re-detect forms, debounced. Single-page apps mutate the DOM constantly. */
function scheduleRescan(showInlineButton: boolean): void {
  window.clearTimeout(rescanTimer);
  rescanTimer = window.setTimeout(() => {
    currentForms = detectForms();
    attachButtons(showInlineButton);
  }, 300);
}

async function initialise(): Promise<void> {
  // Settings are read through the worker; the content script has no direct
  // storage access by design.
  let showInlineButton = true;

  const state = await sendToBackground<SuggestionsPayload>({
    type: 'PAGE_SUGGESTIONS',
    url: window.location.href,
  });

  if (state.ok && state.data.vaultState === 'no_session') {
    // Not signed in: no buttons, nothing to offer.
    showInlineButton = false;
  }

  currentForms = detectForms();
  attachButtons(showInlineButton);

  /**
   * Fill automatically, when it is unambiguous.
   *
   * Three conditions, all necessary:
   *
   *  - the setting is on;
   *  - the vault is unlocked, so there is something to fill with;
   *  - **exactly one** saved credential matches this site.
   *
   * The last is the important one. With two accounts for the same site, picking
   * one is a guess, and guessing wrong means typing a password into the wrong
   * account - possibly locking it. Ambiguity gets the inline button instead, and
   * the user chooses.
   *
   * Filling does not submit. Auto-filling is a convenience; auto-submitting a
   * form the user did not ask to submit is the extension taking an action on
   * their behalf on a page they may only have been passing through. Submission
   * happens only when they click an entry in the popup.
   */
  if (state.ok && state.data.vaultState === 'unlocked' && state.data.suggestions.length === 1) {
    const { autoFillOnLoad } = state.data;
    const only = state.data.suggestions[0];

    if (autoFillOnLoad && only && currentForms.length > 0) {
      const response = await sendToBackground({ type: 'FILL_ACTIVE_TAB', itemId: only.itemId });
      if (!response.ok) {
        console.warn('[PassM] Auto-fill did not run:', response.error);
      }
    }
  }

  const observer = new MutationObserver(() => scheduleRescan(showInlineButton));
  observer.observe(document.documentElement, { childList: true, subtree: true });
}

// ---------------------------------------------------------------------------
// Messages from the worker
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener(
  (request: ContentRequest, sender, sendResponse: (response: unknown) => void) => {
    // Only this extension's own worker may drive the content script. Without
    // this check another extension could trigger a fill.
    if (sender.id !== chrome.runtime.id) return false;

    switch (request.type) {
      case 'CONTENT_FILL': {
        const fields = resolveFields(currentForms[0] ?? null);
        const result = fillCredential(fields, {
          username: request.username,
          password: request.password,
        });

        // Every path that puts a password on the page guards it. This is the one
        // the popup, the context menu and launch-and-fill all use; missing it
        // meant a password filled from the popup could be unmasked freely while
        // the same password filled from the inline button could not.
        if (result.filledPassword && fields.passwordField) {
          guardFilled(fields.passwordField, request.itemId);
        }

        /**
         * Submit only when asked, and only when something was actually filled.
         *
         * Submitting an empty form would trip the site's own validation and, on
         * a page that counts attempts, could contribute to locking the user out
         * of the very account they are trying to reach.
         */
        if (request.submit && (result.filledUsername || result.filledPassword)) {
          // A tick, so frameworks that re-render on input have settled before
          // the click - otherwise the handler can read a stale empty value.
          setTimeout(() => {
            submitForm(fields.passwordField ?? fields.usernameField ?? null);
          }, 120);
        }

        sendResponse({ filled: result.filledUsername || result.filledPassword });
        return false;
      }

      case 'CONTENT_VAULT_STATE': {
        // The vault locked: remove the UI rather than leaving buttons that
        // would do nothing.
        if (request.state !== 'unlocked') {
          closePanel();
          for (const cleanup of attached.values()) cleanup();
          attached.clear();
        } else {
          attachButtons(true);
        }
        sendResponse({ acknowledged: true });
        return false;
      }

      case 'CONTENT_PROBE': {
        sendResponse({
          hasPasswordField: document.querySelector('input[type="password"]') !== null,
          hasLoginForm: currentForms.some((form) => form.kind === 'login'),
          origin: window.location.origin,
        });
        return false;
      }

      default:
        return false;
    }
  },
);

// Kick off once the DOM is ready enough to inspect.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => void initialise());
} else {
  void initialise();
}

/** Typed helper so the response type is not lost at the call sites above. */
export type { BackgroundResponse };

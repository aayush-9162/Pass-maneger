/**
 * Keep a filled password field masked.
 *
 * ## The trick this exists for
 *
 * Right-click a password box, Inspect, change `type="password"` to `type="text"`,
 * and the characters appear. It is the first result for "how to see the password
 * behind the dots", it takes about four seconds, and it is how essentially every
 * non-technical person who tries to read a filled password will try.
 *
 * This watches the fields the extension filled and puts `type` straight back,
 * then reports the attempt so an administrator can see who tried.
 *
 * ## What it does not do, stated plainly
 *
 * It does not make the password unreadable to someone who knows a browser. The
 * value is in the field because the site needs it there, so:
 *
 *     document.querySelector('input[type=password]').value
 *
 * prints it from the console without touching the `type` attribute at all, and
 * nothing running inside the page can prevent that. A determined person can also
 * pause the debugger, remove this observer, or read the DOM properties panel.
 *
 * So this is a deterrent against the casual attempt, plus a tripwire. It is not
 * a security boundary, and it is only worth having because the reporting half is
 * real: the extension cannot stop a technical user, but it can make sure the
 * attempt is not invisible.
 */

/** Attribute values that would expose the characters. */
const UNMASKED = new Set(['text', 'search', 'url', 'tel', 'email', 'number']);

/** Reported to the worker when a guarded field is tampered with. */
export type TamperReporter = (detail: { itemId: string; host: string }) => void;

interface GuardedField {
  observer: MutationObserver;
  /** Attempts seen on this field, to escalate rather than fight forever. */
  attempts: number;
}

const guarded = new WeakMap<HTMLInputElement, GuardedField>();

/**
 * How many reverts before the value is cleared instead.
 *
 * Reverting for ever turns into a fight the page always loses in a visible,
 * confusing way. After a few attempts it is clearer - and safer - to drop the
 * password and make them fill again, which is also an unmistakable signal that
 * the behaviour was noticed.
 */
const MAX_REVERTS = 3;

/**
 * Watch a filled password field and re-mask it if its type is changed.
 *
 * Safe to call repeatedly for the same field; the previous guard is replaced.
 *
 * @param field The password input that was just filled.
 * @param itemId The vault item it was filled from, for the report.
 * @param report Called once per tamper attempt. Fire-and-forget.
 * @returns A function that stops guarding, for when the field is refilled or the
 *   page navigates away.
 */
export function guardPasswordField(
  field: HTMLInputElement,
  itemId: string,
  report: TamperReporter,
): () => void {
  unguardPasswordField(field);

  const observer = new MutationObserver((records) => {
    for (const record of records) {
      if (record.attributeName !== 'type') continue;

      const current = (field.getAttribute('type') ?? '').toLowerCase();
      if (!UNMASKED.has(current)) continue;

      const state = guarded.get(field);
      const attempts = (state?.attempts ?? 0) + 1;
      if (state) state.attempts = attempts;

      if (attempts >= MAX_REVERTS) {
        // Stop the tug of war: clear the value, restore the mask, and let them
        // fill again if they genuinely need to sign in.
        field.value = '';
        field.dispatchEvent(new Event('input', { bubbles: true }));
        field.dispatchEvent(new Event('change', { bubbles: true }));
      }

      field.setAttribute('type', 'password');

      try {
        // Hostname only, never the URL - a path or query string on a sign-in
        // page routinely carries a token, and this ends up in an exportable
        // log. Brackets are stripped so an IPv6 literal still passes the
        // server's hostname check rather than being silently dropped.
        report({ itemId, host: window.location.hostname.replace(/[[\]]/g, '') });
      } catch {
        // The worker may be asleep or the extension reloading. The re-mask
        // already happened; losing the report is not worth throwing inside a
        // MutationObserver callback, which would stop the observer.
      }
    }
  });

  observer.observe(field, { attributes: true, attributeFilter: ['type'] });
  guarded.set(field, { observer, attempts: 0 });

  return () => unguardPasswordField(field);
}

/** Stop guarding a field. */
export function unguardPasswordField(field: HTMLInputElement): void {
  const state = guarded.get(field);
  if (!state) return;

  state.observer.disconnect();
  guarded.delete(field);
}

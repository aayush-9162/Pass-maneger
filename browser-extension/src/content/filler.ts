/**
 * Writing values into page fields.
 *
 * Assigning `input.value` directly is not enough on any modern site. React (and
 * Vue, and Angular) track input state internally and re-render from it, so a
 * direct assignment updates the DOM, the framework never learns about it, and
 * the value is wiped on the next render - or, worse, the form submits empty
 * while the user watched it look filled.
 *
 * The fix is to call the *native* value setter, bypassing the framework's
 * property override, then dispatch the events a real keystroke would produce.
 */

/** Native setters, captured once before any page script can replace them. */
const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
  window.HTMLInputElement.prototype,
  'value',
)?.set;

const nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(
  window.HTMLTextAreaElement.prototype,
  'value',
)?.set;

/**
 * Set a field's value the way a user would.
 *
 * Focus and blur bracket the change because many forms validate on blur and
 * will not enable their submit button otherwise.
 */
export function setFieldValue(field: HTMLInputElement | HTMLTextAreaElement, value: string): void {
  const setter =
    field instanceof HTMLTextAreaElement ? nativeTextAreaValueSetter : nativeInputValueSetter;

  field.focus();

  if (setter) {
    setter.call(field, value);
  } else {
    field.value = value;
  }

  // `input` drives React's onChange; `change` drives native and jQuery handlers.
  field.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));

  // A few sites only accept input that arrived with key events.
  field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Unidentified' }));
  field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Unidentified' }));

  field.blur();
}

/**
 * Fill a credential into the fields that were detected.
 *
 * Each field is optional: a two-step sign-in fills only the identifier on the
 * first screen, and only the password on the second.
 *
 * @returns which fields were actually written.
 */
export function fillCredential(
  fields: {
    usernameField?: HTMLInputElement | null;
    passwordField?: HTMLInputElement | null;
  },
  values: { username?: string | null; password?: string | null },
): { filledUsername: boolean; filledPassword: boolean } {
  let filledUsername = false;
  let filledPassword = false;

  if (fields.usernameField && values.username) {
    setFieldValue(fields.usernameField, values.username);
    filledUsername = true;
  }

  if (fields.passwordField && values.password) {
    setFieldValue(fields.passwordField, values.password);
    filledPassword = true;
  }

  return { filledUsername, filledPassword };
}

/**
 * Submit the form a field belongs to.
 *
 * ## Why this is not just `form.submit()`
 *
 * `HTMLFormElement.submit()` bypasses validation *and* does not fire the
 * `submit` event, so React and every other framework that intercepts submission
 * never sees it - the page appears to do nothing. `requestSubmit()` behaves like
 * a real button press and is what modern sites expect.
 *
 * Many sign-in pages have no `<form>` at all, or a form whose submit handler is
 * bound to a button rather than the form. So this tries, in order:
 *
 *   1. an explicit submit button inside the form,
 *   2. `requestSubmit()`,
 *   3. a likely-looking button near the field,
 *   4. an Enter keypress on the field itself.
 *
 * ## Two-step sign-ins
 *
 * Pages that ask for the identifier first and the password on the next screen
 * are extremely common. Submitting after filling only the username is correct
 * there, which is why the caller decides whether to submit rather than this
 * function assuming a complete credential.
 */
export function submitForm(field: HTMLInputElement | null): boolean {
  if (!field) return false;

  const form = field.form;

  if (form) {
    // A real submit button, clicked the way a user would.
    const button = form.querySelector<HTMLElement>(
      'button[type="submit"], input[type="submit"], button:not([type])',
    );

    if (button) {
      button.click();
      return true;
    }

    if (typeof form.requestSubmit === 'function') {
      form.requestSubmit();
      return true;
    }
  }

  // No form, or nothing in it worked. Look for a button that reads like a
  // sign-in control near the field - single-page apps frequently have no form.
  // The root node is a Document or ShadowRoot, both of which query like a
  // ParentNode; the DOM types just do not narrow that far.
  const scope: ParentNode = form ?? (field.getRootNode() as unknown as ParentNode) ?? document;
  const candidates = Array.from(
    scope.querySelectorAll<HTMLElement>('button, [role="button"], input[type="submit"]'),
  );

  const wording = /(sign|log)\s*-?\s*in|continue|next|submit|proceed/i;
  const match = candidates.find((candidate) => {
    if (candidate.hasAttribute('disabled')) return false;
    const label = `${candidate.textContent ?? ''} ${candidate.getAttribute('aria-label') ?? ''}`;
    return wording.test(label);
  });

  if (match) {
    match.click();
    return true;
  }

  /**
   * Last resort: press Enter in the field.
   *
   * `keydown` alone is enough for most handlers, but the full sequence is sent
   * because some listen for `keypress` or `keyup` instead.
   */
  for (const type of ['keydown', 'keypress', 'keyup'] as const) {
    field.dispatchEvent(
      new KeyboardEvent(type, {
        key: 'Enter',
        code: 'Enter',
        keyCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true,
      }),
    );
  }

  return true;
}

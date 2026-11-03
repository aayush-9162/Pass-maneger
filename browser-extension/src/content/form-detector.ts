/**
 * Login, signup and password-change form detection.
 *
 * There is no reliable declarative signal for "this is a login form" - sites
 * disagree about `autocomplete`, many omit `<form>` entirely, and single-page
 * apps rebuild the DOM constantly. So this scores candidates on several weak
 * signals rather than trusting any one of them.
 *
 * The classification that matters most is **login vs everything else**: autofill
 * only targets login forms. Filling a saved password into a signup or
 * change-password form would be wrong at best.
 *
 * Signals used, strongest first:
 *  1. `autocomplete` tokens - `current-password`, `new-password`, `username`.
 *     When present these are decisive, because a site that sets them means them.
 *  2. Password field count and order - one password is a login; two adjacent
 *     new-password fields are a signup or a change; three is a change.
 *  3. Text near the form - button labels and headings.
 *  4. URL path - `/login`, `/signup`, `/password/change`.
 */

export type FormKind = 'login' | 'signup' | 'change_password' | 'unknown';

export interface DetectedForm {
  kind: FormKind;
  /** The element that scopes this form - a `<form>`, or a containing element. */
  container: HTMLElement;
  usernameField: HTMLInputElement | null;
  /** For login: the password. For change: the *new* password. */
  passwordField: HTMLInputElement | null;
  /** Only for change-password forms. */
  currentPasswordField: HTMLInputElement | null;
  confirmPasswordField: HTMLInputElement | null;
  /** 0-1; below `MIN_CONFIDENCE` the form is ignored. */
  confidence: number;
}

const MIN_CONFIDENCE = 0.35;

/** Words that suggest a field holds an account identifier. */
const USERNAME_HINTS = [
  'user', 'username', 'login', 'email', 'e-mail', 'account', 'identifier',
  'loginfmt', 'signin', 'userid', 'user_id', 'user-name', 'emailaddress',
];

const SIGNUP_HINTS = ['sign up', 'signup', 'register', 'create account', 'get started', 'join'];
const CHANGE_HINTS = [
  'change password', 'update password', 'new password', 'reset password',
  'current password', 'old password',
];
const LOGIN_HINTS = ['sign in', 'signin', 'log in', 'login', 'continue'];

/** True when the element is rendered and interactive. */
export function isVisible(element: HTMLElement): boolean {
  if (element.hidden) return false;

  const input = element as HTMLInputElement;
  if (input.disabled || input.readOnly) return false;
  if (input.type === 'hidden') return false;

  // `offsetParent` is null for display:none and detached nodes; the rect check
  // catches zero-sized and visibility:hidden.
  const rect = element.getBoundingClientRect();
  if (rect.width < 4 || rect.height < 4) return false;

  const style = window.getComputedStyle(element);
  if (style.visibility === 'hidden' || style.display === 'none' || style.opacity === '0') {
    return false;
  }

  return true;
}

/** All the text a field carries: name, id, placeholder, aria-label, its label. */
function fieldSignature(field: HTMLInputElement): string {
  const parts = [
    field.name,
    field.id,
    field.placeholder,
    field.getAttribute('aria-label') ?? '',
    field.getAttribute('autocomplete') ?? '',
    field.getAttribute('data-testid') ?? '',
  ];

  // The associated <label>, which is often the only human-readable hint.
  if (field.labels) {
    for (const label of Array.from(field.labels)) parts.push(label.textContent ?? '');
  }

  return parts.join(' ').toLowerCase();
}

/** Visible text of a container, capped so a whole page body is not scanned. */
function containerText(container: HTMLElement): string {
  return (container.innerText ?? container.textContent ?? '').slice(0, 2000).toLowerCase();
}

function scoreUsernameField(field: HTMLInputElement): number {
  const autocomplete = (field.getAttribute('autocomplete') ?? '').toLowerCase();

  // A site that declares this means it; nothing else is as reliable.
  if (autocomplete === 'username' || autocomplete === 'email') return 100;

  const type = field.type.toLowerCase();
  const signature = fieldSignature(field);

  let score = 0;
  if (type === 'email') score += 50;
  if (type === 'text' || type === 'tel') score += 10;

  for (const hint of USERNAME_HINTS) {
    if (signature.includes(hint)) {
      score += 20;
      break;
    }
  }

  // Search boxes sit near login forms often enough to be worth excluding.
  if (/search|query|coupon|promo|zip|postal/.test(signature)) score -= 60;

  return score;
}

/** Password inputs inside a container, in document order. */
function passwordFields(container: HTMLElement): HTMLInputElement[] {
  return Array.from(container.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter(
    isVisible,
  );
}

/** The best username candidate that appears before the password field. */
function findUsernameField(
  container: HTMLElement,
  password: HTMLInputElement | null,
): HTMLInputElement | null {
  const candidates = Array.from(
    container.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="email"], input[type="tel"], input:not([type])',
    ),
  ).filter(isVisible);

  if (candidates.length === 0) return null;

  const scored = candidates
    .map((field) => {
      let score = scoreUsernameField(field);

      // Identifier fields almost always precede the password.
      if (
        password &&
        field.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING
      ) {
        score += 25;
      }

      return { field, score };
    })
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score);

  return scored[0]?.field ?? null;
}

/**
 * Classify a container that holds at least one password field.
 *
 * The `autocomplete` branch is checked first and returns immediately: when a
 * site declares `current-password` alongside `new-password`, that is a
 * password-change form and no amount of heuristic text matching should override
 * an explicit declaration.
 */
function classify(container: HTMLElement, passwords: HTMLInputElement[]): {
  kind: FormKind;
  confidence: number;
} {
  const autocompletes = passwords.map((field) =>
    (field.getAttribute('autocomplete') ?? '').toLowerCase(),
  );

  const hasCurrent = autocompletes.includes('current-password');
  const hasNew = autocompletes.some((value) => value === 'new-password');

  if (hasCurrent && hasNew) return { kind: 'change_password', confidence: 0.95 };
  if (hasCurrent && passwords.length === 1) return { kind: 'login', confidence: 0.9 };
  if (hasNew && !hasCurrent) {
    // Two new-password fields with no current one is a signup (or a reset from
    // an emailed link, which behaves the same way for our purposes).
    return { kind: 'signup', confidence: 0.75 };
  }

  const text = containerText(container);
  const url = window.location.href.toLowerCase();

  const mentions = (hints: string[]): boolean =>
    hints.some((hint) => text.includes(hint) || url.includes(hint.replace(/\s+/g, '')));

  if (passwords.length >= 3) return { kind: 'change_password', confidence: 0.8 };

  if (passwords.length === 2) {
    if (mentions(CHANGE_HINTS)) return { kind: 'change_password', confidence: 0.7 };
    if (mentions(SIGNUP_HINTS)) return { kind: 'signup', confidence: 0.7 };
    // Two password fields with no other signal is most often a signup.
    return { kind: 'signup', confidence: 0.5 };
  }

  if (mentions(CHANGE_HINTS)) return { kind: 'change_password', confidence: 0.55 };
  if (mentions(SIGNUP_HINTS)) return { kind: 'signup', confidence: 0.55 };
  if (mentions(LOGIN_HINTS)) return { kind: 'login', confidence: 0.8 };

  // A single password field and nothing else to go on: a login is the most
  // common case, and the worst outcome is a fill the user ignores.
  return { kind: 'login', confidence: 0.5 };
}

/**
 * Find the containers worth examining.
 *
 * Prefers real `<form>` elements. Falls back to a common ancestor of the
 * password fields for the many sites that do not use one - a pattern that used
 * to be unusual and is now the norm in single-page apps.
 */
function findContainers(root: ParentNode): HTMLElement[] {
  const forms = Array.from(root.querySelectorAll<HTMLFormElement>('form')).filter(
    (form) => passwordFields(form).length > 0,
  );

  if (forms.length > 0) return forms;

  const orphans = Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]'))
    .filter(isVisible)
    .filter((field) => field.form === null);

  if (orphans.length === 0) return [];

  // Walk up a bounded number of levels looking for an ancestor that also holds a
  // plausible username field. Unbounded would end at <body>, which would scoop
  // up unrelated inputs from elsewhere on the page.
  const containers = new Set<HTMLElement>();

  for (const field of orphans) {
    let node: HTMLElement | null = field.parentElement;

    for (let depth = 0; depth < 6 && node; depth += 1) {
      if (node.querySelector('input[type="text"], input[type="email"], input:not([type])')) break;
      node = node.parentElement;
    }

    containers.add(node ?? field.parentElement ?? document.body);
  }

  return Array.from(containers);
}

/** Detect every credential form in a root (the document, or a shadow root). */
export function detectForms(root: ParentNode = document): DetectedForm[] {
  const detected: DetectedForm[] = [];

  for (const container of findContainers(root)) {
    const passwords = passwordFields(container);
    if (passwords.length === 0) continue;

    const { kind, confidence } = classify(container, passwords);
    if (confidence < MIN_CONFIDENCE) continue;

    const byAutocomplete = (token: string): HTMLInputElement | null =>
      passwords.find(
        (field) => (field.getAttribute('autocomplete') ?? '').toLowerCase() === token,
      ) ?? null;

    let currentPasswordField: HTMLInputElement | null = null;
    let passwordField: HTMLInputElement | null = null;
    let confirmPasswordField: HTMLInputElement | null = null;

    if (kind === 'change_password') {
      currentPasswordField = byAutocomplete('current-password') ?? passwords[0] ?? null;
      passwordField =
        byAutocomplete('new-password') ??
        passwords.find((field) => field !== currentPasswordField) ??
        null;
      confirmPasswordField =
        passwords.find((field) => field !== currentPasswordField && field !== passwordField) ??
        null;
    } else if (kind === 'signup') {
      passwordField = byAutocomplete('new-password') ?? passwords[0] ?? null;
      confirmPasswordField = passwords.find((field) => field !== passwordField) ?? null;
    } else {
      passwordField = byAutocomplete('current-password') ?? passwords[0] ?? null;
    }

    detected.push({
      kind,
      container,
      usernameField: findUsernameField(container, passwordField),
      passwordField,
      currentPasswordField,
      confirmPasswordField,
      confidence,
    });
  }

  return detected;
}

/**
 * A username field with no password anywhere - the first step of a two-page
 * login.
 *
 * Google, Microsoft and Amazon all ask for the identifier on one screen and the
 * password on the next. Without this the extension would appear to do nothing on
 * the screen where the user actually needs it.
 */
export function detectIdentifierOnlyField(root: ParentNode = document): HTMLInputElement | null {
  if (root.querySelector('input[type="password"]')) return null;

  const candidates = Array.from(
    root.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="email"], input:not([type])',
    ),
  ).filter(isVisible);

  const scored = candidates
    .map((field) => ({ field, score: scoreUsernameField(field) }))
    // A higher bar than inside a form: with no password field for corroboration,
    // a weak signal is far more likely to be a search box.
    .filter((entry) => entry.score >= 50)
    .sort((a, b) => b.score - a.score);

  return scored[0]?.field ?? null;
}

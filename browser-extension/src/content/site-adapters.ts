/**
 * Per-site adjustments for the large identity providers.
 *
 * The generic detector handles most of the web. These adapters exist for the
 * handful of sites whose sign-in flow breaks a generic assumption - almost
 * always because the identifier and the password live on *different screens*, so
 * "find the username field next to the password field" finds nothing.
 *
 * Each adapter is deliberately small and declarative. The temptation with this
 * kind of code is to encode brittle CSS selectors for every provider; those rot
 * within months. What is encoded here instead is the *shape* of the flow, plus
 * selectors only where a stable, semantic one exists.
 */

import { isVisible } from './form-detector';

export interface SiteAdapter {
  /** Registrable domains this adapter applies to. */
  domains: readonly string[];
  name: string;
  /**
   * Sign-in is split across screens, so an identifier field with no password on
   * the page is expected rather than suspicious.
   */
  multiStep: boolean;
  /** Preferred identifier selectors, tried in order before the generic scoring. */
  usernameSelectors?: readonly string[];
  /** Preferred password selectors. */
  passwordSelectors?: readonly string[];
  /**
   * Click after filling the identifier to advance a multi-step flow.
   * Only used when the user explicitly asked to fill.
   */
  nextButtonSelectors?: readonly string[];
  /**
   * Milliseconds to wait after a step advances before re-detecting.
   * These flows animate, and querying too early finds the previous screen.
   */
  stepDelayMs?: number;
}

const ADAPTERS: readonly SiteAdapter[] = [
  {
    name: 'Google',
    domains: ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com'],
    multiStep: true,
    // `identifierId` and `Passwd` have been stable across Google redesigns for
    // years; the type selectors are the fallback when they change.
    usernameSelectors: ['input#identifierId', 'input[name="identifier"]', 'input[type="email"]'],
    passwordSelectors: ['input[name="Passwd"]', 'input[name="password"]', 'input[type="password"]'],
    nextButtonSelectors: ['#identifierNext button', '#identifierNext'],
    stepDelayMs: 900,
  },
  {
    name: 'Microsoft',
    domains: [
      'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com',
      'microsoftonline.com', 'hotmail.com', 'azure.com', 'sharepoint.com',
    ],
    multiStep: true,
    // `loginfmt` and `passwd` are the long-standing Microsoft field names.
    usernameSelectors: ['input[name="loginfmt"]', 'input[type="email"]'],
    passwordSelectors: ['input[name="passwd"]', 'input[type="password"]'],
    nextButtonSelectors: ['input#idSIButton9', 'button[type="submit"]'],
    stepDelayMs: 900,
  },
  {
    name: 'Amazon',
    domains: [
      'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it',
      'amazon.es', 'amazon.ca', 'amazon.co.jp', 'amazon.in', 'amazon.com.au',
      'amazon.com.br', 'amazon.com.mx',
    ],
    multiStep: true,
    usernameSelectors: ['input#ap_email', 'input[name="email"]'],
    passwordSelectors: ['input#ap_password', 'input[name="password"]'],
    nextButtonSelectors: ['input#continue', '#continue'],
    stepDelayMs: 700,
  },
  {
    name: 'GitHub',
    domains: ['github.com'],
    multiStep: false,
    usernameSelectors: ['input#login_field', 'input[name="login"]'],
    passwordSelectors: ['input#password', 'input[name="password"]'],
  },
  {
    name: 'Facebook',
    domains: ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com'],
    multiStep: false,
    usernameSelectors: ['input#email', 'input[name="email"]', 'input[name="username"]'],
    passwordSelectors: ['input#pass', 'input[name="pass"]', 'input[name="password"]'],
  },
  {
    name: 'LinkedIn',
    domains: ['linkedin.com'],
    multiStep: false,
    usernameSelectors: ['input#username', 'input[name="session_key"]'],
    passwordSelectors: ['input#password', 'input[name="session_password"]'],
  },
];

/** Registrable domain of a host, matching `uri-match.ts`'s simple rules. */
function registrableDomain(host: string): string {
  const normalized = host.toLowerCase().replace(/^www\./, '');
  const labels = normalized.split('.');
  if (labels.length <= 2) return normalized;

  const lastTwo = labels.slice(-2).join('.');
  // Only the suffixes that appear in the adapter list above need handling here.
  if (/^(co|com|net|org)\.[a-z]{2}$/.test(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

/** The adapter for the current page, if one applies. */
export function adapterForHost(host: string): SiteAdapter | null {
  const domain = registrableDomain(host);
  return ADAPTERS.find((adapter) => adapter.domains.includes(domain)) ?? null;
}

/** First visible element matching any selector, in order of preference. */
export function querySelectors(
  selectors: readonly string[] | undefined,
  root: ParentNode = document,
): HTMLInputElement | null {
  if (!selectors) return null;

  for (const selector of selectors) {
    const element = root.querySelector<HTMLInputElement>(selector);
    if (element && isVisible(element)) return element;
  }

  return null;
}

/**
 * Advance a multi-step sign-in after the identifier has been filled.
 *
 * Only called when the user explicitly chose to fill: clicking a page's buttons
 * on our own initiative would make the extension a mechanism for triggering
 * actions the user never asked for.
 *
 * @returns whether a button was clicked.
 */
export function advanceStep(adapter: SiteAdapter, root: ParentNode = document): boolean {
  if (!adapter.nextButtonSelectors) return false;

  for (const selector of adapter.nextButtonSelectors) {
    const button = root.querySelector<HTMLElement>(selector);
    if (button && isVisible(button)) {
      button.click();
      return true;
    }
  }

  return false;
}

/**
 * A readable site name.
 *
 * Prefers the adapter's name, then the document title, then the host, so the
 * user sees something they recognise.
 */
export function siteName(host: string): string {
  const adapter = adapterForHost(host);
  if (adapter) return adapter.name;

  const title = document.title.trim();
  if (title.length > 0 && title.length <= 40) return title;

  return registrableDomain(host);
}

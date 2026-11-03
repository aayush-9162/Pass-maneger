/**
 * Matching vault entries to the page the user is on.
 *
 * This is the single most security-sensitive piece of logic in the extension:
 * it decides which credential is offered to which site. A match that is too
 * loose hands a password to an attacker's lookalike domain; one that is too
 * strict makes the extension useless and pushes people back to copy-paste.
 *
 * The rules, in order of confidence:
 *
 *  1. **Exact origin** - scheme, host and port all equal. Highest confidence.
 *  2. **Host** - same host, any scheme or port.
 *  3. **Registrable domain** - `mail.google.com` matches an entry for
 *     `google.com`. This is where care is needed, and where the public-suffix
 *     handling below matters.
 *  4. **Known service family** - Microsoft signs users in at `login.live.com`
 *     for an `office.com` credential. Handled by explicit, curated groups
 *     rather than by loosening the domain rule for everyone.
 *
 * Never matched: a bare substring. `paypal.com.evil.tld` contains "paypal.com",
 * and any implementation that matches on `includes()` will leak the credential.
 */

export type MatchConfidence = 'exact' | 'host' | 'domain' | 'family' | 'none';

/** Ranking used to sort candidates; higher is a better match. */
const CONFIDENCE_RANK: Record<MatchConfidence, number> = {
  exact: 100,
  host: 80,
  domain: 60,
  family: 40,
  none: 0,
};

/**
 * Multi-part public suffixes that appear in practice.
 *
 * Without these, `example.co.uk` and `other.co.uk` would both reduce to `co.uk`
 * and match each other - a credential leak between unrelated companies. This is
 * a pragmatic subset; a full deployment should bundle the Public Suffix List.
 */
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.za', 'org.za', 'net.za',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'com.mx', 'com.ar', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.my',
  'co.kr', 'or.kr',
  'com.pl', 'com.ua', 'com.ru', 'com.es', 'com.pt', 'com.gr',
]);

/**
 * Service families whose sign-in happens on a different domain than the site.
 *
 * Curated deliberately: each entry is a decision that these domains belong to
 * one identity provider, and widening the general domain rule to cover them
 * would weaken matching for every other site.
 */
const SERVICE_FAMILIES: readonly (readonly string[])[] = [
  // Google - accounts.google.com serves sign-in for every Google property.
  ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com', 'googlemail.com'],
  // Microsoft - the sign-in host differs from the product host entirely.
  [
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com',
    'microsoftonline.com', 'login.microsoftonline.com', 'hotmail.com', 'azure.com',
    'sharepoint.com', 'skype.com', 'msn.com', 'xbox.com',
  ],
  // Amazon - regional storefronts share one account.
  [
    'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it',
    'amazon.es', 'amazon.ca', 'amazon.co.jp', 'amazon.in', 'amazon.com.au',
    'amazon.com.br', 'amazon.com.mx', 'aws.amazon.com',
  ],
  ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com'],
  ['github.com', 'githubusercontent.com', 'github.io'],
  ['linkedin.com', 'licdn.com'],
  ['apple.com', 'icloud.com'],
  ['paypal.com', 'paypal.me'],
];

/** Normalise a host: lowercase, strip a trailing dot and a leading `www.`. */
export function normalizeHost(host: string): string {
  const lower = host.toLowerCase().replace(/\.$/, '');
  return lower.startsWith('www.') ? lower.slice(4) : lower;
}

/**
 * Reduce a host to its registrable domain.
 *
 * `mail.google.com` -> `google.com`; `shop.example.co.uk` -> `example.co.uk`.
 * An IP address or a single-label host is returned unchanged - neither has a
 * registrable domain, and truncating one would create false matches.
 */
export function registrableDomain(host: string): string {
  const normalized = normalizeHost(host);

  // IPv4/IPv6 literals and single-label hosts (e.g. "localhost").
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalized) || normalized.includes(':')) return normalized;

  const labels = normalized.split('.');
  if (labels.length <= 2) return normalized;

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join('.');
  }

  return lastTwo;
}

/** Parse a stored URI, tolerating entries saved without a scheme. */
export function parseUri(value: string): URL | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;

  try {
    return new URL(trimmed);
  } catch {
    // Vault entries are often stored as a bare host.
    try {
      return new URL(`https://${trimmed}`);
    } catch {
      return null;
    }
  }
}

/**
 * Origin with the host normalised.
 *
 * `URL.origin` compares raw hosts, so `https://www.github.com` and
 * `https://github.com` would not be equal - and a stored entry for one would
 * rank as a weaker "same site" match against the other. Every password manager
 * treats the `www` prefix as the same site, and both values already match; this
 * only corrects the confidence reported to the user.
 */
function normalizedOrigin(url: URL): string {
  return `${url.protocol}//${normalizeHost(url.hostname)}${url.port ? `:${url.port}` : ''}`;
}

/** The family both hosts belong to, if any. */
function sharedFamily(a: string, b: string): boolean {
  const domainA = registrableDomain(a);
  const domainB = registrableDomain(b);

  return SERVICE_FAMILIES.some(
    (family) =>
      family.some((entry) => entry === domainA || entry === normalizeHost(a)) &&
      family.some((entry) => entry === domainB || entry === normalizeHost(b)),
  );
}

/**
 * How well a stored URI matches the page.
 *
 * @param storedUri A URI from a vault item.
 * @param pageUrl The URL of the page requesting a fill.
 */
export function matchUri(storedUri: string, pageUrl: string): MatchConfidence {
  const stored = parseUri(storedUri);
  const page = parseUri(pageUrl);
  if (!stored || !page) return 'none';

  // Never offer credentials to a non-web scheme.
  if (!/^https?:$/.test(page.protocol)) return 'none';

  if (normalizedOrigin(stored) === normalizedOrigin(page)) return 'exact';

  const storedHost = normalizeHost(stored.hostname);
  const pageHost = normalizeHost(page.hostname);

  if (storedHost === pageHost) return 'host';

  // Compare registrable domains, not substrings: "paypal.com.evil.tld" reduces
  // to "evil.tld" and correctly fails to match.
  if (registrableDomain(storedHost) === registrableDomain(pageHost)) return 'domain';

  if (sharedFamily(storedHost, pageHost)) return 'family';

  return 'none';
}

/** Best confidence across all of an item's stored URIs. */
export function bestMatch(storedUris: readonly string[], pageUrl: string): MatchConfidence {
  let best: MatchConfidence = 'none';

  for (const uri of storedUris) {
    const confidence = matchUri(uri, pageUrl);
    if (CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[best]) best = confidence;
  }

  return best;
}

export function confidenceRank(confidence: MatchConfidence): number {
  return CONFIDENCE_RANK[confidence];
}

/** Human label shown next to a suggestion, so the user can judge it. */
export function describeMatch(confidence: MatchConfidence): string {
  switch (confidence) {
    case 'exact':
      return 'Exact match';
    case 'host':
      return 'Same site';
    case 'domain':
      return 'Same domain';
    case 'family':
      return 'Related sign-in service';
    default:
      return 'No match';
  }
}

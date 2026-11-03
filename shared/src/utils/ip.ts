/**
 * IP address parsing and CIDR matching.
 *
 * Lives in `shared` because the admin panel needs to answer "would this address
 * get in?" before saving a rule, and getting a *different* answer from the
 * server would be worse than not offering the check at all.
 *
 * ## The IPv4-mapped IPv6 trap
 *
 * Node hands you `::ffff:192.168.1.50` for an IPv4 client whenever the listening
 * socket is dual-stack, which it is by default. An administrator types
 * `192.168.1.0/24`. A naive comparison fails, the rule silently never matches,
 * and enforcement locks out the whole office.
 *
 * So every address is normalised to its canonical form first, and a mapped
 * address is unwrapped to plain IPv4. This is the single most important thing in
 * this file.
 */

/** A parsed address: the family plus its big-endian bytes. */
export interface ParsedIp {
  family: 4 | 6;
  bytes: Uint8Array;
  /** Canonical text form, after unwrapping any IPv4 mapping. */
  normalized: string;
}

const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseIpv4(value: string): Uint8Array | null {
  const match = IPV4_PATTERN.exec(value);
  if (!match) return null;

  const bytes = new Uint8Array(4);
  for (let index = 0; index < 4; index += 1) {
    const part = match[index + 1];
    if (part === undefined) return null;

    // Reject `01` and `1.2.3.04`: leading zeros are read as octal by some
    // resolvers and as decimal by others, which is a classic bypass.
    if (part.length > 1 && part.startsWith('0')) return null;

    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    bytes[index] = octet;
  }
  return bytes;
}

function parseIpv6(value: string): Uint8Array | null {
  let text = value;

  // A zone index (`fe80::1%eth0`) is a local routing detail, not part of the
  // address, and never appears in a rule.
  const zoneAt = text.indexOf('%');
  if (zoneAt !== -1) text = text.slice(0, zoneAt);

  if (!text.includes(':')) return null;

  // A trailing dotted quad, as in `::ffff:192.168.1.1`, becomes two groups.
  let tail = '';
  const lastColon = text.lastIndexOf(':');
  const afterLastColon = text.slice(lastColon + 1);
  if (afterLastColon.includes('.')) {
    const embedded = parseIpv4(afterLastColon);
    if (!embedded) return null;
    const high = ((embedded[0] ?? 0) << 8) | (embedded[1] ?? 0);
    const low = ((embedded[2] ?? 0) << 8) | (embedded[3] ?? 0);
    tail = `${high.toString(16)}:${low.toString(16)}`;
    text = text.slice(0, lastColon + 1) + tail;
  }

  const doubleColonAt = text.indexOf('::');
  let head: string[];
  let rest: string[];

  if (doubleColonAt === -1) {
    head = text.split(':');
    rest = [];
    if (head.length !== 8) return null;
  } else {
    // More than one `::` is ambiguous and therefore invalid.
    if (text.indexOf('::', doubleColonAt + 1) !== -1) return null;

    const before = text.slice(0, doubleColonAt);
    const after = text.slice(doubleColonAt + 2);
    head = before.length > 0 ? before.split(':') : [];
    rest = after.length > 0 ? after.split(':') : [];
    if (head.length + rest.length > 7) return null;
  }

  const groups: number[] = [];
  const push = (group: string): boolean => {
    if (group.length === 0 || group.length > 4) return false;
    if (!/^[0-9a-fA-F]+$/.test(group)) return false;
    groups.push(Number.parseInt(group, 16));
    return true;
  };

  for (const group of head) if (!push(group)) return null;

  const missing = 8 - head.length - rest.length;
  for (let index = 0; index < missing; index += 1) groups.push(0);

  for (const group of rest) if (!push(group)) return null;
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let index = 0; index < 8; index += 1) {
    const group = groups[index] ?? 0;
    bytes[index * 2] = (group >> 8) & 0xff;
    bytes[index * 2 + 1] = group & 0xff;
  }
  return bytes;
}

/** True when a 16-byte address is an IPv4-mapped one (`::ffff:a.b.c.d`). */
function isIpv4Mapped(bytes: Uint8Array): boolean {
  for (let index = 0; index < 10; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return bytes[10] === 0xff && bytes[11] === 0xff;
}

/**
 * Parse an address, unwrapping any IPv4 mapping.
 *
 * Returns `null` for anything malformed rather than throwing: this runs on
 * untrusted input on every request, and an exception per probe is a denial of
 * service waiting to happen.
 */
export function parseIp(value: string): ParsedIp | null {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 45) return null;

  // Some proxies wrap IPv6 in brackets, occasionally with a port.
  const unbracketed =
    trimmed.startsWith('[') && trimmed.includes(']')
      ? trimmed.slice(1, trimmed.indexOf(']'))
      : trimmed;

  const asIpv4 = parseIpv4(unbracketed);
  if (asIpv4) {
    return { family: 4, bytes: asIpv4, normalized: formatIpv4(asIpv4) };
  }

  const asIpv6 = parseIpv6(unbracketed);
  if (!asIpv6) return null;

  if (isIpv4Mapped(asIpv6)) {
    const embedded = asIpv6.slice(12, 16);
    return { family: 4, bytes: embedded, normalized: formatIpv4(embedded) };
  }

  return { family: 6, bytes: asIpv6, normalized: formatIpv6(asIpv6) };
}

function formatIpv4(bytes: Uint8Array): string {
  return Array.from(bytes.slice(0, 4)).join('.');
}

/** RFC 5952 form: lowercase, longest run of zero groups collapsed once. */
function formatIpv6(bytes: Uint8Array): string {
  const groups: number[] = [];
  for (let index = 0; index < 8; index += 1) {
    groups.push(((bytes[index * 2] ?? 0) << 8) | (bytes[index * 2 + 1] ?? 0));
  }

  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;

  for (let index = 0; index <= 8; index += 1) {
    if (index < 8 && groups[index] === 0) {
      if (runStart === -1) runStart = index;
    } else if (runStart !== -1) {
      const length = index - runStart;
      // A single zero group is written out; collapsing it saves nothing.
      if (length > 1 && length > bestLength) {
        bestStart = runStart;
        bestLength = length;
      }
      runStart = -1;
    }
  }

  const parts: string[] = [];
  for (let index = 0; index < 8; index += 1) {
    if (bestStart !== -1 && index === bestStart) {
      parts.push('');
      index += bestLength - 1;
      if (bestStart === 0) parts.push('');
      if (bestStart + bestLength === 8) parts.push('');
      continue;
    }
    parts.push((groups[index] ?? 0).toString(16));
  }

  return parts.join(':').replace(/:{3,}/, '::');
}

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

export interface ParsedCidr {
  ip: ParsedIp;
  /** Prefix length in bits. A bare address gets the full width. */
  prefix: number;
}

/**
 * Parse `192.168.1.0/24`, `10.0.0.5`, `2001:db8::/32`.
 *
 * A bare address is treated as a /32 or /128, so an administrator can allow one
 * machine without knowing what a prefix length is.
 */
export function parseCidr(value: string): ParsedCidr | null {
  const trimmed = value.trim();
  const slashAt = trimmed.lastIndexOf('/');

  if (slashAt === -1) {
    const ip = parseIp(trimmed);
    if (!ip) return null;
    return { ip, prefix: ip.family === 4 ? 32 : 128 };
  }

  const ip = parseIp(trimmed.slice(0, slashAt));
  if (!ip) return null;

  const prefixText = trimmed.slice(slashAt + 1);
  if (!/^\d{1,3}$/.test(prefixText)) return null;

  const prefix = Number(prefixText);
  const width = ip.family === 4 ? 32 : 128;
  if (prefix < 0 || prefix > width) return null;

  return { ip, prefix };
}

/** Does `address` fall inside `cidr`? Mismatched families never match. */
export function ipInCidr(address: ParsedIp, cidr: ParsedCidr): boolean {
  if (address.family !== cidr.ip.family) return false;

  const fullBytes = cidr.prefix >> 3;
  const remainingBits = cidr.prefix & 7;

  for (let index = 0; index < fullBytes; index += 1) {
    if (address.bytes[index] !== cidr.ip.bytes[index]) return false;
  }

  if (remainingBits === 0) return true;

  // Compare only the significant high bits of the boundary byte.
  const mask = 0xff << (8 - remainingBits);
  return ((address.bytes[fullBytes] ?? 0) & mask) === ((cidr.ip.bytes[fullBytes] ?? 0) & mask);
}

/** Convenience wrapper over strings, for one-off checks and the admin tester. */
export function ipMatchesCidr(address: string, cidr: string): boolean {
  const parsedAddress = parseIp(address);
  const parsedCidr = parseCidr(cidr);
  if (!parsedAddress || !parsedCidr) return false;
  return ipInCidr(parsedAddress, parsedCidr);
}

/** Human-readable validation for the rule form. `null` means valid. */
export function describeCidrProblem(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return 'Enter an address or range.';

  const parsed = parseCidr(trimmed);
  if (!parsed) {
    return trimmed.includes('/')
      ? 'Not a valid address or prefix length. Try something like 192.168.1.0/24.'
      : 'Not a valid IP address. Try something like 192.168.1.50.';
  }

  // A prefix with host bits set (`192.168.1.5/24`) is almost always a mistake -
  // the author meant either the single host or the whole network.
  const fullBytes = parsed.prefix >> 3;
  const remainingBits = parsed.prefix & 7;
  const width = parsed.ip.family === 4 ? 32 : 128;

  if (parsed.prefix < width) {
    let hostBitsSet = false;
    if (remainingBits !== 0) {
      const mask = 0xff >> remainingBits;
      if (((parsed.ip.bytes[fullBytes] ?? 0) & mask) !== 0) hostBitsSet = true;
    }
    for (let index = fullBytes + (remainingBits === 0 ? 0 : 1); index < parsed.ip.bytes.length; index += 1) {
      if (parsed.ip.bytes[index] !== 0) hostBitsSet = true;
    }
    if (hostBitsSet) {
      return `Host bits are set. Did you mean ${networkAddressOf(parsed)}/${parsed.prefix}?`;
    }
  }

  return null;
}

/** The network address of a range, with host bits cleared. */
export function networkAddressOf(cidr: ParsedCidr): string {
  const bytes = new Uint8Array(cidr.ip.bytes);
  const fullBytes = cidr.prefix >> 3;
  const remainingBits = cidr.prefix & 7;

  if (remainingBits !== 0) {
    const byteIndex = fullBytes;
    bytes[byteIndex] = (bytes[byteIndex] ?? 0) & (0xff << (8 - remainingBits));
  }
  for (let index = fullBytes + (remainingBits === 0 ? 0 : 1); index < bytes.length; index += 1) {
    bytes[index] = 0;
  }

  return cidr.ip.family === 4 ? formatIpv4(bytes) : formatIpv6(bytes);
}

/** How many addresses a range covers, for the "this allows 256 machines" hint. */
export function cidrSize(cidr: ParsedCidr): number {
  const width = cidr.ip.family === 4 ? 32 : 128;
  const hostBits = width - cidr.prefix;
  // Beyond 2^53 the count stops being meaningful; report Infinity instead of
  // silently losing precision.
  return hostBits > 53 ? Number.POSITIVE_INFINITY : 2 ** hostBits;
}

/**
 * Common private ranges, offered as one-click presets in the rule form.
 *
 * A LAN deployment almost always wants exactly one of these, and typing a
 * prefix by hand is where lockouts come from.
 */
export const PRIVATE_RANGE_PRESETS: readonly { cidr: string; label: string }[] = [
  { cidr: '10.0.0.0/8', label: 'Private class A (10.x.x.x)' },
  { cidr: '172.16.0.0/12', label: 'Private class B (172.16-31.x.x)' },
  { cidr: '192.168.0.0/16', label: 'Private class C (192.168.x.x)' },
  { cidr: '127.0.0.0/8', label: 'Loopback (this machine)' },
  { cidr: 'fc00::/7', label: 'IPv6 unique local' },
  { cidr: '::1/128', label: 'IPv6 loopback' },
];

/** True for addresses that are not routable on the public internet. */
export function isPrivateAddress(value: string): boolean {
  const parsed = parseIp(value);
  if (!parsed) return false;

  if (parsed.family === 4) {
    const [a = 0, b = 0] = Array.from(parsed.bytes);
    if (a === 10 || a === 127) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }

  const first = parsed.bytes[0] ?? 0;
  // fc00::/7 unique-local, fe80::/10 link-local.
  if ((first & 0xfe) === 0xfc) return true;
  if (first === 0xfe && ((parsed.bytes[1] ?? 0) & 0xc0) === 0x80) return true;

  return parsed.normalized === '::1';
}

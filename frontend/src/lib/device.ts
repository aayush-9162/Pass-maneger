/**
 * Client device identity.
 *
 * Two distinct values, and the distinction matters:
 *
 *  - **`deviceId`** - a random UUID generated once per browser profile and kept
 *    in `localStorage`. It is an *identifier*, not a secret: it says "this is the
 *    same browser as last time" so the account's device list stays meaningful.
 *    Losing it costs nothing beyond a new entry in that list.
 *
 *  - **`fingerprint`** - a hash of stable browser characteristics. The server
 *    treats it purely as a change detector: if a trusted device's fingerprint
 *    shifts, trust is dropped and an audit event is written. It is deliberately
 *    *not* an authentication factor, because fingerprints are trivially forged.
 *
 * Neither is a credential. The actual proof of a remembered device is the
 * httpOnly device-trust cookie, which JavaScript here cannot read.
 */

const DEVICE_ID_STORAGE_KEY = 'passm.device.id';

/**
 * UUIDv4.
 *
 * `crypto.randomUUID` is restricted to secure contexts, so over plain HTTP it is
 * undefined - but `getRandomValues` is not, and it is what actually matters.
 * `Math.random` is the last resort for server rendering only, where the value is
 * discarded before it reaches a browser.
 */
function randomUuid(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
    bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;

    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20, 32),
    ].join('-');
  }

  // Non-secret identifier, and unreachable in a browser; the server treats it
  // as opaque either way.
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (char) => {
    const random = (Math.random() * 16) | 0;
    const value = char === 'x' ? random : (random & 0x3) | 0x8;
    return value.toString(16);
  });
}

/**
 * Stable device id for this browser profile.
 *
 * Returns an empty string during server rendering: there is no browser to
 * identify, and the request headers are simply omitted.
 */
export function getDeviceId(): string {
  if (typeof window === 'undefined') return '';

  try {
    const existing = window.localStorage.getItem(DEVICE_ID_STORAGE_KEY);
    if (existing && existing.length >= 8) return existing;

    const created = randomUuid();
    window.localStorage.setItem(DEVICE_ID_STORAGE_KEY, created);
    return created;
  } catch {
    // Private browsing or a storage quota error. A per-session id still works;
    // the device simply appears as new on the next visit.
    return randomUuid();
  }
}

/** Human readable device label, shown in the account's device list. */
export function getDeviceName(): string {
  if (typeof navigator === 'undefined') return 'Unknown device';

  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /OPR\//.test(ua)
      ? 'Opera'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Firefox\//.test(ua)
          ? 'Firefox'
          : /Safari\//.test(ua)
            ? 'Safari'
            : 'Browser';

  const platform = /Windows/.test(ua)
    ? 'Windows'
    : /Mac OS X/.test(ua)
      ? 'macOS'
      : /Android/.test(ua)
        ? 'Android'
        : /iPhone|iPad/.test(ua)
          ? 'iOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : 'Unknown OS';

  return `${browser} on ${platform}`;
}

let cachedFingerprint: string | null = null;

/**
 * Hash of stable browser characteristics.
 *
 * Signals are chosen to be stable across sessions but to change when the
 * *environment* changes materially (different machine, different browser build).
 * High-entropy identifiers such as canvas rendering are avoided: this is not a
 * tracking mechanism, and the extra entropy buys nothing for change detection.
 */
export async function getDeviceFingerprint(): Promise<string | undefined> {
  if (typeof window === 'undefined' || typeof navigator === 'undefined') return undefined;
  if (cachedFingerprint) return cachedFingerprint;

  const signals = [
    navigator.userAgent,
    navigator.language,
    String(navigator.hardwareConcurrency ?? ''),
    String(navigator.maxTouchPoints ?? ''),
    `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`,
    Intl.DateTimeFormat().resolvedOptions().timeZone ?? '',
  ].join('|');

  // `crypto.subtle` exists only in a secure context. `localhost` qualifies; a
  // bare LAN address over HTTP does not, so on an HTTP deployment this is
  // undefined and the non-cryptographic fallback below is used instead.
  if (window.isSecureContext && typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(signals));
      cachedFingerprint = Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');
      return cachedFingerprint;
    } catch {
      // Fall through to the non-cryptographic hash.
    }
  }

  cachedFingerprint = insecureHash(signals);
  return cachedFingerprint;
}

/**
 * FNV-1a hash, for use when `crypto.subtle` is unavailable.
 *
 * Not cryptographic, and it does not need to be: the server treats this value
 * purely as a *change detector* and never as an authentication factor - it is
 * already assumed to be forgeable. What matters is that the same browser keeps
 * producing the same value, which this does. It is prefixed so a fingerprint
 * computed this way is distinguishable in the database.
 */
function insecureHash(input: string): string {
  let high = 0x811c9dc5;
  let low = 0x811c9dc5;

  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    high = ((high ^ code) * 0x01000193) >>> 0;
    // A second lane seeded from the reversed position widens the output to 64
    // bits, which is enough to make an accidental collision implausible.
    low = ((low ^ (code + i)) * 0x01000193) >>> 0;
  }

  return `fnv-${high.toString(16).padStart(8, '0')}${low.toString(16).padStart(8, '0')}`;
}

/** Forget this browser's device id (used after "this isn't my device"). */
export function clearDeviceId(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(DEVICE_ID_STORAGE_KEY);
  } catch {
    // Nothing to do: storage is unavailable, so there is nothing stored.
  }
}

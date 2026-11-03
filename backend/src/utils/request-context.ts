/**
 * Extraction of trustworthy facts from an incoming request.
 *
 * Everything here originates from the client and is therefore treated as
 * untrusted input: values are length-capped, character-restricted and
 * normalised before they can reach the database or a log line.
 */

import type { Request } from 'express';

import { DEVICE_PLATFORM, HEADERS, type DeviceIdentity, type DevicePlatform } from '@passm/shared';

import { isValidClientDeviceId } from './ids';

/** Column widths in MySQL - truncate rather than let an INSERT fail. */
const MAX_USER_AGENT_LENGTH = 512;
const MAX_DEVICE_NAME_LENGTH = 120;
const MAX_FINGERPRINT_LENGTH = 128;

/** Read a header as a single string; arrays (duplicated headers) collapse to the first. */
function headerValue(req: Request, name: string): string | undefined {
  const raw = req.headers[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed === '' ? undefined : trimmed;
}

/**
 * Replace C0/C1 control characters (and DEL) with a space.
 *
 * Done with a code-point scan rather than a regex so no literal control byte
 * ever appears in this source file. The motivation is log-injection safety: a
 * newline inside a device name would otherwise let a caller forge log lines.
 */
function stripControlCharacters(value: string): string {
  let output = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    const isControl = code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f);
    output += isControl ? ' ' : character;
  }
  return output;
}

/** Sanitise and cap a free-text client value. */
function sanitizeText(value: string | undefined, maxLength: number): string | undefined {
  if (value === undefined) return undefined;
  const cleaned = stripControlCharacters(value).replace(/\s+/g, ' ').trim();
  return cleaned === '' ? undefined : cleaned.slice(0, maxLength);
}

/**
 * Client IP address.
 *
 * `req.ip` already accounts for `trust proxy`, which is configured from
 * TRUST_PROXY_HOPS. Setting that value correctly matters: too high and clients
 * can spoof `X-Forwarded-For` to evade rate limits and lockouts, too low and
 * every request appears to come from the load balancer.
 */
export function getClientIp(req: Request): string {
  const raw = req.ip ?? req.socket.remoteAddress ?? '';
  // Normalise IPv4-mapped IPv6 ("::ffff:10.0.0.1" -> "10.0.0.1") so the same
  // client always produces one consistent rate-limit key.
  const normalised = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  return normalised.slice(0, 45) || 'unknown';
}

export function getUserAgent(req: Request): string | null {
  return sanitizeText(headerValue(req, 'user-agent'), MAX_USER_AGENT_LENGTH) ?? null;
}

/** Best-effort platform classification from the User-Agent string. */
export function inferPlatform(userAgent: string | null): DevicePlatform {
  if (!userAgent) return DEVICE_PLATFORM.UNKNOWN;
  const ua = userAgent.toLowerCase();

  if (/android|iphone|ipad|ipod|mobile/.test(ua)) return DEVICE_PLATFORM.MOBILE;
  if (/electron/.test(ua)) return DEVICE_PLATFORM.DESKTOP;
  if (/mozilla|chrome|safari|firefox|edg/.test(ua)) return DEVICE_PLATFORM.WEB;
  return DEVICE_PLATFORM.UNKNOWN;
}

/** Human readable device label derived from the User-Agent, used as a fallback. */
export function inferDeviceName(userAgent: string | null): string {
  if (!userAgent) return 'Unknown device';

  // Order matters: Edge and Opera both advertise "Chrome" in their UA strings.
  const browser = /edg\//i.test(userAgent)
    ? 'Edge'
    : /opr\/|opera/i.test(userAgent)
      ? 'Opera'
      : /chrome\//i.test(userAgent)
        ? 'Chrome'
        : /firefox\//i.test(userAgent)
          ? 'Firefox'
          : /safari\//i.test(userAgent)
            ? 'Safari'
            : 'Browser';

  const os = /windows/i.test(userAgent)
    ? 'Windows'
    : /mac os x/i.test(userAgent)
      ? 'macOS'
      : /android/i.test(userAgent)
        ? 'Android'
        : /iphone|ipad|ipod/i.test(userAgent)
          ? 'iOS'
          : /linux/i.test(userAgent)
            ? 'Linux'
            : 'Unknown OS';

  return `${browser} on ${os}`;
}

/** Body shape accepted for device metadata (also supplied via headers). */
interface DeviceBodyFragment {
  device?: {
    deviceId?: unknown;
    fingerprint?: unknown;
    name?: unknown;
    platform?: unknown;
  };
}

const VALID_PLATFORMS = new Set<string>(Object.values(DEVICE_PLATFORM));

/**
 * Resolve the device identity for this request.
 *
 * Headers win over the body: they are set uniformly by every API client,
 * whereas the body form exists only for clients that cannot set custom headers.
 *
 * Returns `null` when no usable device id was supplied - the caller decides
 * whether that is acceptable (it is for `/login` from a brand-new browser; it is
 * not for endpoints that manage a specific device).
 */
export function getDeviceIdentity(req: Request): DeviceIdentity | null {
  const body = (req.body ?? {}) as DeviceBodyFragment;
  const fromBody = body.device ?? {};

  const headerDeviceId = headerValue(req, HEADERS.DEVICE_ID);
  const bodyDeviceId = typeof fromBody.deviceId === 'string' ? fromBody.deviceId : undefined;
  const deviceId = headerDeviceId ?? bodyDeviceId;

  if (!isValidClientDeviceId(deviceId)) return null;

  const userAgent = getUserAgent(req);

  const rawName =
    sanitizeText(headerValue(req, HEADERS.DEVICE_NAME), MAX_DEVICE_NAME_LENGTH) ??
    sanitizeText(
      typeof fromBody.name === 'string' ? fromBody.name : undefined,
      MAX_DEVICE_NAME_LENGTH,
    );

  const rawFingerprint =
    sanitizeText(headerValue(req, HEADERS.DEVICE_FINGERPRINT), MAX_FINGERPRINT_LENGTH) ??
    sanitizeText(
      typeof fromBody.fingerprint === 'string' ? fromBody.fingerprint : undefined,
      MAX_FINGERPRINT_LENGTH,
    );

  const rawPlatform = typeof fromBody.platform === 'string' ? fromBody.platform : undefined;
  const platform =
    rawPlatform !== undefined && VALID_PLATFORMS.has(rawPlatform)
      ? (rawPlatform as DevicePlatform)
      : inferPlatform(userAgent);

  return {
    deviceId,
    name: rawName ?? inferDeviceName(userAgent),
    platform,
    ...(rawFingerprint ? { fingerprint: rawFingerprint } : {}),
  };
}

/**
 * True when the caller cannot rely on cookies and needs tokens in the JSON body.
 *
 * The Chrome extension's service worker has no dependable cookie jar for
 * cross-origin requests, so it identifies itself explicitly rather than having
 * the server guess from the Origin header alone.
 */
export function isNonCookieClient(req: Request): boolean {
  const origin = headerValue(req, 'origin');
  if (origin?.startsWith('chrome-extension://')) return true;
  return headerValue(req, 'x-client-type')?.toLowerCase() === 'extension';
}

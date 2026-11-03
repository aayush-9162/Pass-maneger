/**
 * Build-time configuration.
 *
 * `VITE_API_URL` is the *default* server, baked in at build time; the build
 * also grants it in `host_permissions`. Users can point an installed extension
 * at another server - see `lib/server.ts`, which is what callers use.
 */

const rawApiUrl = (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:4000/api/v1';

export const DEFAULT_API_URL = rawApiUrl.replace(/\/$/, '');

/**
 * How long before expiry to renew the access token proactively.
 *
 * The service worker is unloaded when idle, so this is enforced with
 * `chrome.alarms` rather than a timer, which would not survive suspension.
 */
export const REFRESH_SKEW_SECONDS = 60;

/** Name of the alarm that drives proactive refresh. */
export const REFRESH_ALARM = 'passm:refresh';

/** Minimum alarm period Chrome will honour, in minutes. */
export const MIN_ALARM_PERIOD_MINUTES = 1;

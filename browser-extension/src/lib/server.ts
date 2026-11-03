/**
 * Which PassM server this extension talks to.
 *
 * The build bakes in a default (`VITE_API_URL`). An administrator can point an
 * installed extension somewhere else - the server's IP changed, say - from the
 * side panel or the sign-in screen, and that choice is kept in
 * `chrome.storage.local` until someone changes it again. It survives browser
 * restarts and signing out; "Use the default" removes it.
 *
 * Only the origin is configurable. The API path (`/api/v1`) comes from the
 * build, because it belongs to the server's version, not to where it lives.
 *
 * Reaching a new origin needs Chrome's permission for it. The manifest declares
 * any http(s) origin as *optional* - granted one at a time, when the user saves
 * an address - so the extension never holds blanket access to every site.
 */

import { DEFAULT_API_URL } from './config';

const SERVER_KEY = 'passm.serverOrigin';

const defaultUrl = new URL(DEFAULT_API_URL);

/** The build's server, e.g. `http://192.168.0.211.nip.io:1225`. */
export const DEFAULT_SERVER_ORIGIN = defaultUrl.origin;

/** The API path on whichever server, e.g. `/api/v1`. */
const API_PATH = defaultUrl.pathname.replace(/\/$/, '');

/** The server in use: the saved one, or the build's default. */
export async function getServerOrigin(): Promise<string> {
  try {
    const stored = await chrome.storage.local.get(SERVER_KEY);
    const value = stored[SERVER_KEY];
    return typeof value === 'string' && value.length > 0 ? value : DEFAULT_SERVER_ORIGIN;
  } catch {
    return DEFAULT_SERVER_ORIGIN;
  }
}

/** Base URL for API calls, e.g. `http://192.168.0.211.nip.io:1225/api/v1`. */
export async function getApiBaseUrl(): Promise<string> {
  return `${await getServerOrigin()}${API_PATH}`;
}

/** `null` returns to the build's default. */
export async function setServerOrigin(origin: string | null): Promise<void> {
  if (origin === null || origin === DEFAULT_SERVER_ORIGIN) {
    await chrome.storage.local.remove(SERVER_KEY);
  } else {
    await chrome.storage.local.set({ [SERVER_KEY]: origin });
  }
}

/**
 * Turn what someone typed into an origin.
 *
 * Accepts `192.168.0.211.nip.io:1225`, `http://192.168.0.211.nip.io:1225`, or a
 * full API URL; anything after the host and port is ignored. A missing scheme
 * means http, matching how the office network runs PassM.
 */
export function parseServerAddress(input: string): { origin: string } | { error: string } {
  const trimmed = input.trim();
  if (!trimmed) return { error: 'Enter the server address.' };

  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`);
  } catch {
    return { error: 'That is not a valid address.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { error: 'The address must start with http:// or https://.' };
  }
  if (!url.hostname) return { error: 'That address has no host name.' };

  return { origin: url.origin };
}

/** Does a PassM server answer at this origin? */
export async function checkServer(origin: string): Promise<boolean> {
  try {
    const response = await fetch(`${origin}${API_PATH}/health`, { credentials: 'omit' });
    return response.ok;
  } catch {
    return false;
  }
}

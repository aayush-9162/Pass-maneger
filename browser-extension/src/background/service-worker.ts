/**
 * MV3 service worker: the extension's only privileged context.
 *
 * ## Why everything lives here
 *
 * The popup is destroyed the moment it loses focus, and content scripts run
 * inside pages we do not trust. Neither can own a session: a refresh interrupted
 * halfway would leave the client holding a token the server has already rotated,
 * which the API correctly treats as replay and answers by revoking the session.
 *
 * So the worker owns authentication, the item index and every password fetch.
 * The other contexts send typed messages.
 *
 * ## Worker lifetime
 *
 * Chrome suspends an idle worker after roughly 30 seconds; module-level state
 * does not survive. Everything durable lives in `chrome.storage.session`, and
 * everything time-based runs on `chrome.alarms`, which does survive.
 *
 * ## Message trust
 *
 * `isContentRequest` gates what a tab may ask for. A compromised page can send
 * anything, so the worker refuses privileged message types that arrive with a
 * `sender.tab` - the vault index and arbitrary secrets are reachable only from
 * extension pages.
 */

import { ERROR_CODES, SECRET_PURPOSE, generatePassword } from '@passm/shared';

import { REFRESH_ALARM, REFRESH_SKEW_SECONDS } from '../lib/config';
import { ExtensionApiError, extensionApi, onSessionEnded } from '../lib/api';
import { clearFavorites, readFavorites, toggleFavorite } from '../lib/favorites';
import { readSettings } from '../lib/settings';
import {
  clearSession,
  clearVaultSession,
  lockDownSessionStorage,
  readSession,
  readVaultSession,
  touchVaultSession,
  writeSession,
  type StoredSession,
} from '../lib/storage';
import {
  isContentRequest,
  type AuthStatePayload,
  type BackgroundRequest,
  type BackgroundResponse,
  type ContentRequest,
  type CredentialSecret,
  type SearchResultPayload,
  type SuggestionsPayload,
  type VaultStatePayload,
} from '../lib/messages';
import { bestMatch } from '../lib/uri-match';
import { clipboard } from './clipboard';
import { contextMenus } from './context-menus';
import { registerHttpAuth } from './http-auth';
import { vaultSession } from './vault-session';

const VAULT_LOCK_ALARM = 'passm:vault-lock';

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
  void bootstrap();
});

chrome.runtime.onStartup.addListener(() => {
  void bootstrap();
});

/**
 * Load the item index if signed in and it is not loaded yet.
 *
 * This is what makes a browser restart invisible: the auth session survives in
 * local storage, so the first thing that needs the vault finds it open.
 */
async function ensureVaultOpen(): Promise<void> {
  if (await readVaultSession()) return;

  const session = await getUsableSession();
  if (!session) return;

  try {
    await vaultSession.open(session.accessToken);
    await refreshContextMenus();
  } catch (error) {
    console.warn('[PassM] Could not load the vault.', error);
  }
}

async function bootstrap(): Promise<void> {
  await lockDownSessionStorage();
  // The session now survives restarts, so the refresh alarm must too.
  if (await readSession()) {
    await ensureRefreshAlarm();
    await ensureVaultOpen();
  }
  await refreshContextMenus();

  // Opening the side panel from the toolbar icon is a Chrome-level behaviour,
  // set once rather than per click.
  try {
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
  } catch {
    // Older Chrome without the side panel API; the popup still works.
  }
}

// ---------------------------------------------------------------------------
// Alarms
// ---------------------------------------------------------------------------

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) {
    void maintainSession();
    return;
  }

  if (alarm.name === VAULT_LOCK_ALARM) {
    // The idle lock is gone, but an alarm armed by an older build survives in
    // the browser's alarm store and would fire exactly once - locking a vault
    // the settings say should never lock. Swallow it and clear it instead.
    void chrome.alarms.clear(VAULT_LOCK_ALARM);
    return;
  }

  if (clipboard.isClearAlarm(alarm.name)) {
    void clipboard.clear();
  }
});

async function ensureRefreshAlarm(): Promise<void> {
  const existing = await chrome.alarms.get(REFRESH_ALARM);
  if (existing) return;
  await chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: 1 });
}

async function scheduleVaultLock(): Promise<void> {
  const { autoLockMinutes } = await readSettings();

  // Zero means never. Clearing rather than skipping matters: an alarm armed
  // before the setting changed would otherwise still be pending and would lock
  // the vault once more, which reads as the setting not working.
  if (autoLockMinutes <= 0) {
    await chrome.alarms.clear(VAULT_LOCK_ALARM);
    return;
  }

  await chrome.alarms.create(VAULT_LOCK_ALARM, { delayInMinutes: autoLockMinutes });
}

/** Discard the item index and tell every tab the UI should go away. */
async function lockVault(): Promise<void> {
  await clearVaultSession();
  await chrome.alarms.clear(VAULT_LOCK_ALARM);
  await refreshContextMenus();
  await broadcastVaultState();
}

// ---------------------------------------------------------------------------
// Authentication session
// ---------------------------------------------------------------------------

function needsRefresh(session: StoredSession): boolean {
  return Date.now() >= session.accessTokenExpiresAt - REFRESH_SKEW_SECONDS * 1000;
}

/**
 * Rotate the token pair.
 *
 * @returns the refreshed session, or `null` when the refresh token is no longer
 *   accepted - in which case local state is cleared, because retrying with a
 *   rejected token only risks tripping the API's replay detection.
 */
async function refreshSession(session: StoredSession): Promise<StoredSession | null> {
  try {
    const result = await extensionApi.refresh(session.refreshToken);

    const refreshed: StoredSession = {
      accessToken: result.tokens.accessToken,
      refreshToken: result.tokens.refreshToken ?? session.refreshToken,
      accessTokenExpiresAt: Date.now() + result.tokens.expiresIn * 1000,
      user: result.user,
      sessionId: result.session.id,
    };

    await writeSession(refreshed);
    return refreshed;
  } catch (error) {
    if (error instanceof ExtensionApiError && error.statusCode === 0) {
      // Network failure: the token may still be valid, so keep it and let the
      // next alarm tick try again.
      return session;
    }

    await endLocalSession();
    return null;
  }
}

/** Why the server ended the last sign-in, shown on the sign-in screen. */
const SIGNED_OUT_REASON_KEY = 'passm.signedOutReason';

/**
 * Forget the sign-in on this browser: tokens, the item list and every timer,
 * then tell the open surfaces so they show the sign-in screen.
 */
async function endLocalSession(reason?: string): Promise<void> {
  await clearSession();
  await clearVaultSession();
  await chrome.alarms.clear(REFRESH_ALARM);
  await chrome.alarms.clear(VAULT_LOCK_ALARM);
  if (reason) await chrome.storage.session.set({ [SIGNED_OUT_REASON_KEY]: reason });
  await refreshContextMenus();
  await broadcastVaultState();
}

/*
 * The server ended this sign-in (signed out by an administrator, role changed,
 * account locked). Without this the extension kept its stale tokens and item
 * list, looked signed in, and every fill failed silently.
 */
let endingSession: Promise<void> | null = null;
onSessionEnded((error, rejectedAccessToken) => {
  endingSession ??= (async () => {
    // A late answer to a request made with an earlier sign-in's token must not
    // end the newer one.
    const current = await readSession();
    if (current?.accessToken !== rejectedAccessToken) return;

    // Locked / disabled: the server's own wording says what to do. Otherwise
    // the usual cause is an administrator ending the session or changing the
    // person's role.
    const accountBlocked =
      error.code === ERROR_CODES.ACCOUNT_LOCKED || error.code === ERROR_CODES.ACCOUNT_DISABLED;
    await endLocalSession(
      accountBlocked
        ? error.message
        : 'You were signed out - an administrator ended your session or changed your access. Sign in again to continue.',
    );
  })().finally(() => {
    endingSession = null;
  });
});

async function maintainSession(): Promise<void> {
  const session = await readSession();
  if (!session) {
    await chrome.alarms.clear(REFRESH_ALARM);
    return;
  }

  if (needsRefresh(session)) await refreshSession(session);
}

/** A session with a usable access token, refreshing on demand. */
async function getUsableSession(): Promise<StoredSession | null> {
  const session = await readSession();
  if (!session) return null;
  if (!needsRefresh(session)) return session;
  return refreshSession(session);
}

async function requireAccessToken(): Promise<string> {
  const session = await getUsableSession();
  if (!session) throw new Error('Sign in to PassM first.');
  return session.accessToken;
}

// The browser's own "Sign in" box (HTTP Basic/Digest). Registered at the top
// level so Chrome can wake the worker for it.
registerHttpAuth(requireAccessToken);

// ---------------------------------------------------------------------------
// Broadcasting state
// ---------------------------------------------------------------------------

/** Tell every http(s) tab whether the vault is open, so buttons match reality. */
async function broadcastVaultState(): Promise<void> {
  const session = await readSession();
  const state = await vaultSession.getState(session?.accessToken ?? null);
  const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });

  const message: ContentRequest = {
    type: 'CONTENT_VAULT_STATE',
    state,
    suggestionCount: 0,
  };

  await Promise.all(
    tabs.map(async (tab) => {
      if (tab.id === undefined) return;
      try {
        await chrome.tabs.sendMessage(tab.id, message);
      } catch {
        // No content script in that tab (a restricted page, or not yet loaded).
      }
    }),
  );
}

/** Rebuild the context menu for the active tab's matches. */
async function refreshContextMenus(): Promise<void> {
  const session = await readSession();
  const vault = await readVaultSession();

  let suggestions: { id: string; name: string; username: string | null }[] = [];

  if (vault) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      suggestions = (await vaultSession.suggestionsFor(tab.url)).map((suggestion) => ({
        id: suggestion.itemId,
        name: suggestion.name,
        username: suggestion.username,
      }));
    }
  }

  await contextMenus.rebuild({
    signedIn: session !== null,
    unlocked: vault !== null,
    suggestions,
  });
}

// The menu is per-tab in effect, so it is rebuilt as the user moves around.
chrome.tabs.onActivated.addListener(() => void refreshContextMenus());
chrome.tabs.onUpdated.addListener((_tabId, info) => {
  if (info.status === 'complete') void refreshContextMenus();
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  void (async () => {
    const result = await contextMenus.handleClick(info, tab);

    if (result.action === 'fill') {
      await fillTab(result.tabId, result.itemId);
      return;
    }

    if (result.action === 'open-vault' && result.tabId !== undefined) {
      try {
        await chrome.sidePanel.open({ tabId: result.tabId });
      } catch {
        // Side panel unavailable; the popup remains the entry point.
      }
    }
  })();
});

// ---------------------------------------------------------------------------
// Filling
// ---------------------------------------------------------------------------

/** Fetch a credential and send it to a tab's content script. */
async function fillTab(tabId: number, itemId: string, submit = false): Promise<boolean> {
  const accessToken = await requireAccessToken();
  const secret = await vaultSession.revealSecret(accessToken, itemId, SECRET_PURPOSE.FILL);

  const message: ContentRequest = {
    type: 'CONTENT_FILL',
    itemId,
    username: secret.username,
    password: secret.password,
    totp: secret.totp,
    submit,
  };

  try {
    await chrome.tabs.sendMessage(tabId, message);
    // Filling is user activity; push the auto-lock deadline out.
    const { autoLockMinutes } = await readSettings();
    await touchVaultSession(autoLockMinutes);
    await scheduleVaultLock();
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Request handlers
// ---------------------------------------------------------------------------

async function handleAuthState(): Promise<AuthStatePayload> {
  const session = await getUsableSession();

  if (!session) {
    const stored = await chrome.storage.session.get(SIGNED_OUT_REASON_KEY);
    const reason = stored[SIGNED_OUT_REASON_KEY];
    return {
      authenticated: false,
      user: null,
      sessionId: null,
      accessTokenExpiresAt: null,
      signedOutReason: typeof reason === 'string' ? reason : null,
    };
  }

  return {
    authenticated: true,
    user: session.user,
    sessionId: session.sessionId,
    accessTokenExpiresAt: session.accessTokenExpiresAt,
  };
}

/**
 * Ask Google for an ID token, through Chrome's own sign-in window.
 *
 * `launchWebAuthFlow` opens Google's account chooser and returns to
 * `https://<extension-id>.chromiumapp.org/`, which must be listed as an
 * authorised redirect URI on the OAuth client. The token comes back in the URL
 * fragment (the implicit `id_token` flow), so no client secret is involved.
 *
 * The nonce is checked here as well as being required by Google: a token that
 * does not carry the one this call generated was not minted for this call.
 */
async function requestGoogleIdToken(): Promise<string> {
  const config = await extensionApi.googleConfig();
  if (!config.clientId) {
    throw new Error('Google sign-in is not configured on the PassM server.');
  }

  const nonce = crypto.randomUUID();
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', config.clientId);
  authUrl.searchParams.set('response_type', 'id_token');
  authUrl.searchParams.set('redirect_uri', chrome.identity.getRedirectURL());
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('prompt', 'select_account');
  // A hint for the account chooser only; the server enforces the domain.
  if (config.hostedDomain) authUrl.searchParams.set('hd', config.hostedDomain);

  let responseUrl: string | undefined;
  try {
    responseUrl = await chrome.identity.launchWebAuthFlow({
      url: authUrl.toString(),
      interactive: true,
    });
  } catch (error) {
    // Chrome reports a closed window as an error with no useful detail.
    throw new Error(
      error instanceof Error && /closed|cancel/i.test(error.message)
        ? 'Google sign-in was cancelled.'
        : 'Google sign-in could not be completed.',
    );
  }
  if (!responseUrl) throw new Error('Google sign-in was cancelled.');

  const fragment = new URLSearchParams(new URL(responseUrl).hash.slice(1));
  const googleError = fragment.get('error');
  if (googleError) throw new Error(`Google refused the sign-in (${googleError}).`);

  const idToken = fragment.get('id_token');
  if (!idToken) throw new Error('Google did not return a sign-in token.');

  const payload = JSON.parse(
    atob(idToken.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')),
  ) as { nonce?: string };
  if (payload.nonce !== nonce) throw new Error('Google sign-in could not be verified.');

  return idToken;
}

async function handleLogin(rememberDevice: boolean): Promise<AuthStatePayload> {
  const credential = await requestGoogleIdToken();
  const result = await extensionApi.googleLogin(credential, rememberDevice);

  if (!result.tokens.refreshToken) {
    // The API only omits it when it believes the client uses cookies, which
    // would mean the `x-client-type: extension` header did not arrive.
    throw new Error('The server did not return a refresh token for this client.');
  }

  await writeSession({
    accessToken: result.tokens.accessToken,
    refreshToken: result.tokens.refreshToken,
    accessTokenExpiresAt: Date.now() + result.tokens.expiresIn * 1000,
    user: result.user,
    sessionId: result.session.id,
  });
  await chrome.storage.session.remove(SIGNED_OUT_REASON_KEY);

  try {
    await vaultSession.open(result.tokens.accessToken);
  } catch (error) {
    // Signed in, but the list did not load. The session stays valid so the
    // popup can retry rather than failing the whole sign-in.
    console.warn('[PassM] Signed in, but the vault could not be loaded.', error);
  }

  await ensureRefreshAlarm();
  await refreshContextMenus();

  return {
    authenticated: true,
    user: result.user,
    sessionId: result.session.id,
    accessTokenExpiresAt: Date.now() + result.tokens.expiresIn * 1000,
  };
}

async function handleLogout(): Promise<AuthStatePayload> {
  const session = await readSession();

  if (session) {
    try {
      await extensionApi.logout(session.accessToken, session.refreshToken);
    } catch {
      // Server-side revocation failed; local state is cleared regardless. The
      // token expires on its own, and leaving it here would be worse.
    }
  }

  // Favourites are per-device and per-user. Signing out on a shared machine
  // should not leave the next person a list of the sites this one has accounts
  // with - the ids alone would say that much.
  if (session) await clearFavorites(session.user.id);

  await endLocalSession();

  return { authenticated: false, user: null, sessionId: null, accessTokenExpiresAt: null };
}

async function handleVaultState(): Promise<VaultStatePayload> {
  const session = await readSession();
  const state = await vaultSession.getState(session?.accessToken ?? null);
  const vault = await readVaultSession();

  return {
    state,
    itemCount: vault?.index.length ?? 0,
    syncedAt: vault?.syncedAt ?? null,
    lockAt: vault?.lockAt ?? null,
  };
}

/**
 * Message router.
 *
 * `sendResponse` is called asynchronously, so the listener returns `true` to
 * keep the channel open. Returning a promise instead does not work in Chrome.
 */
chrome.runtime.onMessage.addListener(
  (
    request: BackgroundRequest,
    sender,
    sendResponse: (response: BackgroundResponse<unknown>) => void,
  ) => {
    // Messages relayed to the offscreen document are not for this listener.
    if ((request as { target?: string }).target === 'offscreen-clipboard') return false;

    void (async () => {
      try {
        /*
         * Trust is decided by origin, not by "is it in a tab".
         *
         * A content script runs on a hostile page, so its sender URL is that
         * page's - it may only send the small allow-listed set. But the full
         * view is our own popup.html opened AS a tab, and judging it by
         * `sender.tab` alone locked the extension's own page out of its own
         * worker - which surfaced as a sign-in prompt in the full view.
         * Chrome sets the sender URL itself; a content script cannot forge it.
         */
        const ownPage = sender.url?.startsWith(chrome.runtime.getURL('')) === true;
        const fromTab = sender.tab !== undefined && !ownPage;
        if (fromTab && !isContentRequest(request.type)) {
          sendResponse({ ok: false, error: 'That action is not available from a page.' });
          return;
        }

        /*
         * Reopen the vault before handling anything, if a persisted key allows.
         *
         * `onStartup` does this too, but a popup opened quickly after a browser
         * start - or a page asking for suggestions - can race it, and losing
         * that race would show "locked" to a user who never has to unlock.
         * Costs one storage read when the vault is already open.
         */
        await ensureVaultOpen();

        switch (request.type) {
          // --- Authentication ------------------------------------------------
          case 'AUTH_STATE':
            sendResponse({ ok: true, data: await handleAuthState() });
            return;

          case 'LOGIN':
            sendResponse({ ok: true, data: await handleLogin(request.rememberDevice) });
            return;

          case 'LOGOUT':
            sendResponse({ ok: true, data: await handleLogout() });
            return;

          // --- Vault ---------------------------------------------------------
          case 'VAULT_STATE':
            sendResponse({ ok: true, data: await handleVaultState() });
            return;

          // The user pointed the extension at another server (lib/server.ts).
          // The session belongs to the same PassM deployment, so it is kept;
          // only the list is fetched again from the new address. A refresh the
          // new server rejects signs out through the usual path.
          case 'SERVER_CHANGED': {
            await clearVaultSession();
            await ensureVaultOpen();
            await refreshContextMenus();
            await broadcastVaultState();
            sendResponse({ ok: true, data: await handleVaultState() });
            return;
          }

          // Load the list again, after a failure at sign-in.
          case 'VAULT_UNLOCK': {
            await vaultSession.open(await requireAccessToken());
            await scheduleVaultLock();
            await refreshContextMenus();
            await broadcastVaultState();
            sendResponse({ ok: true, data: await handleVaultState() });
            return;
          }

          /*
           * Lock means sign out. The server releases passwords to any live
           * session, so a lock that kept the session would be undone by the
           * next request; reopening must take a fresh Google sign-in.
           */
          case 'VAULT_LOCK':
            await lockVault();
            await handleLogout();
            sendResponse({ ok: true, data: await handleVaultState() });
            return;

          case 'VAULT_SYNC': {
            const accessToken = await requireAccessToken();
            await vaultSession.resync(accessToken);
            sendResponse({ ok: true, data: await handleVaultState() });
            return;
          }

          case 'VAULT_SEARCH':
            sendResponse({
              ok: true,
              data: {
                items: await vaultSession.search(request.query, request.limit ?? 20),
              } satisfies SearchResultPayload,
            });
            return;

          case 'VAULT_FAVORITES': {
            const session = await readSession();
            sendResponse({
              ok: true,
              data: {
                items: session
                  ? await vaultSession.favorites(session.user.id, request.limit ?? 20)
                  : [],
              },
            });
            return;
          }

          case 'TOGGLE_FAVORITE': {
            const session = await readSession();
            if (!session) {
              sendResponse({ ok: false, error: 'Sign in first.' });
              return;
            }
            const favorite = await toggleFavorite(session.user.id, request.itemId);
            sendResponse({ ok: true, data: { favorite } });
            return;
          }

          case 'GET_FAVORITES': {
            const session = await readSession();
            sendResponse({
              ok: true,
              data: {
                ids: session ? [...(await readFavorites(session.user.id))] : [],
              },
            });
            return;
          }

          case 'VAULT_RECENT':
            sendResponse({
              ok: true,
              data: { items: await vaultSession.recent(request.limit ?? 10) },
            });
            return;

          /*
           * There is deliberately no message that hands a stored password back
           * to a caller.
           *
           * `GET_SECRET` and `COPY_SECRET` used to live here, for a popup that
           * offered copy buttons. That popup now launches and fills instead, and
           * leaving the handlers behind would have left the capability reachable
           * by any extension page for no remaining feature - the opposite of the
           * password-access policy the console enforces.
           *
           * `REQUEST_FILL` below is the only path a password takes out of this
           * worker, and it checks that the item belongs to the requesting page
           * first.
           */
          // --- Content script ------------------------------------------------
          case 'PAGE_SUGGESTIONS': {
            const session = await readSession();
            const state = await vaultSession.getState(session?.accessToken ?? null);

            sendResponse({
              ok: true,
              data: {
                // Names and usernames only; no secret leaves the worker here.
                suggestions:
                  state === 'unlocked' ? await vaultSession.suggestionsFor(request.url) : [],
                vaultState: state,
                autoFillOnLoad: (await readSettings()).autoFillOnLoad,
              } satisfies SuggestionsPayload,
            });
            return;
          }

          case 'REQUEST_FILL': {
            const accessToken = await requireAccessToken();

            // Re-check that this item actually matches the requesting page. The
            // content script names an item id, and a compromised page could name
            // any id it liked - this is what stops it asking for an unrelated
            // credential.
            const entry = await vaultSession.findEntry(request.itemId);
            if (!entry || bestMatch(entry.uris, request.url) === 'none') {
              sendResponse({ ok: false, error: 'That credential does not belong to this site.' });
              return;
            }

            const secret = await vaultSession.revealSecret(
              accessToken,
              request.itemId,
              SECRET_PURPOSE.FILL,
            );
            const { autoLockMinutes } = await readSettings();
            await touchVaultSession(autoLockMinutes);
            await scheduleVaultLock();

            sendResponse({ ok: true, data: secret satisfies CredentialSecret });
            return;
          }

          case 'REPORT_FIELD_TAMPER': {
            // The content script already re-masked the field. This only makes
            // sure the attempt is not invisible: an administrator seeing
            // "Reveal blocked by policy" against a user and a host learns
            // something the extension could never have prevented outright.
            const session = await readSession();
            if (session) {
              await extensionApi.reportAccessEvent(session.accessToken, {
                action: 'reveal_blocked',
                itemId: request.itemId,
                field: 'password',
                // The site it happened on. An item id alone names a row nobody
                // reading the trail can look up, so this is the part that says
                // which account was being gone after.
                host: request.host,
              });
              console.warn('[PassM] a filled password field was unmasked', {
                host: request.host,
                itemId: request.itemId,
              });
            }
            sendResponse({ ok: true, data: { received: true } });
            return;
          }

          // --- Misc ----------------------------------------------------------
          case 'FILL_ACTIVE_TAB': {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.id === undefined) {
              sendResponse({ ok: false, error: 'No active tab.' });
              return;
            }
            sendResponse({ ok: true, data: { filled: await fillTab(tab.id, request.itemId) } });
            return;
          }

          /**
           * Open the site, wait for it, fill and sign in.
           *
           * The wait is the fiddly part: `chrome.tabs.create` resolves as soon
           * as the tab exists, long before the content script is running. So we
           * listen for the tab to finish loading, then fill - rather than
           * guessing with a fixed delay that is either too short on a slow
           * connection or needlessly slow on a fast one.
           */
          case 'LAUNCH_AND_FILL': {
            const entry = await vaultSession.findEntry(request.itemId);

            if (!entry) {
              sendResponse({ ok: false, error: 'That item is no longer in your vault.' });
              return;
            }

            const target = entry.uris[0];
            if (!target) {
              sendResponse({
                ok: false,
                error: 'This entry has no website address saved, so there is nothing to open.',
              });
              return;
            }

            const url = /^https?:\/\//i.test(target) ? target : `https://${target}`;
            const tab = await chrome.tabs.create({ url, active: true });

            if (tab.id === undefined) {
              sendResponse({ ok: false, error: 'The page could not be opened.' });
              return;
            }

            const tabId = tab.id;

            // Resolve on load, or give up after 15 seconds rather than leaving
            // a listener attached to a tab that never finishes.
            await new Promise<void>((resolve) => {
              const timeout = setTimeout(finish, 15_000);

              function finish(): void {
                clearTimeout(timeout);
                chrome.tabs.onUpdated.removeListener(onUpdated);
                resolve();
              }

              function onUpdated(updatedId: number, info: chrome.tabs.TabChangeInfo): void {
                if (updatedId === tabId && info.status === 'complete') finish();
              }

              chrome.tabs.onUpdated.addListener(onUpdated);
            });

            // A further beat for single-page apps that render the form after
            // `complete`. Cheap, and the difference between working and not on
            // a lot of modern sign-in pages.
            await new Promise((resolve) => setTimeout(resolve, 600));

            const filled = await fillTab(tabId, request.itemId, true);
            sendResponse({ ok: true, data: { filled } });
            return;
          }

          case 'OPEN_SIDE_PANEL': {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab?.id !== undefined) await chrome.sidePanel.open({ tabId: tab.id });
            sendResponse({ ok: true, data: { opened: true } });
            return;
          }

          case 'GENERATE_PASSWORD':
            sendResponse({
              ok: true,
              data: {
                password: generatePassword({
                  length: request.length ?? 20,
                  pronounceable: request.pronounceable ?? false,
                }),
              },
            });
            return;

          default: {
            // Exhaustiveness check: a new request type without a case here is a
            // compile error, not a silent failure.
            const unhandled: never = request;
            sendResponse({ ok: false, error: `Unsupported request: ${JSON.stringify(unhandled)}` });
          }
        }
      } catch (error) {
        sendResponse({
          ok: false,
          error: error instanceof Error ? error.message : 'Unexpected error.',
          ...(error instanceof ExtensionApiError ? { code: error.code } : {}),
        });
      }
    })();

    // Keep the message channel open for the async response above.
    return true;
  },
);

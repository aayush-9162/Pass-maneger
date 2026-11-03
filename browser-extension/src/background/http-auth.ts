/**
 * HTTP authentication: the browser's own "Sign in" box.
 *
 * Some sites (vendor extranets, routers, old intranet pages) do not have a login
 * form at all. The server answers 401 with `WWW-Authenticate: Basic` (or Digest)
 * and Chrome draws its own username/password dialog. That dialog is browser UI,
 * not page DOM, so the content script cannot see it or fill it.
 *
 * Chrome instead lets an extension answer the challenge itself
 * (`webRequest.onAuthRequired`). This does so when the vault holds a login saved
 * for that exact site.
 *
 * ## Why answering without a click is acceptable here
 *
 * Page autofill is opt-in because a hostile page can hide or overlay a form and
 * harvest what gets filled into it. Neither is possible here: the credentials go
 * straight to the server that asked, through the browser, and no page script
 * ever sees them. Two further limits keep it tight:
 *
 *  - **Top-level pages only.** A page cannot embed the vendor in a hidden frame
 *    and make PassM sign the visitor in behind their back.
 *  - **The exact site only.** A login saved for `extranet.example.com` is used on
 *    that host, never on a sibling subdomain that merely shares the domain.
 *
 * Each answer is one password release, audited as "filled" like any other.
 */

import { SECRET_PURPOSE } from '@passm/shared';

import { vaultSession } from './vault-session';

/**
 * Requests already answered. If the server rejects what was sent, Chrome raises
 * the challenge again on the same request id - the second time the person gets
 * the normal dialog instead of PassM retrying a wrong password forever.
 */
const answered = new Set<string>();

/**
 * The one login to use for a URL, or null to leave the dialog to the person.
 *
 * Only exact-origin or same-host matches qualify. With several, an exact-origin
 * match wins if it is the only one; anything more ambiguous is not guessed at.
 */
async function pickLogin(url: string): Promise<string | null> {
  const candidates = (await vaultSession.suggestionsFor(url)).filter(
    (suggestion) => suggestion.confidence === 'exact' || suggestion.confidence === 'host',
  );
  if (candidates.length === 1) return candidates[0]?.itemId ?? null;

  const exact = candidates.filter((suggestion) => suggestion.confidence === 'exact');
  return exact.length === 1 ? (exact[0]?.itemId ?? null) : null;
}

async function answer(
  details: chrome.webRequest.WebAuthenticationChallengeDetails,
  requireAccessToken: () => Promise<string>,
): Promise<chrome.webRequest.BlockingResponse> {
  // A proxy's challenge is about the network, not a saved site login.
  if (details.isProxy || answered.has(details.requestId)) return {};

  try {
    const itemId = await pickLogin(details.url);
    if (!itemId) return {};

    const accessToken = await requireAccessToken();
    const secret = await vaultSession.revealSecret(accessToken, itemId, SECRET_PURPOSE.FILL);
    if (!secret.username || !secret.password) return {};

    answered.add(details.requestId);
    return { authCredentials: { username: secret.username, password: secret.password } };
  } catch {
    // Signed out, vault closed, password hidden from this person, server down:
    // the browser's own dialog is the right fallback for all of them.
    return {};
  }
}

/** Start answering HTTP authentication challenges. Call once, at worker start. */
export function registerHttpAuth(requireAccessToken: () => Promise<string>): void {
  const filter: chrome.webRequest.RequestFilter = {
    urls: ['http://*/*', 'https://*/*'],
    types: ['main_frame'],
  };

  chrome.webRequest.onAuthRequired.addListener(
    (details, callback) => {
      void answer(details, requireAccessToken).then((response) => callback?.(response));
    },
    filter,
    ['asyncBlocking'],
  );

  // Forget finished requests so the set does not grow for the browser's lifetime.
  const forget = (details: { requestId: string }): void => {
    answered.delete(details.requestId);
  };
  chrome.webRequest.onCompleted.addListener(forget, filter);
  chrome.webRequest.onErrorOccurred.addListener(forget, filter);
}

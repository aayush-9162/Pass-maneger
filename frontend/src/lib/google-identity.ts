/**
 * Google Identity Services: the "Sign in with Google" button.
 *
 * The script is Google's, loaded on demand from accounts.google.com (the CSP
 * allows exactly its `/gsi/` paths). It renders the button in an iframe and
 * hands back an ID token - the `credential` - which the API verifies. Nothing
 * here touches the token beyond passing it on.
 *
 * Used twice: on the sign-in page, and in the step-up dialog, where the
 * server's challenge nonce is passed as `nonce` so the resulting token can only
 * satisfy that one challenge.
 */

import type { GoogleSignInConfig } from '@passm/shared';

import { api } from './api-client';

const GIS_SRC = 'https://accounts.google.com/gsi/client';

interface CredentialResponse {
  credential: string;
}

interface GoogleAccountsId {
  initialize(options: {
    client_id: string;
    callback: (response: CredentialResponse) => void;
    nonce?: string;
    hd?: string;
    auto_select?: boolean;
    cancel_on_tap_outside?: boolean;
  }): void;
  renderButton(
    parent: HTMLElement,
    options: {
      type?: 'standard' | 'icon';
      theme?: 'outline' | 'filled_blue' | 'filled_black';
      size?: 'large' | 'medium' | 'small';
      text?: 'signin_with' | 'continue_with' | 'signin';
      shape?: 'rectangular' | 'pill';
      width?: number;
    },
  ): void;
  disableAutoSelect(): void;
}

declare global {
  interface Window {
    google?: { accounts?: { id?: GoogleAccountsId } };
  }
}

let scriptLoad: Promise<GoogleAccountsId> | null = null;
let configLoad: Promise<GoogleSignInConfig> | null = null;

/** Load Google's script once per page. */
function loadGis(): Promise<GoogleAccountsId> {
  scriptLoad ??= new Promise<GoogleAccountsId>((resolve, reject) => {
    const ready = (): void => {
      const id = window.google?.accounts?.id;
      if (id) resolve(id);
      else reject(new Error('Google Sign-In did not initialise.'));
    };

    if (window.google?.accounts?.id) {
      ready();
      return;
    }

    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    script.addEventListener('load', ready);
    script.addEventListener('error', () => {
      // Let a later attempt retry rather than caching the failure forever.
      scriptLoad = null;
      reject(
        new Error('Could not reach Google to sign in. Check this computer can reach accounts.google.com.'),
      );
    });
    document.head.appendChild(script);
  });
  return scriptLoad;
}

/** The server's Google settings, fetched once per page. */
function loadConfig(): Promise<GoogleSignInConfig> {
  configLoad ??= api.getGoogleConfig().catch((error: unknown) => {
    configLoad = null;
    throw error;
  });
  return configLoad;
}

/**
 * Render Google's button into `parent`; `onCredential` receives the ID token
 * when the user completes sign-in.
 *
 * @param options.nonce Bind the resulting token to a server challenge.
 */
export async function renderGoogleButton(
  parent: HTMLElement,
  onCredential: (credential: string) => void,
  options: { nonce?: string; text?: 'signin_with' | 'continue_with'; width?: number } = {},
): Promise<void> {
  const config = await loadConfig();
  if (!config.clientId) {
    throw new Error('Google sign-in is not configured on the server (GOOGLE_CLIENT_ID).');
  }

  const id = await loadGis();
  id.initialize({
    client_id: config.clientId,
    callback: (response) => onCredential(response.credential),
    // A hint for the account chooser only; the server enforces the domain.
    ...(config.hostedDomain ? { hd: config.hostedDomain } : {}),
    ...(options.nonce ? { nonce: options.nonce } : {}),
    auto_select: false,
    cancel_on_tap_outside: true,
  });

  parent.replaceChildren();
  id.renderButton(parent, {
    type: 'standard',
    theme: 'outline',
    size: 'large',
    shape: 'rectangular',
    text: options.text ?? 'signin_with',
    width: options.width ?? 320,
  });
}

/** After signing out: stop Google offering to sign straight back in. */
export function forgetGoogleSelection(): void {
  try {
    window.google?.accounts?.id?.disableAutoSelect();
  } catch {
    // Script never loaded on this page; nothing to forget.
  }
}

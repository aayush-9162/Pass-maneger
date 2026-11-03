/**
 * Components shared by the popup and the side panel.
 *
 * Both surfaces show the same item list with the same actions, so the list lives
 * here rather than being written twice - the copy and fill behaviour is
 * security-relevant, and two implementations would eventually disagree.
 */

import * as React from 'react';

import {
  DEFAULT_PASSWORD_OPTIONS,
  estimatePasswordEntropy,
  generatePassword,
  passwordStrength,
  type PasswordGeneratorOptions,
} from '@passm/shared';

import { sendToBackground } from '../lib/messages';
import {
  DEFAULT_SERVER_ORIGIN,
  checkServer,
  getApiBaseUrl,
  getServerOrigin,
  originPattern,
  parseServerAddress,
  setServerOrigin,
} from '../lib/server';
import type { VaultIndexEntry } from '../lib/storage';

// ---------------------------------------------------------------------------
// Item list
// ---------------------------------------------------------------------------

export interface ItemListProps {
  items: VaultIndexEntry[];
  emptyMessage: string;
  /** Shown when a fill is possible - the popup has an active tab, the panel too. */
  /** The tab the popup was opened over, used to decide fill versus launch. */
  pageUrl?: string | null;
  /** Item ids starred on this device. */
  favorites?: Set<string>;
  onToggleFavorite?: (itemId: string) => void;
  onCopied: (message: string) => void;
  onError: (message: string) => void;
}

/** Join class names, dropping falsy ones. */
function cn(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(' ');
}

/** Hostname of a URL or bare domain, without `www.`. Null when unparseable. */
function hostOf(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    return url.hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Where a site's logo may be found, in the order worth trying.
 *
 * First the PassM server's icon relay: the public icon services answer
 * unknown domains with a placeholder image browsers render even under a 404
 * status, so an `<img>` pointed straight at them can never fail over - every
 * entry wore the same grey globe. The relay reads the real status server-side
 * and returns an honest empty 404 instead, which does trigger `onError`. The
 * site's own /favicon.ico is the second chance; the lettered tile is the end
 * of the line. Fetched live, stored nowhere.
 */
function faviconCandidates(host: string, apiBaseUrl: string | null): string[] {
  return [
    ...(apiBaseUrl ? [`${apiBaseUrl}/icons/${encodeURIComponent(host)}`] : []),
    `https://${host}/favicon.ico`,
  ];
}

/** The API base URL in use, loaded once per mount. */
function useApiBaseUrl(): string | null {
  const [base, setBase] = React.useState<string | null>(null);
  React.useEffect(() => {
    void getApiBaseUrl().then(setBase);
  }, []);
  return base;
}

export function ItemList({
  items,
  emptyMessage,
  pageUrl,
  favorites,
  onToggleFavorite,
  onCopied,
  onError,
}: ItemListProps): React.ReactElement {
  if (items.length === 0) {
    return <p className="empty">{emptyMessage}</p>;
  }

  return (
    <ul className="item-list">
      {items.map((item) => (
        <ItemRow
          key={item.id}
          item={item}
          pageUrl={pageUrl ?? null}
          isFavorite={favorites?.has(item.id) ?? false}
          onToggleFavorite={onToggleFavorite ?? (() => undefined)}
          onCopied={onCopied}
          onError={onError}
        />
      ))}
    </ul>
  );
}

/**
 * One credential.
 *
 * ## One action, not four
 *
 * The row used to offer copy-username, copy-password and fill as three separate
 * buttons. That is three decisions and a lot of clicking for the thing people
 * actually want, which is to be signed in. Clicking the row now does the whole
 * job: open the site, fill both fields, and submit.
 *
 * On a page that is already the right site, it fills in place instead of opening
 * a second tab - opening a duplicate of the page you are looking at is a small
 * thing that feels broken.
 *
 * ## What happens to entries with no password
 *
 * A shared vault entry whose password is hidden from this member cannot be
 * signed in with. The row says so rather than offering an action that would
 * silently half-work.
 */
function ItemRow({
  item,
  pageUrl,
  isFavorite,
  onToggleFavorite,
  onCopied,
  onError,
}: {
  item: VaultIndexEntry;
  /** The tab the popup was opened over, or null if it is not a web page. */
  pageUrl?: string | null;
  isFavorite: boolean;
  onToggleFavorite: (itemId: string) => void;
  onCopied: (message: string) => void;
  onError: (message: string) => void;
}): React.ReactElement {
  const [busy, setBusy] = React.useState(false);

  const host = React.useMemo(() => hostOf(item.uris[0]), [item.uris]);

  // Which favicon source is being tried; an error advances to the next, and
  // past the end the tile falls back to the entry's initial.
  const [iconIndex, setIconIndex] = React.useState(0);
  React.useEffect(() => setIconIndex(0), [host]);

  const apiBaseUrl = useApiBaseUrl();
  const candidates = host ? faviconCandidates(host, apiBaseUrl) : [];
  const iconSrc = candidates[iconIndex] ?? null;
  const showIcon = iconSrc !== null;

  const iconRef = React.useRef<HTMLImageElement | null>(null);
  const advanceIcon = React.useCallback(() => setIconIndex((current) => current + 1), []);

  // A "complete" image with zero pixels failed before the error handler was
  // attached; without this check it would sit as a broken-image glyph forever.
  React.useEffect(() => {
    const img = iconRef.current;
    if (img && img.complete && img.naturalWidth === 0) advanceIcon();
  }, [iconSrc, advanceIcon]);

  /**
   * Is this entry for the page we are looking at?
   *
   * Decides fill-in-place versus open-and-sign-in. Comparing hostnames, not the
   * mere fact that the tab is a web page: the previous version treated *any*
   * http(s) tab as fillable, so picking an entry from Search while sitting on a
   * new tab tried to fill a page with no form on it, and silently did nothing.
   */
  const matchesPage = React.useMemo(() => {
    if (!pageUrl || !host) return false;
    const current = hostOf(pageUrl);
    if (!current) return false;
    return current === host || current.endsWith(`.${host}`) || host.endsWith(`.${current}`);
  }, [pageUrl, host]);

  /**
   * Sign in with this entry.
   *
   * The credential never passes through this component. The worker fetches it
   * and sends it straight to the content script, so a flaw in the popup cannot
   * reach a password.
   */
  const signIn = async (): Promise<void> => {
    if (!item.hasPassword) {
      onError('The password for this entry is hidden from you, so it cannot be filled.');
      return;
    }

    setBusy(true);

    // Already on the right site: fill here rather than opening a duplicate tab.
    const response = matchesPage
      ? await sendToBackground<{ filled: boolean }>({ type: 'FILL_ACTIVE_TAB', itemId: item.id })
      : await sendToBackground<{ filled: boolean }>({ type: 'LAUNCH_AND_FILL', itemId: item.id });

    setBusy(false);

    if (!response.ok) {
      onError(response.error);
      return;
    }

    if (!response.data.filled) {
      onError(
        matchesPage
          ? 'No sign-in form was found on this page.'
          : 'The page opened, but no sign-in form was found to fill.',
      );
      return;
    }

    // The work is done, or is happening in the new tab; either way the popup
    // has nothing left to show.
    window.close();
  };

  return (
    <li className={cn('item', isFavorite && 'item-starred')}>
      <button
        type="button"
        className="item-main"
        disabled={busy}
        onClick={() => void signIn()}
        title={
          item.hasPassword
            ? matchesPage
              ? `Fill ${item.name} on this page`
              : `Open ${host ?? item.name} and sign in`
            : 'The password for this entry is hidden from you'
        }
      >
        <span className={cn('item-mark', showIcon && 'has-icon')} aria-hidden>
          {showIcon ? (
            <img ref={iconRef} src={iconSrc} alt="" loading="lazy" onError={advanceIcon} />
          ) : (
            item.name.charAt(0).toUpperCase() || 'P'
          )}
        </span>

        <span className="item-text">
          <span className="item-name">{item.name}</span>
          <span className="item-sub">{item.username ?? host ?? item.type.replace('_', ' ')}</span>
        </span>

        <span className="item-go" aria-hidden>
          {busy ? (
            <span className="spinner" />
          ) : !item.hasPassword ? (
            <span className="item-locked">hidden</span>
          ) : matchesPage ? (
            'Fill'
          ) : (
            'Sign in'
          )}
        </span>
      </button>

      {/*
        The star sits outside the main button.
        
        Nesting a button inside a button is invalid HTML and, more practically,
        means a click on the star also triggers the sign-in - so it has to be a
        sibling.
      */}
      <button
        type="button"
        className={cn('star-btn', isFavorite && 'star-on')}
        aria-pressed={isFavorite}
        title={isFavorite ? 'Remove from favourites' : 'Add to favourites'}
        aria-label={`${isFavorite ? 'Remove' : 'Add'} ${item.name} ${isFavorite ? 'from' : 'to'} favourites`}
        onClick={(event) => {
          event.stopPropagation();
          onToggleFavorite(item.id);
        }}
      >
        {isFavorite ? '★' : '☆'}
      </button>
    </li>
  );
}

// ---------------------------------------------------------------------------
// Password generator
// ---------------------------------------------------------------------------

/**
 * Generator panel.
 *
 * Generation runs in `@passm/shared`, so the popup, the side panel, the context
 * menu and the web console all produce identically-distributed passwords.
 */
export function GeneratorPanel({
  onCopied,
  onError,
}: {
  onCopied: (message: string) => void;
  onError: (message: string) => void;
}): React.ReactElement {
  const [options, setOptions] = React.useState<PasswordGeneratorOptions>(
    DEFAULT_PASSWORD_OPTIONS,
  );
  const [password, setPassword] = React.useState('');

  const regenerate = React.useCallback((next: PasswordGeneratorOptions) => {
    try {
      setPassword(generatePassword(next));
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : 'Could not generate a password.');
      setPassword('');
    }
  }, [onError]);

  React.useEffect(() => {
    regenerate(options);
  }, [options, regenerate]);

  const bits = password ? estimatePasswordEntropy(password, options) : 0;
  const strength = passwordStrength(bits);

  const toggle = (key: keyof PasswordGeneratorOptions) => (): void => {
    setOptions((current) => ({ ...current, [key]: !current[key] }) as PasswordGeneratorOptions);
  };

  const copy = async (): Promise<void> => {
    // Routed through the worker so the generated password gets the same
    // auto-clear treatment as a stored one.
    const response = await sendToBackground<{ password: string }>({
      type: 'GENERATE_PASSWORD',
      length: options.length,
      pronounceable: options.pronounceable,
    });

    if (!response.ok) {
      onError(response.error);
      return;
    }

    try {
      await navigator.clipboard.writeText(password);
      onCopied('Password copied.');
    } catch {
      onError('Could not access the clipboard.');
    }
  };

  return (
    <div className="content" style={{ padding: 0, gap: 12 }}>
      <div className="generated">
        <code>{password || '—'}</code>
        <button type="button" className="btn-secondary" onClick={() => regenerate(options)}>
          New
        </button>
      </div>

      <div className="strength">
        <span>
          {password.length} chars &middot; ~{bits} bits
        </span>
        <span className={`strength-${strength.strength}`}>{strength.label}</span>
      </div>

      <div className="field">
        <label htmlFor="genLength">Length: {options.length}</label>
        <input
          id="genLength"
          type="range"
          min={12}
          max={64}
          value={options.length}
          onChange={(event) =>
            setOptions((current) => ({ ...current, length: Number(event.target.value) }))
          }
        />
      </div>

      <div className="options-grid">
        <Toggle id="genUpper" label="A-Z" checked={options.uppercase} onChange={toggle('uppercase')} />
        <Toggle id="genLower" label="a-z" checked={options.lowercase} onChange={toggle('lowercase')} />
        <Toggle id="genNum" label="0-9" checked={options.numbers} onChange={toggle('numbers')} />
        <Toggle id="genSym" label="Symbols" checked={options.symbols} onChange={toggle('symbols')} />
        <Toggle
          id="genAmb"
          label="Avoid look-alikes"
          checked={options.excludeAmbiguous}
          onChange={toggle('excludeAmbiguous')}
        />
        <Toggle
          id="genPron"
          label="Pronounceable"
          checked={options.pronounceable}
          onChange={toggle('pronounceable')}
        />
      </div>

      <button type="button" className="btn-primary" onClick={() => void copy()} disabled={!password}>
        Copy password
      </button>
    </div>
  );
}

function Toggle({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: () => void;
}): React.ReactElement {
  return (
    <div className="checkbox-row">
      <input id={id} type="checkbox" checked={checked} onChange={onChange} />
      <label htmlFor={id}>{label}</label>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sign-in and unlock
// ---------------------------------------------------------------------------

export function SignInForm({
  onSignedIn,
  initialError,
}: {
  onSignedIn: () => Promise<void>;
  initialError?: string | null;
}): React.ReactElement {
  const [rememberDevice, setRememberDevice] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(initialError ?? null);

  // Google's window opens from the worker. The popup usually closes when it
  // takes focus; the worker finishes regardless, and the popup opens signed in.
  const signIn = async (): Promise<void> => {
    setBusy(true);
    setError(null);

    const response = await sendToBackground({ type: 'LOGIN', rememberDevice });

    if (response.ok) {
      await onSignedIn();
    } else {
      setError(response.error);
    }

    setBusy(false);
  };

  return (
    <div className="content signin">
      <div className="signin-card">
        <div className="signin-hero">
          <img className="signin-logo" src="/icons/icon-128.png" alt="" />
          <h1 className="signin-title">Sign in to PassM</h1>
          <p className="signin-sub">Your team&apos;s passwords, filled right where you sign in.</p>
        </div>

        {error && (
          <div className="alert alert-error" role="alert">
            {error}
          </div>
        )}

        <button type="button" className="btn-google" onClick={() => void signIn()} disabled={busy}>
          {busy ? <span className="spinner" aria-hidden /> : <GoogleMark />}
          <span>{busy ? 'Waiting for Google…' : 'Continue with Google'}</span>
        </button>

        <label className="signin-remember" htmlFor="remember">
          <input
            id="remember"
            type="checkbox"
            checked={rememberDevice}
            onChange={(event) => setRememberDevice(event.target.checked)}
            disabled={busy}
          />
          <span>
            <span className="signin-remember-title">Remember this browser</span>
            <span className="signin-remember-hint">Only on a device that is yours alone.</span>
          </span>
        </label>
      </div>

      <p className="signin-note">
        <LockGlyph />
        Use your company Google account. Access is managed by your administrator.
      </p>
    </div>
  );
}

/** Google's four-colour "G", as its sign-in branding guidelines require. */
function GoogleMark(): React.ReactElement {
  return (
    <svg className="google-mark" viewBox="0 0 48 48" aria-hidden>
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  );
}

function LockGlyph(): React.ReactElement {
  return (
    <svg className="signin-note-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" strokeLinecap="round" />
    </svg>
  );
}

/** What the footer shows: the IP for a nip.io name, otherwise the host. */
function shortServerLabel(origin: string): string {
  try {
    const { hostname, port } = new URL(origin);
    const host = hostname.endsWith('.nip.io') ? hostname.slice(0, -'.nip.io'.length) : hostname;
    return port ? `${host}:${port}` : host;
  } catch {
    return origin;
  }
}

/**
 * The server address, as small plain text in the footer.
 *
 * Deliberately not inviting: no pointer cursor, no hover effect, and a single
 * click does nothing. A triple click opens a one-line editor in place, so the
 * address can be changed when the server moves but not by accident.
 *
 * The address is saved permanently on this browser until changed here again.
 * Chrome's permission for a new address is requested inside the click - it only
 * allows that from a user gesture - and the old address's is released.
 */
export function ServerAddress({ onChanged }: { onChanged?: () => void }): React.ReactElement {
  const [current, setCurrent] = React.useState<string | null>(null);
  const [editing, setEditing] = React.useState(false);
  const [value, setValue] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState<{ error: boolean; text: string } | null>(null);

  React.useEffect(() => {
    void getServerOrigin().then(setCurrent);
  }, []);

  const open = (): void => {
    setValue(current ?? '');
    setMessage(null);
    setEditing(true);
  };

  const apply = async (origin: string, granted: Promise<boolean>): Promise<void> => {
    setBusy(true);
    setMessage(null);
    try {
      if (!(await granted)) {
        setMessage({ error: true, text: 'Chrome did not allow that address. Nothing changed.' });
        return;
      }

      const previous = current;
      await setServerOrigin(origin);
      setCurrent(origin);

      // Release the address no longer in use - but never the build's own.
      if (previous && previous !== origin && previous !== DEFAULT_SERVER_ORIGIN) {
        await chrome.permissions.remove({ origins: [originPattern(previous)] }).catch(() => false);
      }

      await sendToBackground({ type: 'SERVER_CHANGED' });
      onChanged?.();

      if (await checkServer(origin)) {
        setEditing(false);
      } else {
        setMessage({ error: true, text: 'Saved, but no PassM server answers there.' });
      }
    } finally {
      setBusy(false);
    }
  };

  const save = (): void => {
    const parsed = parseServerAddress(value);
    if ('error' in parsed) {
      setMessage({ error: true, text: parsed.error });
      return;
    }
    if (parsed.origin === current) {
      setEditing(false);
      return;
    }
    // Requested before anything is awaited: Chrome only shows the permission
    // prompt while the click is still being handled.
    const granted = chrome.permissions.request({ origins: [originPattern(parsed.origin)] });
    void apply(parsed.origin, granted);
  };

  if (!editing) {
    return (
      <span
        className="server-label"
        title={current ?? undefined}
        // `detail` is the browser's own consecutive-click count.
        onClick={(event) => {
          if (event.detail === 3) open();
        }}
      >
        {current ? shortServerLabel(current) : '…'}
      </span>
    );
  }

  return (
    <div className="server-edit">
      <input
        type="text"
        inputMode="url"
        aria-label="PassM server address"
        autoComplete="off"
        spellCheck={false}
        placeholder="192.168.0.211.nip.io:1225"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Enter') save();
          if (event.key === 'Escape') setEditing(false);
        }}
        disabled={busy}
        autoFocus
      />
      <button type="button" className="btn-link" onClick={save} disabled={busy}>
        {busy ? '…' : 'Save'}
      </button>
      {current !== DEFAULT_SERVER_ORIGIN && (
        <button
          type="button"
          className="btn-link"
          title={`Back to ${DEFAULT_SERVER_ORIGIN}`}
          onClick={() => void apply(DEFAULT_SERVER_ORIGIN, Promise.resolve(true))}
          disabled={busy}
        >
          Default
        </button>
      )}
      <button type="button" className="btn-link" onClick={() => setEditing(false)} disabled={busy}>
        Cancel
      </button>
      {message && (
        <span className={message.error ? 'server-msg server-msg-error' : 'server-msg'} role="status">
          {message.text}
        </span>
      )}
    </div>
  );
}

export function UnlockForm({
  onUnlocked,
}: {
  onUnlocked: () => Promise<void>;
}): React.ReactElement {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  // The list normally loads straight after sign-in; this is the retry after a
  // failure - the server unreachable, say.
  const open = async (): Promise<void> => {
    setBusy(true);
    setError(null);

    const response = await sendToBackground({ type: 'VAULT_UNLOCK' });

    if (response.ok) {
      await onUnlocked();
    } else {
      setError(response.error);
    }

    setBusy(false);
  };

  return (
    <div className="content">
      <p className="section-title">Vault not open</p>

      <p className="hint">Your passwords did not load when you signed in. Try again.</p>

      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}

      <button type="button" className="btn-primary" onClick={() => void open()} disabled={busy}>
        {busy ? 'Opening...' : 'Open vault'}
      </button>
    </div>
  );
}

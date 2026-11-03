/**
 * Side panel: the full vault browser.
 *
 * Differs from the popup in what it is for. The popup answers "give me the
 * credential for this page" and closes; the panel stays open beside the page
 * while the user works - so it keeps a persistent search, groups by type, and
 * carries the settings that the popup has no room for.
 *
 * Like the popup, it holds no tokens and no passwords.
 */

import * as React from 'react';

import { VAULT_ITEM_TYPE_LABEL, VAULT_ITEM_TYPES, type VaultItemType } from '@passm/shared';

import {
  sendToBackground,
  type AuthStatePayload,
  type SearchResultPayload,
  type VaultStatePayload,
} from '../lib/messages';
import { DEFAULT_SETTINGS, readSettings, writeSettings, type ExtensionSettings } from '../lib/settings';
import type { VaultIndexEntry } from '../lib/storage';
import {
  GeneratorPanel,
  ItemList,
  ServerAddress,
  SignInForm,
  UnlockForm,
} from '../ui/components';
import '../ui/styles.css';

type Panel = 'vault' | 'generate' | 'settings';

export function App(): React.ReactElement {
  const [auth, setAuth] = React.useState<AuthStatePayload | null>(null);
  const [vault, setVault] = React.useState<VaultStatePayload | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    const authResponse = await sendToBackground<AuthStatePayload>({ type: 'AUTH_STATE' });
    if (authResponse.ok) setAuth(authResponse.data);

    const vaultResponse = await sendToBackground<VaultStatePayload>({ type: 'VAULT_STATE' });
    if (vaultResponse.ok) setVault(vaultResponse.data);

    setLoading(false);
  }, []);

  React.useEffect(() => {
    void refresh();

    // The panel stays open across navigations and auto-locks, so it polls for
    // state rather than assuming what it read on mount still holds.
    const timer = setInterval(() => void refresh(), 20_000);
    return () => clearInterval(timer);
  }, [refresh]);

  React.useEffect(() => {
    if (!notice) return undefined;
    const timer = setTimeout(() => setNotice(null), 3500);
    return () => clearTimeout(timer);
  }, [notice]);

  // Bumped after each refresh-from-server; the vault list watches it so a new
  // item appears without the search text having to change.
  const [syncTick, setSyncTick] = React.useState(0);
  const [syncing, setSyncing] = React.useState(false);

  const syncNow = async (): Promise<void> => {
    if (syncing) return;
    setSyncing(true);
    const response = await sendToBackground({ type: 'VAULT_SYNC' });
    setSyncing(false);

    if (!response.ok) {
      setError(response.error);
      return;
    }
    setNotice('Up to date.');
    setSyncTick((current) => current + 1);
    await refresh();
  };

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <img className="brand-mark" src="/icons/icon-48.png" alt="" />
          <span>PassM Vault</span>
        </div>

        <div className="header-side">
          {vault?.state === 'unlocked' && (
            <button
              type="button"
              className="icon-btn"
              title="Refresh - pull the latest passwords from the server"
              aria-label="Refresh from the server"
              disabled={syncing}
              onClick={() => void syncNow()}
            >
              <svg
                className={syncing ? 'spin' : undefined}
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden
              >
                <path d="M21 12a9 9 0 1 1-2.64-6.36" />
                <path d="M21 3v6h-6" />
              </svg>
            </button>
          )}

          {vault?.state === 'unlocked' && (
            <button
              type="button"
              className="btn-link"
              onClick={() => void sendToBackground({ type: 'VAULT_LOCK' }).then(refresh)}
            >
              Lock
            </button>
          )}
        </div>
      </header>

      {loading ? (
        <div className="loading">Loading your vault...</div>
      ) : !auth?.authenticated ? (
        <SignInForm onSignedIn={refresh} initialError={auth?.signedOutReason} />
      ) : vault?.state !== 'unlocked' ? (
        <UnlockForm onUnlocked={refresh} />
      ) : (
        <UnlockedPanel
          vault={vault}
          syncTick={syncTick}
          notice={notice}
          error={error}
          onNotice={setNotice}
          onError={setError}
          onRefresh={refresh}
        />
      )}

      <footer className="footer">
        <ServerAddress onChanged={() => void refresh()} />
      </footer>
    </div>
  );
}

function UnlockedPanel({
  vault,
  syncTick,
  notice,
  error,
  onNotice,
  onError,
  onRefresh,
}: {
  /** Bumped by the header's refresh button; the vault list watches it. */
  syncTick: number;
  vault: VaultStatePayload;
  notice: string | null;
  error: string | null;
  onNotice: (message: string) => void;
  onError: (message: string) => void;
  onRefresh: () => Promise<void>;
}): React.ReactElement {
  const [panel, setPanel] = React.useState<Panel>('vault');
  const [query, setQuery] = React.useState('');
  const [typeFilter, setTypeFilter] = React.useState<VaultItemType | 'all'>('all');
  const [favoritesOnly, setFavoritesOnly] = React.useState(false);
  const [items, setItems] = React.useState<VaultIndexEntry[]>([]);

  // The worker holds the whole index, so the panel pulls it once and filters
  // locally - the same trade the console makes, for the same reason.
  React.useEffect(() => {
    if (panel !== 'vault') return undefined;

    const timer = setTimeout(() => {
      void (async () => {
        const response = await sendToBackground<SearchResultPayload>({
          type: 'VAULT_SEARCH',
          query,
          limit: 300,
        });
        if (response.ok) setItems(response.data.items);
      })();
    }, 120);

    return () => clearTimeout(timer);
  }, [panel, query, syncTick]);

  const visible = items.filter((item) => {
    if (favoritesOnly && !item.favorite) return false;
    if (typeFilter !== 'all' && item.type !== typeFilter) return false;
    return true;
  });


  return (
    <>
      <nav className="tabs" role="tablist">
        {(
          [
            ['vault', 'Vault'],
            ['generate', 'Generate'],
            ['settings', 'Settings'],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            className="tab"
            aria-selected={panel === key}
            onClick={() => setPanel(key)}
          >
            {label}
          </button>
        ))}
      </nav>

      <div className="content">
        {error && (
          <div className="alert alert-error" role="alert">
            {error}
          </div>
        )}
        {notice && (
          <div className="alert alert-success" role="status">
            {notice}
          </div>
        )}

        {panel === 'vault' && (
          <>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search your vault"
              aria-label="Search your vault"
            />

            <div className="strength">
              <select
                value={typeFilter}
                onChange={(event) => setTypeFilter(event.target.value as VaultItemType | 'all')}
                aria-label="Filter by type"
                style={{
                  background: 'var(--bg)',
                  color: 'inherit',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '4px 6px',
                  fontSize: 12,
                }}
              >
                <option value="all">All types</option>
                {VAULT_ITEM_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {VAULT_ITEM_TYPE_LABEL[type]}
                  </option>
                ))}
              </select>

              <label className="checkbox-row" style={{ margin: 0 }}>
                <input
                  type="checkbox"
                  checked={favoritesOnly}
                  onChange={(event) => setFavoritesOnly(event.target.checked)}
                />
                <span>Favourites only</span>
              </label>
            </div>

            <ItemList
              items={visible}
              emptyMessage={query ? 'Nothing matches that search.' : 'Your vault is empty.'}
          pageUrl={null}
              onCopied={onNotice}
              onError={onError}
            />

            <div className="strength" style={{ paddingTop: 4 }}>
              <span>
                {visible.length} of {vault.itemCount} items
              </span>
            </div>
          </>
        )}

        {panel === 'generate' && <GeneratorPanel onCopied={onNotice} onError={onError} />}

        {panel === 'settings' && <SettingsPanel onSaved={() => onNotice('Settings saved.')} />}
      </div>
    </>
  );
}

/** Behaviour settings. The panel is the only surface with room for these. */
function SettingsPanel({ onSaved }: { onSaved: () => void }): React.ReactElement {
  const [settings, setSettings] = React.useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    void (async () => {
      setSettings(await readSettings());
      setLoaded(true);
    })();
  }, []);

  const update = async (patch: Partial<ExtensionSettings>): Promise<void> => {
    const next = await writeSettings(patch);
    setSettings(next);
    onSaved();
  };

  if (!loaded) return <div className="loading">Loading settings...</div>;

  return (
    <div className="content" style={{ padding: 0, gap: 14 }}>
      <div className="field">
        <label htmlFor="clipboardClear">
          Clear clipboard after: {settings.clipboardClearSeconds === 0 ? 'never' : `${settings.clipboardClearSeconds}s`}
        </label>
        <input
          id="clipboardClear"
          type="range"
          min={0}
          max={300}
          step={5}
          value={settings.clipboardClearSeconds}
          onChange={(event) => void update({ clipboardClearSeconds: Number(event.target.value) })}
        />
        <p style={{ margin: 0, fontSize: 11, color: 'var(--muted)' }}>
          Any application on this machine can read the clipboard, and some platforms sync it
          between devices. Setting this to never leaves copied passwords there indefinitely.
        </p>
      </div>

      <Setting
        id="inlineButton"
        label="Show the PassM button in login fields"
        checked={settings.showInlineButton}
        onChange={(value) => void update({ showInlineButton: value })}
      />
    </div>
  );
}

function Setting({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}): React.ReactElement {
  return (
    <div className="checkbox-row">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      <label htmlFor={id}>{label}</label>
    </div>
  );
}

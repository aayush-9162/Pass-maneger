/**
 * Popup: the quick-access surface.
 *
 * Optimised for the common case - the user is on a site and wants the credential
 * for it - so matches for the current tab appear first, with search, favourites,
 * recents and the generator behind tabs.
 *
 * Holds no tokens and no passwords: every operation is a message to the service
 * worker, which is torn down and rebuilt independently of this window.
 */

import * as React from 'react';

import {
  sendToBackground,
  type AuthStatePayload,
  type SearchResultPayload,
  type SuggestionsPayload,
  type VaultStatePayload,
} from '../lib/messages';
import type { VaultIndexEntry } from '../lib/storage';
import { GeneratorPanel, ItemList, ServerAddress, SignInForm, UnlockForm } from '../ui/components';
import '../ui/styles.css';

type Tab = 'this-site' | 'items' | 'favorites' | 'recent' | 'generate';

export function App(): React.ReactElement {
  const [auth, setAuth] = React.useState<AuthStatePayload | null>(null);
  const [vault, setVault] = React.useState<VaultStatePayload | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  /**
   * True when this very page is running as a full browser tab rather than the
   * 420px popup. Same HTML, same code - `?view=full` swaps the body class
   * before render (see main.tsx), and this just reads the result.
   */
  const [fullView] = React.useState(() => document.body.classList.contains('fullview'));

  const openFullView = (): void => {
    void chrome.tabs.create({ url: chrome.runtime.getURL('popup.html?view=full') });
    window.close();
  };

  /**
   * Bumped after every refresh-from-server, and watched by every list in the
   * unlocked view. Without it a sync updated the index and the item count but
   * no list re-read the index until the tab or search text changed.
   */
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

  const refresh = React.useCallback(async () => {
    const authResponse = await sendToBackground<AuthStatePayload>({ type: 'AUTH_STATE' });
    if (authResponse.ok) setAuth(authResponse.data);

    const vaultResponse = await sendToBackground<VaultStatePayload>({ type: 'VAULT_STATE' });
    if (vaultResponse.ok) setVault(vaultResponse.data);

    setLoading(false);
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  // Feedback is transient: the popup is small, and a stale banner crowds out the
  // list the user came here for.
  React.useEffect(() => {
    if (!notice) return undefined;
    const timer = setTimeout(() => setNotice(null), 3500);
    return () => clearTimeout(timer);
  }, [notice]);

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <img className="brand-mark" src="/icons/icon-48.png" alt="" />
          <span>PassM</span>
        </div>

        <div className="header-side">
          {auth?.authenticated && auth.user && (
            <div className="identity">
              <strong>{auth.user.fullName}</strong>
              <span title={auth.user.email}>{auth.user.email}</span>
            </div>
          )}
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
          {!fullView && (
            <button
              type="button"
              className="icon-btn expand-btn"
              title="Open in a full tab"
              aria-label="Open in a full tab"
              onClick={openFullView}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                <path d="M15 3h6v6" />
                <path d="M9 21H3v-6" />
                <path d="M21 3l-7 7" />
                <path d="M3 21l7-7" />
              </svg>
            </button>
          )}
        </div>
      </header>

      {loading ? (
        <div className="loading">Checking your session...</div>
      ) : !auth?.authenticated ? (
        <SignInForm onSignedIn={refresh} />
      ) : vault?.state !== 'unlocked' ? (
        <UnlockForm onUnlocked={refresh} />
      ) : (
        <UnlockedView
          vault={vault}
          fullView={fullView}
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
        {vault?.state === 'unlocked' && (
          <button
            type="button"
            className="btn-link"
            onClick={() => void sendToBackground({ type: 'VAULT_LOCK' }).then(refresh)}
          >
            Lock vault
          </button>
        )}
      </footer>
    </div>
  );
}

function UnlockedView({
  vault,
  fullView,
  syncTick,
  notice,
  error,
  onNotice,
  onError,
  onRefresh,
}: {
  vault: VaultStatePayload;
  fullView: boolean;
  /** Bumped by the header's refresh button; every list below watches it. */
  syncTick: number;
  notice: string | null;
  error: string | null;
  onNotice: (message: string) => void;
  onError: (message: string) => void;
  onRefresh: () => Promise<void>;
}): React.ReactElement {
  // In a full tab, "this site" would mean the extension page itself - useless -
  // so the tab is hidden and the view opens on the full item list.
  const [tab, setTab] = React.useState<Tab>(fullView ? 'items' : 'this-site');

  /**
   * Item ids starred on this device.
   *
   * Held here rather than derived from `item.favorite`, which is the server's
   * flag: starring is a per-device shortcut that needs no permission and leaves
   * no trace in the audit trail. See `lib/favorites`.
   */
  const [favorites, setFavorites] = React.useState<Set<string>>(new Set());

  React.useEffect(() => {
    void (async () => {
      const response = await sendToBackground<{ ids: string[] }>({ type: 'GET_FAVORITES' });
      if (response.ok) setFavorites(new Set(response.data.ids));
    })();
  }, []);

  const toggleFavorite = async (itemId: string): Promise<void> => {
    // Optimistic: the star responds instantly, and the write is local so it
    // effectively cannot fail in a way worth blocking the interface for.
    setFavorites((current) => {
      const next = new Set(current);
      if (next.has(itemId)) next.delete(itemId);
      else next.add(itemId);
      return next;
    });

    const response = await sendToBackground<{ favorite: boolean }>({
      type: 'TOGGLE_FAVORITE',
      itemId,
    });

    if (!response.ok) {
      // Put it back the way it was.
      setFavorites((current) => {
        const next = new Set(current);
        if (next.has(itemId)) next.delete(itemId);
        else next.add(itemId);
        return next;
      });
      onError(response.error);
      return;
    }

    // Refresh the Favourites tab if it is what we are looking at.
    if (tab === 'favorites') void loadList();
  };
  const [query, setQuery] = React.useState('');
  const [results, setResults] = React.useState<VaultIndexEntry[]>([]);
  const [siteMatches, setSiteMatches] = React.useState<VaultIndexEntry[]>([]);
  const [pageUrl, setPageUrl] = React.useState<string | null>(null);

  // Matches for the active tab, resolved once when the popup opens.
  React.useEffect(() => {
    if (fullView) return;

    void (async () => {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab?.url) return;

      setPageUrl(activeTab.url);

      const response = await sendToBackground<SuggestionsPayload>({
        type: 'PAGE_SUGGESTIONS',
        url: activeTab.url,
      });

      if (!response.ok) return;

      // Suggestions carry no `hasPassword`/`tags`, so they are re-hydrated from
      // the index by searching for each id.
      const search = await sendToBackground<SearchResultPayload>({
        type: 'VAULT_SEARCH',
        query: '',
        limit: 500,
      });

      if (!search.ok) return;

      const byId = new Map(search.data.items.map((item) => [item.id, item]));
      setSiteMatches(
        response.data.suggestions
          .map((suggestion) => byId.get(suggestion.itemId))
          .filter((item): item is VaultIndexEntry => item !== undefined),
      );

      // Land on the tab that is actually useful: if nothing matches this site,
      // going straight to the full list saves a click.
      if (response.data.suggestions.length === 0) setTab('items');
    })();
  }, [fullView, syncTick]);

  /*
   * The Items tab: everything, filtered as you type.
   *
   * An empty query shows the whole vault rather than a "start typing" void -
   * the list is what people open the tab for, and the search box narrows it.
   */
  React.useEffect(() => {
    if (tab !== 'items') return undefined;

    const timer = setTimeout(() => {
      void (async () => {
        const response = await sendToBackground<SearchResultPayload>({
          type: 'VAULT_SEARCH',
          query,
          limit: query ? 50 : 500,
        });
        if (response.ok) setResults(response.data.items);
      })();
    }, 120);

    return () => clearTimeout(timer);
  }, [tab, query, syncTick]);

  // Favourites and recents come straight from the index.
  const loadList = React.useCallback(async (): Promise<void> => {
    if (tab !== 'favorites' && tab !== 'recent') return;

    const response = await sendToBackground<SearchResultPayload>({
      type: tab === 'favorites' ? 'VAULT_FAVORITES' : 'VAULT_RECENT',
      limit: 30,
    });
    if (response.ok) setResults(response.data.items);
  }, [tab, syncTick]);

  React.useEffect(() => {
    void loadList();
  }, [loadList]);


  return (
    <>
      <nav className="tabs" role="tablist">
        {(
          [
            ...(fullView ? [] : ([['this-site', 'This site']] as [Tab, string][])),
            ['items', 'Items'],
            ['favorites', 'Favourites'],
            ['recent', 'Recent'],
            ['generate', 'Generate'],
          ] as [Tab, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            className="tab"
            aria-selected={tab === key}
            onClick={() => setTab(key)}
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

        {tab === 'this-site' && (
          <ItemList
            items={siteMatches}
            emptyMessage="No saved logins match this site."
            pageUrl={pageUrl}
            favorites={favorites}
            onToggleFavorite={(id) => void toggleFavorite(id)}
            onCopied={onNotice}
            onError={onError}
          />
        )}

        {tab === 'items' && (
          <>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by name, username or website"
              aria-label="Search your passwords"
              autoFocus
            />
            <ItemList
              items={results}
              emptyMessage={
                query
                  ? 'Nothing matches that search.'
                  : 'No passwords have been shared with you yet.'
              }
              pageUrl={pageUrl}
              favorites={favorites}
              onToggleFavorite={(id) => void toggleFavorite(id)}
              onCopied={onNotice}
              onError={onError}
            />
          </>
        )}

        {(tab === 'favorites' || tab === 'recent') && (
          <ItemList
            items={results}
            emptyMessage={
              tab === 'favorites'
                ? 'No favourites yet. Star an item in the web console.'
                : 'Nothing here yet.'
            }
            pageUrl={pageUrl}
            favorites={favorites}
            onToggleFavorite={(id) => void toggleFavorite(id)}
            onCopied={onNotice}
            onError={onError}
          />
        )}

        {tab === 'generate' && <GeneratorPanel onCopied={onNotice} onError={onError} />}

        {tab !== 'generate' && (
          <div className="strength" style={{ paddingTop: 4 }}>
            <span>{vault.itemCount} items unlocked</span>
          </div>
        )}
      </div>
    </>
  );
}

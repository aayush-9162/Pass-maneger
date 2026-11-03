/**
 * Passwords - the one screen where credentials live.
 *
 * ## The model, as the user sees it
 *
 * There are passwords, and there are groups of passwords. A password either
 * sits in a group or stands alone ("Individual"). People are given access to a
 * group, or to a single password, from the People page - never from here.
 *
 * ## The model, as the code sees it
 *
 * Every password lives in a shared vault. A "group" is a vault of
 * `kind: 'group'`; an individual password is a vault of `kind: 'item'` that
 * wraps exactly one item. The wrapper is invisible - the UI never says "vault" -
 * but it is what makes sharing one password the same grant as sharing a group,
 * with no second code path. The server creates and removes wrappers itself.
 *
 * The listing carries names, usernames and sites only. A password is fetched
 * from the server one at a time, when someone reveals or copies it, and the
 * server records that in the audit trail.
 */

import {
  Check,
  ChevronRight,
  Copy,
  Eye,
  EyeOff,
  FolderInput,
  FolderPlus,
  KeyRound,
  Loader2,
  Lock,
  Pencil,
  Plus,
  ShieldAlert,
  Trash2,
  UsersRound,
} from 'lucide-react';
import * as React from 'react';

import {
  PERMISSIONS,
  ROLES,
  SECRET_PURPOSE,
  VAULT_ITEM_TYPE,
  VAULT_KIND,
  VAULT_ROLE,
  canRevealStoredPassword,
  type MemberSharedVault,
  type SecretPurpose,
  type SharedItemData,
} from '@passm/shared';

import { ConfirmDialog, Feedback, PageHeader, messageOf } from '@/components/admin/admin-kit';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { API_BASE_URL, api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { copyWithAutoClear } from '@/lib/clipboard';
import { useSecurityPolicy } from '@/lib/security-policy-context';
import { cn } from '@/lib/utils';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One row of the flat list: a password, wherever it lives. */
interface Row {
  itemId: string;
  vaultId: string;
  /** `item` = an individual password (its vault is the invisible wrapper). */
  kind: 'group' | 'item';
  groupName: string | null;
  name: string;
  username: string;
  uri: string;
  /** Everything stored beside the password, kept whole so an edit preserves it. */
  data: SharedItemData;
  /** Present only after an explicit reveal. */
  password: string | null;
  revision: number;
  /** False when the server will not release this password to the caller. */
  canReadSecret: boolean;
}

// ---------------------------------------------------------------------------
// Site logos
// ---------------------------------------------------------------------------

function hostOf(value: string): string | null {
  if (!value.trim()) return null;
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
 * First our own icon relay, which turns the icon services' fake-success
 * placeholder answers into honest 404s an `<img>` reliably errors on; then
 * the site's own /favicon.ico. Only when both fail does the tile fall back to
 * the lettered gradient. Public icon services are never addressed directly:
 * browsers render their placeholder bodies even under a 404 status, which is
 * how every entry once wore the same grey globe.
 */
function faviconCandidates(host: string): string[] {
  return [
    // `v=2` busts day-long browser caches of responses served before the
    // relay's embed policy was corrected - those cached copies carry the old
    // blocking header and would keep failing until the cache expired.
    `${API_BASE_URL}/icons/${encodeURIComponent(host)}?v=2`,
    `https://${host}/favicon.ico`,
  ];
}

/**
 * The site's logo beside each password, fetched live at render time.
 *
 * Deliberately not stored anywhere - the browser asks as the row renders,
 * disclosing only the hostname. Offline, or for an internal host with no
 * public icon, every candidate errors and the tile falls back to the entry's
 * initial on the product gradient.
 */
function SiteIcon({ name, uri }: { name: string; uri: string }): React.ReactElement {
  const host = React.useMemo(() => hostOf(uri), [uri]);

  const [iconIndex, setIconIndex] = React.useState(0);
  React.useEffect(() => setIconIndex(0), [host]);

  const candidates = host ? faviconCandidates(host) : [];
  const iconSrc = candidates[iconIndex] ?? null;

  const imgRef = React.useRef<HTMLImageElement | null>(null);
  const advance = React.useCallback(() => setIconIndex((current) => current + 1), []);

  /*
   * Catch errors that fired before React was listening. The page is
   * server-rendered, so the browser can fetch (and fail) the image while the
   * markup is still hydrating - the error event lands before onError is
   * attached, and the tile would freeze as a broken-image glyph. A mounted
   * image that reports "complete" with zero pixels is that missed failure.
   */
  React.useEffect(() => {
    const img = imgRef.current;
    if (img && img.complete && img.naturalWidth === 0) advance();
  }, [iconSrc, advance]);

  if (iconSrc) {
    return (
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border bg-secondary/50">
        <img
          ref={imgRef}
          src={iconSrc}
          alt=""
          loading="lazy"
          className="size-5 rounded"
          onError={advance}
        />
      </span>
    );
  }

  return (
    <span
      className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-violet-500 text-sm font-bold text-white"
      aria-hidden
    >
      {name.charAt(0).toUpperCase() || 'P'}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function PasswordsPage(): React.ReactElement {
  const { policy } = useSecurityPolicy();
  const { user } = useAuth();

  const mayRevealStored = canRevealStoredPassword(
    user?.role ?? ROLES.EMPLOYEE,
    policy.restrictPasswordAccessToAdmins,
  );

  const [vaults, setVaults] = React.useState<MemberSharedVault[] | null>(null);
  const [rows, setRows] = React.useState<Row[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);

  const [search, setSearch] = React.useState('');

  /**
   * Which sections are unfolded. Everything opens on the first load - a fresh
   * page with all its rows hidden behind chevrons would just be a puzzle - and
   * from there the chevrons remember what the user folded away.
   */
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());
  const expandInitialized = React.useRef(false);
  const knownGroupIds = React.useRef<Set<string>>(new Set());

  const [revealed, setRevealed] = React.useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = React.useState<string | null>(null);

  /** null = dialog closed; '' = new Individual password; otherwise a group id. */
  const [createIn, setCreateIn] = React.useState<string | null>(null);
  const [creatingGroup, setCreatingGroup] = React.useState(false);
  const [editing, setEditing] = React.useState<Row | null>(null);
  const [moving, setMoving] = React.useState<Row | null>(null);
  const [deleting, setDeleting] = React.useState<Row | null>(null);
  const [renamingGroup, setRenamingGroup] = React.useState<MemberSharedVault | null>(null);
  const [deletingGroup, setDeletingGroup] = React.useState<MemberSharedVault | null>(null);

  /**
   * Load everything: every vault the caller holds a grant on, and its items.
   *
   * The page presents one flat list, and for an internal deployment that is
   * tens to hundreds of entries - one listing call per vault. Passwords are
   * not part of it.
   */
  const load = React.useCallback(async (): Promise<void> => {
    setError(null);

    try {
      const { vaults: list } = await api.listMySharedVaults();
      setVaults(list);

      const collected: Row[] = [];
      const failures: string[] = [];

      for (const vault of list) {
        try {
          const result = await api.listSharedItems(vault.id, { pageSize: 100 });
          for (const item of result.items) {
            collected.push({
              itemId: item.id,
              vaultId: vault.id,
              kind: vault.kind === VAULT_KIND.ITEM ? 'item' : 'group',
              groupName: vault.kind === VAULT_KIND.ITEM ? null : vault.name,
              name: item.data.name,
              username: item.data.username ?? '',
              uri: item.data.uris?.[0] ?? '',
              data: item.data,
              password: null,
              revision: item.revision,
              canReadSecret: vault.canReadSecrets && item.hasSecret,
            });
          }
        } catch (caught) {
          // One failing entry must not blank the rest - but it must not be
          // silent either.
          failures.push(`${vault.name}: ${messageOf(caught, 'could not be loaded')}`);
        }
      }

      if (failures.length > 0) {
        setError(
          `${failures.length === 1 ? 'One entry' : `${failures.length} entries`} could not be loaded - ${failures.join('; ')}`,
        );
      }

      collected.sort((a, b) => a.name.localeCompare(b.name));
      setRows(collected);

      const groupIds = list
        .filter((vault) => vault.kind === VAULT_KIND.GROUP)
        .map((vault) => vault.id);

      if (!expandInitialized.current) {
        expandInitialized.current = true;
        setExpanded(new Set(['individual', ...groupIds]));
      } else {
        // A group created a moment ago must not appear folded shut - the very
        // next thing the user does is put a password in it and look for it.
        const fresh = groupIds.filter((id) => !knownGroupIds.current.has(id));
        if (fresh.length > 0) {
          setExpanded((current) => new Set([...current, ...fresh]));
        }
      }
      knownGroupIds.current = new Set(groupIds);
    } catch (caught) {
      setError(messageOf(caught, 'Could not load your passwords.'));
      setRows([]);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  // -- derived ---------------------------------------------------------------

  const groups = (vaults ?? []).filter((vault) => vault.kind === VAULT_KIND.GROUP);

  const query = search.trim().toLowerCase();
  const matches = (row: Row): boolean =>
    !query ||
    row.name.toLowerCase().includes(query) ||
    row.username.toLowerCase().includes(query) ||
    row.uri.toLowerCase().includes(query);

  const individualRows = (rows ?? []).filter((row) => row.kind === 'item' && matches(row));
  const rowsFor = (vaultId: string): Row[] =>
    (rows ?? []).filter((row) => row.vaultId === vaultId && matches(row));

  // While searching every section is forced open - a hit hidden behind a
  // folded chevron is indistinguishable from no hit at all.
  const isOpen = (id: string): boolean => (query ? true : expanded.has(id));
  const toggleOpen = (id: string): void => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // -- per-row actions -------------------------------------------------------

  /** Fetch one password from the server, which records why it was asked for. */
  const reveal = async (row: Row, purpose: SecretPurpose): Promise<string | null> => {
    if (!mayRevealStored) {
      void api.reportAccessEvents([
        { sharedVaultId: row.vaultId, itemId: row.itemId, action: 'reveal_blocked', field: 'password' },
      ]);
      setError(
        'Only an administrator can see or copy a stored password. Use the browser extension to fill it into the site.',
      );
      return null;
    }

    try {
      const secret = await api.getSharedItemSecret(row.vaultId, row.itemId, purpose);
      const password = secret.password ?? '';

      setRows((current) =>
        (current ?? []).map((candidate) =>
          candidate.itemId === row.itemId ? { ...candidate, password } : candidate,
        ),
      );
      return password;
    } catch (caught) {
      setError(messageOf(caught, 'That password could not be fetched.'));
      return null;
    }
  };

  const toggleReveal = async (row: Row): Promise<void> => {
    if (revealed.has(row.itemId)) {
      setRevealed((current) => {
        const next = new Set(current);
        next.delete(row.itemId);
        return next;
      });
      return;
    }
    const password = row.password ?? (await reveal(row, SECRET_PURPOSE.VIEW));
    if (password === null) return;
    setRevealed((current) => new Set(current).add(row.itemId));
  };

  /** Always fetched afresh, so every copy is in the audit trail as a copy. */
  const copyPassword = async (row: Row): Promise<void> => {
    const password = await reveal(row, SECRET_PURPOSE.COPY);
    if (password === null) return;

    if (await copyWithAutoClear(password, policy.clipboardClearSeconds)) {
      setCopiedId(row.itemId);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  /** The server removes an individual password's wrapper along with it. */
  const removeRow = async (row: Row): Promise<void> => {
    await api.deleteSharedItem(row.vaultId, row.itemId);
    setNotice(`Deleted "${row.name}".`);
    await load();
  };

  // -- render ----------------------------------------------------------------

  /** One password row: site logo, name, username · site, then the actions. */
  const renderRow = (row: Row): React.ReactElement => (
    <div key={row.itemId} className="flex flex-wrap items-center gap-3 px-3 py-2.5">
      <SiteIcon name={row.name} uri={row.uri} />
      <div className="min-w-0 flex-1">
        <p className="truncate font-medium">{row.name}</p>
        <p className="truncate text-sm text-muted-foreground">
          {row.username || '—'}
          {row.uri ? ` · ${row.uri}` : ''}
        </p>
        {revealed.has(row.itemId) && row.password && (
          <code className="mt-1 block break-all rounded bg-secondary px-2 py-1 font-mono text-xs">
            {row.password}
          </code>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1">
        {!mayRevealStored ? (
          <span
            title="Only an administrator can see or copy a stored password."
            className="flex items-center gap-1 rounded-full bg-secondary px-2 py-0.5 text-[11px] text-muted-foreground"
          >
            <Lock className="size-3" aria-hidden />
            fill only
          </span>
        ) : row.canReadSecret ? (
          <>
            <Button
              variant="ghost"
              size="icon"
              title={revealed.has(row.itemId) ? 'Hide password' : 'Show password'}
              onClick={() => void toggleReveal(row)}
            >
              {revealed.has(row.itemId) ? (
                <EyeOff className="size-4" aria-hidden />
              ) : (
                <Eye className="size-4" aria-hidden />
              )}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              title="Copy password"
              onClick={() => void copyPassword(row)}
            >
              {copiedId === row.itemId ? (
                <Check className="size-4 text-success" aria-hidden />
              ) : (
                <Copy className="size-4" aria-hidden />
              )}
            </Button>
          </>
        ) : (
          <span
            title="Passwords in this group are hidden from you."
            className="rounded-full bg-secondary px-2 py-0.5 text-[11px] text-muted-foreground"
          >
            hidden
          </span>
        )}

        <Button
          variant="ghost"
          size="icon"
          title={`Edit ${row.name}`}
          onClick={() => setEditing(row)}
        >
          <Pencil className="size-4" aria-hidden />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          title={`Move ${row.name} to another group`}
          onClick={() => setMoving(row)}
        >
          <FolderInput className="size-4" aria-hidden />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          title={`Delete ${row.name}`}
          onClick={() => setDeleting(row)}
        >
          <Trash2 className="size-4" aria-hidden />
        </Button>
      </div>
    </div>
  );

  /**
   * One section: a header row with a chevron, then the passwords inside it
   * once unfolded. Used for every group and for "Individual".
   */
  const renderSection = (options: {
    id: string;
    title: string;
    icon: React.ReactNode;
    count: number;
    subtitle?: string;
    actions?: React.ReactNode;
    sectionRows: Row[];
    emptyText: string;
  }): React.ReactElement => {
    const open = isOpen(options.id);

    return (
      <div key={options.id} className="overflow-hidden rounded-lg border bg-card">
        <div className="flex items-center gap-2 px-2 py-1.5">
          <button
            type="button"
            onClick={() => toggleOpen(options.id)}
            aria-expanded={open}
            className="flex min-w-0 flex-1 items-center gap-2.5 rounded-md px-1.5 py-1.5 text-left hover:bg-secondary/60"
          >
            <ChevronRight
              className={cn('size-4 shrink-0 text-muted-foreground transition-transform', open && 'rotate-90')}
              aria-hidden
            />
            {options.icon}
            <span className="truncate font-semibold">{options.title}</span>
            <span className="shrink-0 rounded-full bg-secondary px-2 py-0.5 text-xs tabular-nums text-secondary-foreground">
              {options.count}
            </span>
            {options.subtitle && (
              <span className="hidden truncate text-sm text-muted-foreground sm:inline">
                {options.subtitle}
              </span>
            )}
          </button>
          <div className="flex shrink-0 items-center gap-0.5">{options.actions}</div>
        </div>

        {open && (
          <div className="divide-y border-t">
            {options.sectionRows.length === 0 ? (
              <p className="px-4 py-4 text-sm text-muted-foreground">{options.emptyText}</p>
            ) : (
              options.sectionRows.map(renderRow)
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Passwords"
        description="Every password in one place. Put them in groups, or keep them individual - then give people access from the People page."
        actions={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setCreatingGroup(true)}>
              <FolderPlus aria-hidden />
              New group
            </Button>
            <Button onClick={() => setCreateIn('')}>
              <Plus aria-hidden />
              New password
            </Button>
          </div>
        }
      />

      <Feedback notice={notice} error={error} onDismiss={() => setNotice(null)} />

      <Input
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        placeholder="Search by name, username or website"
        className="max-w-md"
        aria-label="Search passwords"
      />

      {rows === null ? (
        <div className="space-y-2">
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
        </div>
      ) : rows.length === 0 && groups.length === 0 ? (
        <Card>
          <CardContent className="space-y-3 py-12 text-center">
            <KeyRound className="mx-auto size-8 text-muted-foreground" aria-hidden />
            <p className="font-medium">No passwords yet</p>
            <p className="mx-auto max-w-md text-sm text-muted-foreground">
              Add your first password. You can keep it individual or file it into a group -
              and change your mind later with Move.
            </p>
            <Button onClick={() => setCreateIn('')}>
              <Plus aria-hidden />
              New password
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {/* Individual passwords, then one section per group. */}
          {(!query || individualRows.length > 0) &&
            renderSection({
              id: 'individual',
              title: 'Individual',
              icon: <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />,
              count: individualRows.length,
              subtitle: '· passwords not in any group',
              actions: (
                <Button
                  variant="ghost"
                  size="icon"
                  title="Add an individual password"
                  onClick={() => setCreateIn('')}
                >
                  <Plus className="size-4" aria-hidden />
                </Button>
              ),
              sectionRows: individualRows,
              emptyText: 'No individual passwords. Use + to add one, or Move one out of a group.',
            })}

          {groups.map((group) => {
            const sectionRows = rowsFor(group.id);
            if (query && sectionRows.length === 0) return null;

            return renderSection({
              id: group.id,
              title: group.name,
              icon: <UsersRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />,
              count: sectionRows.length,
              subtitle: `· shared with ${group.memberCount} ${
                group.memberCount === 1 ? 'person' : 'people'
              }${group.autoGrantRole ? ' · default for new people' : ''}`,
              actions: (
                <>
                  <Button
                    variant="ghost"
                    size="icon"
                    title={`Add a password to ${group.name}`}
                    onClick={() => setCreateIn(group.id)}
                  >
                    <Plus className="size-4" aria-hidden />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    title={`Settings for ${group.name}`}
                    onClick={() => setRenamingGroup(group)}
                  >
                    <Pencil className="size-4" aria-hidden />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                    title={`Delete the ${group.name} group`}
                    onClick={() => setDeletingGroup(group)}
                  >
                    <Trash2 className="size-4" aria-hidden />
                  </Button>
                </>
              ),
              sectionRows,
              emptyText: 'Nothing in this group yet. Use + to add a password, or Move one in.',
            });
          })}

          {query &&
            individualRows.length === 0 &&
            groups.every((group) => rowsFor(group.id).length === 0) && (
              <Card>
                <CardContent className="py-10 text-center text-sm text-muted-foreground">
                  Nothing matches "{search.trim()}".
                </CardContent>
              </Card>
            )}
        </div>
      )}

      {/* ----------------------------------------------------------------- */}

      <NewPasswordDialog
        open={createIn !== null}
        onOpenChange={(next) => {
          if (!next) setCreateIn(null);
        }}
        groups={groups}
        initialGroupId={createIn ?? ''}
        onDone={(name) => {
          setNotice(`Added "${name}".`);
          void load();
        }}
      />

      <NewGroupDialog
        open={creatingGroup}
        onOpenChange={setCreatingGroup}
        onDone={(name) => {
          setNotice(`Created the "${name}" group. Add passwords to it, then give people access from the People page.`);
          void load();
        }}
      />

      <EditPasswordDialog
        row={editing}
        onOpenChange={(next) => {
          if (!next) setEditing(null);
        }}
        onDone={(name) => {
          setNotice(`Updated "${name}".`);
          setEditing(null);
          void load();
        }}
      />

      <MovePasswordDialog
        row={moving}
        onOpenChange={(next) => {
          if (!next) setMoving(null);
        }}
        groups={groups}
        onDone={(name, destination) => {
          setNotice(`Moved "${name}" to ${destination}.`);
          setMoving(null);
          void load();
        }}
      />

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(next) => {
          if (!next) setDeleting(null);
        }}
        title={`Delete "${deleting?.name}"?`}
        description="The password is removed for everyone who had access to it. This cannot be undone."
        confirmLabel="Delete password"
        onConfirm={async () => {
          if (!deleting) return;
          try {
            await removeRow(deleting);
          } catch (caught) {
            setError(messageOf(caught, 'Could not delete that password.'));
          }
          setDeleting(null);
        }}
      />

      <GroupSettingsDialog
        group={renamingGroup}
        onOpenChange={(next) => {
          if (!next) setRenamingGroup(null);
        }}
        onDone={(message) => {
          setNotice(message);
          setRenamingGroup(null);
          void load();
        }}
      />

      <ConfirmDialog
        open={deletingGroup !== null}
        onOpenChange={(next) => {
          if (!next) setDeletingGroup(null);
        }}
        title={`Delete the "${deletingGroup?.name}" group?`}
        description={`Its ${deletingGroup?.itemCount ?? 0} password${
          (deletingGroup?.itemCount ?? 0) === 1 ? '' : 's'
        } will be deleted with it, and everyone loses access. If you want to keep any of them, move them out first.`}
        confirmLabel="Delete group"
        onConfirm={async () => {
          if (!deletingGroup) return;
          try {
            await api.deleteSharedVault(deletingGroup.id);
            setNotice(`Deleted the "${deletingGroup.name}" group.`);
            await load();
          } catch (caught) {
            setError(messageOf(caught, 'Could not delete that group.'));
          }
          setDeletingGroup(null);
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pieces
// ---------------------------------------------------------------------------

/** The stored shape of a login, from what the dialogs collect. */
function loginData(
  fields: { name: string; username: string; uri: string },
  previous?: SharedItemData,
): SharedItemData {
  // Addresses past the first are kept: the dialogs edit one, the extension may
  // have saved several.
  const otherUris = previous?.uris?.slice(1) ?? [];
  const uris = [...(fields.uri ? [fields.uri] : []), ...otherUris];

  return {
    ...previous,
    name: fields.name,
    username: fields.username || undefined,
    uris: uris.length > 0 ? uris : undefined,
  };
}

// ---------------------------------------------------------------------------
// New password
// ---------------------------------------------------------------------------

function NewPasswordDialog({
  open,
  onOpenChange,
  groups,
  initialGroupId,
  onDone,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  groups: MemberSharedVault[];
  initialGroupId: string;
  onDone: (name: string) => void;
}): React.ReactElement {
  const [name, setName] = React.useState('');
  const [username, setUsername] = React.useState('');
  const [uri, setUri] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [groupId, setGroupId] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (open) {
      setName('');
      setUsername('');
      setUri('');
      setPassword('');
      setGroupId(initialGroupId);
      setError(null);
    }
  }, [open, initialGroupId]);

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);

    try {
      const fields = {
        name: name.trim(),
        username: username.trim(),
        uri: uri.trim(),
        password,
      };

      const payload = {
        type: VAULT_ITEM_TYPE.LOGIN,
        data: loginData(fields),
        secret: { password: fields.password },
      };

      // Individual: the server wraps it in a vault of its own, which is what
      // makes this one password shareable on its own later.
      if (groupId) await api.createSharedItem(groupId, payload);
      else await api.createIndividualItem(payload);

      onDone(fields.name);
      onOpenChange(false);
    } catch (caught) {
      setError(messageOf(caught, 'Could not add that password.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New password</DialogTitle>
          <DialogDescription>
            Stored encrypted. Choose a group, or keep it individual and share it on its own.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="np-name">Name</Label>
            <Input
              id="np-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Office Wi-Fi"
              autoFocus
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="np-username">Username (optional)</Label>
            <Input
              id="np-username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="np-uri">Website (optional)</Label>
            <Input
              id="np-uri"
              value={uri}
              onChange={(event) => setUri(event.target.value)}
              placeholder="https://example.com/login"
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="np-password">Password</Label>
            <Input
              id="np-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="new-password"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="np-group">Group</Label>
            <Select
              id="np-group"
              value={groupId}
              onChange={(event) => setGroupId(event.target.value)}
            >
              <option value="">Individual - not in any group</option>
              {groups.map((group) => (
                <option key={group.id} value={group.id}>
                  {group.name}
                </option>
              ))}
            </Select>
          </div>

          {error && (
            <Alert variant="destructive">
              <ShieldAlert aria-hidden />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !name.trim() || !password}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            Add password
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// New group
// ---------------------------------------------------------------------------

function NewGroupDialog({
  open,
  onOpenChange,
  onDone,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDone: (name: string) => void;
}): React.ReactElement {
  const [name, setName] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (open) {
      setName('');
      setError(null);
    }
  }, [open]);

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await api.createSharedVault({ name: name.trim(), kind: VAULT_KIND.GROUP });
      onDone(name.trim());
      onOpenChange(false);
    } catch (caught) {
      setError(messageOf(caught, 'Could not create that group.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New group</DialogTitle>
          <DialogDescription>
            A group is a set of passwords you share as one unit - "Marketing", "Servers",
            "Front desk". Name it, put passwords in, give people access.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <Label htmlFor="ng-name">Group name</Label>
          <Input
            id="ng-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Marketing"
            autoFocus
          />
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || name.trim().length < 2}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            Create group
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Edit
// ---------------------------------------------------------------------------

function EditPasswordDialog({
  row,
  onOpenChange,
  onDone,
}: {
  row: Row | null;
  onOpenChange: (open: boolean) => void;
  onDone: (name: string) => void;
}): React.ReactElement {
  const [name, setName] = React.useState('');
  const [username, setUsername] = React.useState('');
  const [uri, setUri] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!row) return;
    setName(row.name);
    setUsername(row.username);
    setUri(row.uri);
    setPassword('');
    setError(null);
  }, [row]);

  const submit = async (): Promise<void> => {
    if (!row) return;

    if (password && !row.canReadSecret) {
      setError('Passwords in this group are hidden from you, so you cannot change this one.');
      return;
    }

    setBusy(true);
    setError(null);

    try {
      // The stored secret is replaced whole, so anything beside the password
      // (a TOTP seed the extension saved, say) is read first and carried over.
      const secret = password
        ? {
            ...(await api.getSharedItemSecret(row.vaultId, row.itemId, SECRET_PURPOSE.EDIT)),
            password,
          }
        : undefined;

      await api.updateSharedItem(row.vaultId, row.itemId, {
        data: loginData(
          { name: name.trim(), username: username.trim(), uri: uri.trim() },
          row.data,
        ),
        // Only when a new one was typed - blank leaves the stored secret alone.
        ...(secret ? { secret } : {}),
        revision: row.revision,
      });

      onDone(name.trim());
    } catch (caught) {
      setError(messageOf(caught, 'Could not save this password.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={row !== null} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit password</DialogTitle>
          <DialogDescription>Everyone with access sees these changes.</DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="ep-name">Name</Label>
            <Input id="ep-name" value={name} onChange={(event) => setName(event.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ep-username">Username</Label>
            <Input
              id="ep-username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ep-uri">Website</Label>
            <Input
              id="ep-uri"
              value={uri}
              onChange={(event) => setUri(event.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="ep-password">New password</Label>
            <Input
              id="ep-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Leave blank to keep the current one"
              autoComplete="new-password"
            />
            <p className="text-xs text-muted-foreground">
              The stored password is not shown here, and is only replaced if you type a new one.
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || !name.trim()}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            Save changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Move
// ---------------------------------------------------------------------------

/**
 * Move a password between "Individual" and any group, or group to group.
 *
 * One request: the server re-files the item. Access follows the destination
 * immediately - whoever can open the destination can now use this password,
 * and whoever could only open the source no longer can.
 */
function MovePasswordDialog({
  row,
  onOpenChange,
  groups,
  onDone,
}: {
  row: Row | null;
  onOpenChange: (open: boolean) => void;
  groups: MemberSharedVault[];
  onDone: (name: string, destination: string) => void;
}): React.ReactElement {
  const [target, setTarget] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  /*
   * Pre-select a destination that is actually on offer. An individual password
   * cannot move to "Individual", so that option is not rendered for it - and a
   * controlled <select> whose value matches no option *displays* the first
   * option while the state still holds ''. The user saw a group chosen and a
   * Move button that never enabled. Initialising to the first real option
   * keeps what is shown and what is submitted the same thing.
   */
  React.useEffect(() => {
    if (!row) return;
    const firstGroup = groups.find((group) => group.id !== row.vaultId);
    setTarget(row.kind === 'item' ? firstGroup?.id ?? '' : '');
    setError(null);
    // Deliberately keyed on the row alone: `groups` gets a fresh identity on
    // every parent render, and re-running then would reset a choice the user
    // has already made in the open dialog.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [row]);

  // Where can this go? Anywhere but where it already is. The server checks
  // the caller may add to the destination.
  const options = groups.filter((group) => group.id !== row?.vaultId);
  const canGoIndividual = row?.kind !== 'item';

  const submit = async (): Promise<void> => {
    if (!row) return;

    setBusy(true);
    setError(null);

    try {
      await api.moveSharedItem(row.vaultId, row.itemId, {
        targetVaultId: target === '' ? null : target,
        revision: row.revision,
      });

      const destinationLabel =
        target === '' ? 'Individual' : groups.find((group) => group.id === target)?.name ?? 'that group';
      onDone(row.name, destinationLabel);
    } catch (caught) {
      setError(messageOf(caught, 'Could not move this password.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={row !== null} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Move "{row?.name}"</DialogTitle>
          <DialogDescription>
            Access follows the destination: whoever can open the destination group can use this
            password, and access through {row?.kind === 'item' ? 'its individual share' : 'its current group'} ends.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <Label htmlFor="mv-target">Move to</Label>
          <Select
            id="mv-target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
          >
            {canGoIndividual && <option value="">Individual - not in any group</option>}
            {options.map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </Select>
          {!canGoIndividual && options.length === 0 && (
            <p className="text-xs text-muted-foreground">
              There is no group to move this into yet - create one first.
            </p>
          )}
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button
            onClick={() => void submit()}
            disabled={busy || (!canGoIndividual && target === '')}
          >
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            Move
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Group settings
// ---------------------------------------------------------------------------

/**
 * Name, and whether the group is a default for new people.
 *
 * A default group is granted to every account the moment it is created - a
 * first Google sign-in, or an administrator adding someone. New people can use
 * its passwords from the extension; nobody changes anything there, so there is
 * no role to pick. People who already have an account are not affected; give
 * them access from the People page.
 */
function GroupSettingsDialog({
  group,
  onOpenChange,
  onDone,
}: {
  group: MemberSharedVault | null;
  onOpenChange: (open: boolean) => void;
  onDone: (message: string) => void;
}): React.ReactElement {
  const { hasPermission } = useAuth();
  const canSetDefault = hasPermission(PERMISSIONS.SHARED_VAULT_MANAGE);

  const [name, setName] = React.useState('');
  const [isDefault, setIsDefault] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (group) {
      setName(group.name);
      setIsDefault(group.autoGrantRole !== null);
      setError(null);
    }
  }, [group]);

  const submit = async (): Promise<void> => {
    if (!group) return;
    setBusy(true);
    setError(null);

    const nextRole = isDefault ? VAULT_ROLE.VIEWER : null;
    try {
      await api.updateSharedVault(group.id, {
        name: name.trim(),
        ...(canSetDefault && nextRole !== group.autoGrantRole ? { autoGrantRole: nextRole } : {}),
      });

      onDone(
        canSetDefault && nextRole !== group.autoGrantRole
          ? nextRole
            ? `Everyone who joins from now on can use "${name.trim()}".`
            : `"${name.trim()}" is no longer given to new people automatically.`
          : `Saved "${name.trim()}".`,
      );
    } catch (caught) {
      setError(messageOf(caught, 'Could not save this group.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={group !== null} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Group settings</DialogTitle>
          <DialogDescription>Everyone sees the new name. Access does not change.</DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <Label htmlFor="gs-name">Group name</Label>
          <Input
            id="gs-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoFocus
          />
        </div>

        {canSetDefault && (
          <div className="space-y-3 rounded-lg border p-3">
            <div className="flex items-start gap-3">
              <Checkbox
                id="gs-default"
                checked={isDefault}
                onCheckedChange={(checked) => setIsDefault(checked === true)}
                className="mt-0.5"
              />
              <div className="space-y-1">
                <Label htmlFor="gs-default">Give new people this group automatically</Label>
                <p className="text-xs text-muted-foreground">
                  Everyone who gets a PassM account from now on - by signing in with Google for the
                  first time, or being added on the People page - can use this group&apos;s
                  passwords from the browser extension straight away. People who already have an
                  account are not affected.
                </p>
              </div>
            </div>
          </div>
        )}

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={busy || name.trim().length < 2}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * User directory.
 *
 * Read access needs `user:read` (managers and admins). Every mutating control is
 * gated on the specific permission it requires, so a manager sees the directory
 * with no action buttons at all. The API enforces the same rules - this only
 * decides what is worth rendering.
 */

import {
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  ShieldOff,
  Trash2,
  Unlock,
  UserPlus,
  UsersRound,
  X,
} from 'lucide-react';
import * as React from 'react';

import {
  PERMISSIONS,
  ROLES,
  ROLE_LABEL,
  USER_STATUS,
  USER_STATUS_LABEL,
  USER_STATUS_LIST,
  VAULT_KIND,
  type AdminUserDetail,
  type AdminUserListItem,
  type RoleName,
  type SharedVault,
} from '@passm/shared';

import {
  ConfirmDialog,
  Feedback,
  PageHeader,
  messageOf,
  useAsyncData,
  useQueryParam,
} from '@/components/admin/admin-kit';
import {
  DataTable,
  DEFAULT_QUERY,
  type Column,
  type DataTableQuery,
} from '@/components/admin/data-table';
import { RoleBadge, StatusBadge } from '@/components/role-badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
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
import { Select, SelectCompact } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Textarea } from '@/components/ui/textarea';

import { ApiError, api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { formatDateTime, formatRelative } from '@/lib/format';

/** Give one person viewer access to each of `vaultIds`. Access is live at once. */
async function grantAccess(userId: string, vaultIds: readonly string[]): Promise<number> {
  for (const vaultId of vaultIds) {
    await api.addSharedVaultGrant(vaultId, { subjectType: 'user', subjectId: userId, role: 'viewer' });
  }
  return vaultIds.length;
}

export default function AdminUsersPage(): React.ReactElement {
  const { hasPermission, user: currentUser } = useAuth();

  const canCreate = hasPermission(PERMISSIONS.USER_CREATE);
  const canAssignRole = hasPermission(PERMISSIONS.ROLE_ASSIGN);
  const canDisable = hasPermission(PERMISSIONS.USER_DISABLE);
  const canLock = hasPermission(PERMISSIONS.USER_LOCK);
  const canRevokeSessions = hasPermission(PERMISSIONS.SESSION_REVOKE_ANY);

  const [query, setQuery] = React.useState<DataTableQuery>({
    ...DEFAULT_QUERY,
    sortBy: 'lastName',
    sortDir: 'asc',
  });
  const [roleFilter, setRoleFilter] = React.useState<string>('');
  const [statusFilter, setStatusFilter] = React.useState<string>('');

  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [pendingId, setPendingId] = React.useState<string | null>(null);
  const [showCreate, setShowCreate] = React.useState(false);

  const [selectedUserId, setSelectedUserId] = useQueryParam('user');

  const [lockTarget, setLockTarget] = React.useState<AdminUserListItem | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<AdminUserListItem | null>(null);


  const { data, refreshing, error: loadError, reload } = useAsyncData(
    () =>
      api.listUsers({
        page: query.page,
        pageSize: query.pageSize,
        sortBy: query.sortBy ?? 'lastName',
        sortDir: query.sortDir,
        ...(query.search ? { search: query.search } : {}),
        ...(roleFilter ? { role: roleFilter as RoleName } : {}),
        ...(statusFilter ? { status: statusFilter } : {}),
      }),
    [query, roleFilter, statusFilter],
  );

  /** Run a mutation with consistent busy state, error handling and refresh. */
  const act = async (
    row: AdminUserListItem,
    work: () => Promise<string>,
  ): Promise<void> => {
    setPendingId(row.id);
    setError(null);
    try {
      setNotice(await work());
      await reload();
    } catch (caught) {
      setError(messageOf(caught, 'That did not work.'));
    } finally {
      setPendingId(null);
    }
  };

  const columns: Column<AdminUserListItem>[] = [
    {
      key: 'user',
      header: 'User',
      sortKey: 'lastName',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="font-medium hover:underline"
              onClick={() => setSelectedUserId(row.id)}
            >
              {row.fullName}
            </button>
            {row.id === currentUser?.id && (
              <span className="text-xs text-muted-foreground">(you)</span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">{row.email}</p>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      sortKey: 'role',
      render: (row) =>
        canAssignRole && row.id !== currentUser?.id ? (
          <SelectCompact
            value={row.role}
            disabled={pendingId === row.id}
            aria-label={`Role for ${row.fullName}`}
            onChange={(event) =>
              void act(row, async () => {
                const role = event.target.value as RoleName;
                await api.changeUserRole(row.id, role, true);
                return `${row.fullName} is now a ${ROLE_LABEL[role]}. Their sessions were ended.`;
              })
            }
          >
            {[ROLES.ADMIN, ROLES.EMPLOYEE].map((role) => (
              <option key={role} value={role}>
                {ROLE_LABEL[role]}
              </option>
            ))}
          </SelectCompact>
        ) : (
          <RoleBadge role={row.role} />
        ),
    },
    {
      key: 'status',
      header: 'Status',
      sortKey: 'status',
      render: (row) => (
        <div className="space-y-1">
          <StatusBadge status={row.status} />
          {row.lockReason && (
            <p className="max-w-[12rem] truncate text-xs text-muted-foreground" title={row.lockReason}>
              {row.lockReason}
            </p>
          )}
        </div>
      ),
    },
    {
      /*
       * What this person can use, and the way in to change it. A count alone
       * looked like a statistic; the ask was "where do I put someone in a
       * group after creating them", and the answer has to be visible on the
       * row itself, not hidden behind clicking their name.
       */
      key: 'canUse',
      header: 'Can use',
      render: (row) => (
        <button
          type="button"
          className="text-left text-sm hover:underline"
          title={`Change what ${row.fullName} can use`}
          onClick={() => setSelectedUserId(row.id)}
        >
          {row.sharedVaultCount > 0 ? (
            <span className="tabular-nums">
              {row.sharedVaultCount}
              <span className="text-muted-foreground">
                {' '}
                {row.sharedVaultCount === 1 ? 'group / password' : 'groups / passwords'}
              </span>
            </span>
          ) : (
            <span className="text-primary">Give access</span>
          )}
          {row.status === 'pending' && (
            <span className="ml-2 text-xs text-muted-foreground">not signed in yet</span>
          )}
        </button>
      ),
    },
    {
      key: 'sessions',
      header: 'Sessions',
      hideOnMobile: true,
      render: (row) => (
        <span className="text-sm tabular-nums">
          {row.activeSessionCount}
          <span className="text-muted-foreground">
            {' '}
            session{row.activeSessionCount === 1 ? '' : 's'} · {row.trustedDeviceCount} device
            {row.trustedDeviceCount === 1 ? '' : 's'}
          </span>
        </span>
      ),
    },
    {
      key: 'lastLogin',
      header: 'Last sign-in',
      sortKey: 'lastLoginAt',
      hideOnMobile: true,
      render: (row) => (
        <span className="text-sm text-muted-foreground">{formatRelative(row.lastLoginAt)}</span>
      ),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'text-right',
      className: 'text-right',
      render: (row) => {
        const isSelf = row.id === currentUser?.id;
        const busy = pendingId === row.id;
        const isLocked = row.status === USER_STATUS.LOCKED;

        return (
          <div className="flex justify-end gap-1">
            {busy && <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden />}

            <Button
              variant="ghost"
              size="sm"
              disabled={busy}
              title="Groups and passwords this person can use"
              onClick={() => setSelectedUserId(row.id)}
            >
              <UsersRound aria-hidden />
              <span className="sr-only">Manage access</span>
            </Button>

            {canRevokeSessions && !isSelf && row.activeSessionCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                disabled={busy}
                title="Sign out everywhere"
                onClick={() =>
                  void act(row, async () => {
                    const result = await api.revokeUserSessions(row.id);
                    return `Ended ${result.revokedSessions} session${
                      result.revokedSessions === 1 ? '' : 's'
                    } for ${row.fullName}.`;
                  })
                }
              >
                <LogOut aria-hidden />
                <span className="sr-only">Force logout</span>
              </Button>
            )}

            {canLock && !isSelf && (
              <Button
                variant="ghost"
                size="sm"
                disabled={busy}
                title={isLocked ? 'Unlock' : 'Lock'}
                onClick={() =>
                  isLocked
                    ? void act(row, async () => {
                        await api.unlockUser(row.id);
                        return `${row.fullName} can sign in again.`;
                      })
                    : setLockTarget(row)
                }
              >
                {isLocked ? <Unlock aria-hidden /> : <Lock aria-hidden />}
                <span className="sr-only">{isLocked ? 'Unlock' : 'Lock'}</span>
              </Button>
            )}

            {canDisable && !isSelf && (
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                disabled={busy}
                title={row.status === USER_STATUS.SUSPENDED ? 'Reactivate' : 'Suspend'}
                onClick={() =>
                  void act(row, async () => {
                    const next =
                      row.status === USER_STATUS.SUSPENDED
                        ? USER_STATUS.ACTIVE
                        : USER_STATUS.SUSPENDED;
                    await api.changeUserStatus(row.id, next);
                    return next === USER_STATUS.SUSPENDED
                      ? `${row.fullName} has been suspended and signed out everywhere.`
                      : `${row.fullName} has been reactivated.`;
                  })
                }
              >
                <ShieldOff aria-hidden />
                <span className="sr-only">
                  {row.status === USER_STATUS.SUSPENDED ? 'Reactivate' : 'Suspend'}
                </span>
              </Button>
            )}

            {canDisable && !isSelf && (
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                disabled={busy}
                title="Delete user"
                onClick={() => setDeleteTarget(row)}
              >
                <Trash2 aria-hidden />
                <span className="sr-only">Delete user</span>
              </Button>
            )}
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="People"
        description={`${(data?.total ?? 0).toLocaleString()} account${
          data?.total === 1 ? '' : 's'
        }. Add someone, then tick what they can use.`}
        actions={
          canCreate && (
            <Button onClick={() => setShowCreate(true)}>
              <UserPlus aria-hidden />
              Add user
            </Button>
          )
        }
      />

      <Feedback
        notice={notice}
        error={error ?? loadError}
        onDismiss={() => setNotice(null)}
      />

      <DataTable
        columns={columns}
        rows={data?.items ?? null}
        total={data?.total ?? 0}
        query={query}
        onQueryChange={setQuery}
        rowKey={(row) => row.id}
        refreshing={refreshing}
        searchPlaceholder="Search name or email"
        emptyMessage="No users match these filters."
        caption="User directory"
        toolbar={
          <>
            <SelectCompact
              value={roleFilter}
              onChange={(event) => {
                setRoleFilter(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by role"
              className="w-auto"
            >
              <option value="">All roles</option>
              {[ROLES.ADMIN, ROLES.EMPLOYEE].map((role) => (
                <option key={role} value={role}>
                  {ROLE_LABEL[role]}
                </option>
              ))}
            </SelectCompact>

            <SelectCompact
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by status"
              className="w-auto"
            >
              <option value="">All statuses</option>
              {USER_STATUS_LIST.map((status) => (
                <option key={status} value={status}>
                  {USER_STATUS_LABEL[status]}
                </option>
              ))}
            </SelectCompact>
          </>
        }
      />

      {canCreate && (
        <CreateUserDialog
          open={showCreate}
          onOpenChange={setShowCreate}
          onCreated={(message) => {
            setNotice(message);
            void reload();
          }}
        />
      )}

      <LockUserDialog
        target={lockTarget}
        onClose={() => setLockTarget(null)}
        onLocked={(message) => {
          setNotice(message);
          void reload();
        }}
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title={`Delete ${deleteTarget?.fullName}?`}
        confirmLabel="Delete user"
        confirmPhrase={deleteTarget?.email}
        confirmPhraseLabel={`Type ${deleteTarget?.email} to confirm`}
        description={
          <>
            <p>
              Their account is removed, their sessions end immediately, and everything shared
              with them is taken back.
            </p>
            <p>
              The passwords themselves are untouched - they stay in their groups for everyone
              else. This cannot be undone.
            </p>
          </>
        }
        onConfirm={async () => {
          if (!deleteTarget) return;
          await api.deleteUser(deleteTarget.id);
          setNotice(`${deleteTarget.fullName} has been deleted.`);
          setDeleteTarget(null);
          await reload();
        }}
      />

      <UserDetailDialog
        userId={selectedUserId}
        onClose={() => setSelectedUserId(null)}
        onChanged={() => void reload()}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Access picker: which password groups / individual passwords a person can use
// ---------------------------------------------------------------------------

/**
 * Checkbox list of everything grantable: password groups first, individual
 * passwords after. `exclude` hides what the person already has.
 */
function AccessPicker({
  selected,
  onToggle,
  exclude,
}: {
  selected: ReadonlySet<string>;
  onToggle: (vaultId: string) => void;
  exclude?: ReadonlySet<string>;
}): React.ReactElement {
  const { data } = useAsyncData(
    () => api.listSharedVaultsAdmin({ pageSize: 100, sortBy: 'name', sortDir: 'asc' }),
    [],
  );

  const all: SharedVault[] = (data?.items ?? []).filter(
    (vault) => !(exclude?.has(vault.id) ?? false),
  );
  const groups = all.filter((vault) => vault.kind === VAULT_KIND.GROUP);
  const singles = all.filter((vault) => vault.kind === VAULT_KIND.ITEM);

  if (data && all.length === 0) {
    return (
      <p className="rounded-md border border-dashed px-3 py-4 text-center text-sm text-muted-foreground">
        Nothing to give access to yet - add passwords and groups on the Passwords page first.
      </p>
    );
  }

  const row = (vault: SharedVault, icon: React.ReactNode): React.ReactElement => (
    <label
      key={vault.id}
      className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-secondary"
    >
      <input
        type="checkbox"
        className="size-4 accent-primary"
        checked={selected.has(vault.id)}
        onChange={() => onToggle(vault.id)}
      />
      {icon}
      <span className="min-w-0 flex-1 truncate">{vault.name}</span>
      {vault.kind === VAULT_KIND.GROUP && (
        <span className="shrink-0 text-xs text-muted-foreground">
          {vault.itemCount} password{vault.itemCount === 1 ? '' : 's'}
        </span>
      )}
    </label>
  );

  return (
    <div className="max-h-56 space-y-3 overflow-y-auto rounded-md border p-2">
      {groups.length > 0 && (
        <div>
          <p className="px-2 pb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Groups
          </p>
          {groups.map((vault) =>
            row(vault, <UsersRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />),
          )}
        </div>
      )}
      {singles.length > 0 && (
        <div>
          <p className="px-2 pb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Individual passwords
          </p>
          {singles.map((vault) =>
            row(vault, <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />),
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

function CreateUserDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (message: string) => void;
}): React.ReactElement {
  const [form, setForm] = React.useState({
    email: '',
    firstName: '',
    lastName: '',
    role: ROLES.EMPLOYEE as RoleName,
    jobTitle: '',
  });
  const [access, setAccess] = React.useState<Set<string>>(new Set());
  const [busy, setBusy] = React.useState(false);
  const [fieldErrors, setFieldErrors] = React.useState<Record<string, string>>({});
  const [formError, setFormError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (open) {
      setForm({
        email: '',
        firstName: '',
        lastName: '',
        role: ROLES.EMPLOYEE,
        jobTitle: '',
      });
      setAccess(new Set());
      setFieldErrors({});
      setFormError(null);
    }
  }, [open]);

  const update =
    (key: keyof typeof form) => (event: React.ChangeEvent<HTMLInputElement>) => {
      setForm((current) => ({ ...current, [key]: event.target.value }));
    };

  const submit = async (event: React.FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setBusy(true);
    setFieldErrors({});
    setFormError(null);

    try {
      const result = await api.createUser({
        email: form.email.trim(),
        firstName: form.firstName.trim(),
        lastName: form.lastName.trim(),
        role: form.role,
        ...(form.jobTitle.trim() ? { jobTitle: form.jobTitle.trim() } : {}),
      });

      let accessNote = '';
      if (access.size > 0) {
        try {
          const granted = await grantAccess(result.user.id, [...access]);
          accessNote = ` They can use ${granted} ${granted === 1 ? 'entry' : 'entries'} from their first sign-in.`;
        } catch (caught) {
          accessNote = ` Giving access failed (${messageOf(caught, 'unknown error')}) - you can grant it from their profile.`;
        }
      }

      onCreated(
        `${result.user.fullName} has been added as a ${ROLE_LABEL[result.user.role]}.${accessNote}`,
      );
      onOpenChange(false);
    } catch (caught) {
      if (caught instanceof ApiError && caught.details.length > 0) {
        const mapped: Record<string, string> = {};
        for (const detail of caught.details) {
          // Server paths look like `body.password`; the last segment is the field.
          const key = detail.field.split('.').pop() ?? detail.field;
          mapped[key] = detail.message;
        }
        setFieldErrors(mapped);
      }
      setFormError(messageOf(caught, 'Could not create that account.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide>
        <DialogHeader>
          <DialogTitle>Add a user</DialogTitle>
          <DialogDescription>
            They sign in with the Google account at this address - there is no password to set.
            Anyone from the company domain is added automatically on first sign-in; add them here
            to choose their role or give them access in advance.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2" noValidate>
          <div className="space-y-2">
            <Label htmlFor="firstName">First name</Label>
            <Input id="firstName" required value={form.firstName} onChange={update('firstName')} />
            {fieldErrors.firstName && (
              <p className="text-xs text-destructive">{fieldErrors.firstName}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="lastName">Last name</Label>
            <Input id="lastName" required value={form.lastName} onChange={update('lastName')} />
            {fieldErrors.lastName && (
              <p className="text-xs text-destructive">{fieldErrors.lastName}</p>
            )}
          </div>

          <div className="space-y-2 sm:col-span-2">
            <Label htmlFor="newEmail">Work email</Label>
            <Input
              id="newEmail"
              type="email"
              required
              value={form.email}
              onChange={update('email')}
              placeholder="person@123cfc.com"
            />
            {fieldErrors.email && <p className="text-xs text-destructive">{fieldErrors.email}</p>}
          </div>

          <div className="space-y-2">
            <Label htmlFor="role">Role</Label>
            <Select
              id="role"
              value={form.role}
              onChange={(event) =>
                setForm((current) => ({ ...current, role: event.target.value as RoleName }))
              }
            >
              {[ROLES.EMPLOYEE, ROLES.ADMIN].map((role) => (
                <option key={role} value={role}>
                  {ROLE_LABEL[role]}
                </option>
              ))}
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="jobTitle">Job title (optional)</Label>
            <Input id="jobTitle" value={form.jobTitle} onChange={update('jobTitle')} />
          </div>

          <div className="space-y-2 sm:col-span-2">
            <Label>What can they use?</Label>
            <AccessPicker
              selected={access}
              onToggle={(vaultId) =>
                setAccess((current) => {
                  const next = new Set(current);
                  if (next.has(vaultId)) next.delete(vaultId);
                  else next.add(vaultId);
                  return next;
                })
              }
            />
            <p className="text-xs text-muted-foreground">
              Tick the groups or individual passwords this person needs. You can change this any
              time from their profile.
            </p>
          </div>

          {formError && (
            <div className="sm:col-span-2">
              <Alert variant="destructive">
                <AlertDescription>{formError}</AlertDescription>
              </Alert>
            </div>
          )}

          <DialogFooter className="sm:col-span-2">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy}>
              {busy && <Loader2 className="animate-spin" aria-hidden />}
              Create account
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------

function LockUserDialog({
  target,
  onClose,
  onLocked,
}: {
  target: AdminUserListItem | null;
  onClose: () => void;
  onLocked: (message: string) => void;
}): React.ReactElement {
  const [reason, setReason] = React.useState('');
  const [bounded, setBounded] = React.useState(false);
  const [until, setUntil] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (target) {
      setReason('');
      setBounded(false);
      setUntil('');
      setError(null);
    }
  }, [target]);

  const submit = async (): Promise<void> => {
    if (!target) return;

    setBusy(true);
    setError(null);
    try {
      const result = await api.lockUser(target.id, {
        reason: reason.trim(),
        // datetime-local has no zone, so it is interpreted in the browser's and
        // converted to UTC here - the API only accepts an absolute instant.
        ...(bounded && until ? { until: new Date(until).toISOString() } : {}),
        revokeSessions: true,
      });

      onLocked(
        `${target.fullName} is locked out. ${result.revokedSessions} session${
          result.revokedSessions === 1 ? ' was' : 's were'
        } ended.`,
      );
      onClose();
    } catch (caught) {
      setError(messageOf(caught, 'Could not lock that account.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Lock {target?.fullName}</DialogTitle>
          <DialogDescription>
            They cannot sign in until the lock is lifted. Their access is untouched, and the lock
            is reversible.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="lockReason">Reason</Label>
            <Textarea
              id="lockReason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Shown to whoever unlocks the account later."
              maxLength={200}
            />
          </div>

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={bounded}
              onChange={(event) => setBounded(event.target.checked)}
              className="size-4 rounded border-input"
            />
            Lift automatically at a set time
          </label>

          {bounded && (
            <div className="space-y-2">
              <Label htmlFor="lockUntil">Locked until</Label>
              <Input
                id="lockUntil"
                type="datetime-local"
                value={until}
                onChange={(event) => setUntil(event.target.value)}
              />
            </div>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={busy || reason.trim().length < 3 || (bounded && !until)}
            onClick={() => void submit()}
          >
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            Lock account
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

function UserDetailDialog({
  userId,
  onClose,
  onChanged,
}: {
  userId: string | null;
  onClose: () => void;
  onChanged: () => void;
}): React.ReactElement | null {
  const { hasPermission } = useAuth();
  const canManageAccess = hasPermission(PERMISSIONS.SHARED_VAULT_MANAGE);

  const [detail, setDetail] = React.useState<AdminUserDetail | null>(null);
  const [sessions, setSessions] = React.useState<{ id: string; ipAddress: string | null }[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [addingAccess, setAddingAccess] = React.useState(false);
  const [accessSelection, setAccessSelection] = React.useState<Set<string>>(new Set());
  const [accessBusy, setAccessBusy] = React.useState(false);

  const refreshDetail = React.useCallback(async (): Promise<void> => {
    if (!userId) return;
    const refreshed = await api.getUserDetail(userId);
    setDetail(refreshed.user);
    onChanged();
  }, [userId, onChanged]);

  /** Grant the ticked entries. */
  const grantSelected = async (): Promise<void> => {
    if (!userId || accessSelection.size === 0) return;
    setAccessBusy(true);
    setError(null);
    try {
      await grantAccess(userId, [...accessSelection]);
      setAccessSelection(new Set());
      setAddingAccess(false);
      await refreshDetail();
    } catch (caught) {
      setError(messageOf(caught, 'Could not give that access.'));
    } finally {
      setAccessBusy(false);
    }
  };

  /** Take one entry away: find the grant naming this user and revoke it. */
  const revokeAccess = async (vaultId: string): Promise<void> => {
    if (!userId) return;
    setAccessBusy(true);
    setError(null);
    try {
      const access = await api.getSharedVaultAccess(vaultId);
      const grant = access.grants.find(
        (candidate) => candidate.subjectType === 'user' && candidate.subjectId === userId,
      );
      if (grant) await api.revokeSharedVaultGrant(vaultId, grant.id);
      await refreshDetail();
    } catch (caught) {
      setError(messageOf(caught, 'Could not remove that access.'));
    } finally {
      setAccessBusy(false);
    }
  };

  React.useEffect(() => {
    if (!userId) {
      setDetail(null);
      return;
    }

    let cancelled = false;
    void (async () => {
      try {
        const [detailResult, sessionResult] = await Promise.all([
          api.getUserDetail(userId),
          api.listUserSessions(userId).catch(() => ({ sessions: [] })),
        ]);
        if (!cancelled) {
          setDetail(detailResult.user);
          setSessions(sessionResult.sessions.map((s) => ({ id: s.id, ipAddress: s.ipAddress })));
          setError(null);
        }
      } catch (caught) {
        if (!cancelled) setError(messageOf(caught, 'Could not load that user.'));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [userId]);

  if (!userId) return null;

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent wide>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : !detail ? (
          <p className="py-8 text-center text-sm text-muted-foreground">Loading…</p>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>{detail.fullName}</DialogTitle>
              <DialogDescription>{detail.email}</DialogDescription>
            </DialogHeader>

            <div className="flex flex-wrap items-center gap-2">
              <RoleBadge role={detail.role} />
              <StatusBadge status={detail.status} />
            </div>

            <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <Detail label="Job title">{detail.jobTitle ?? '-'}</Detail>
              <Detail label="Created">{formatDateTime(detail.createdAt)}</Detail>
              <Detail label="Created by">{detail.createdByName ?? 'System'}</Detail>
              <Detail label="Last sign-in">{formatRelative(detail.lastLoginAt)}</Detail>
              <Detail label="From address">
                <span className="font-mono text-xs">{detail.lastLoginIp ?? '-'}</span>
              </Detail>
            </dl>

            <Separator />

            <div className="grid gap-6 sm:grid-cols-3">
              <div>
                <p className="text-sm text-muted-foreground">Groups / passwords</p>
                <p className="text-xl font-semibold tabular-nums">{detail.sharedVaultCount}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Active sessions</p>
                <p className="text-xl font-semibold tabular-nums">{sessions.length}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Trusted devices</p>
                <p className="text-xl font-semibold tabular-nums">{detail.trustedDeviceCount}</p>
              </div>
            </div>

            <Separator />

            {/*
              What this person can use. A grant is live the moment it exists.
            */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">What they can use</p>
                {canManageAccess && !addingAccess && (
                  <Button size="sm" variant="outline" onClick={() => setAddingAccess(true)}>
                    <KeyRound aria-hidden />
                    Give access
                  </Button>
                )}
              </div>

              {detail.access.length === 0 && !addingAccess ? (
                <p className="rounded-md border border-dashed px-3 py-3 text-sm text-muted-foreground">
                  Nothing yet. Give them a group or an individual password and it appears in
                  their browser extension.
                </p>
              ) : (
                <div className="divide-y rounded-md border">
                  {detail.access.map((entry) => (
                    <div key={entry.vaultId} className="flex items-center gap-2.5 px-3 py-2">
                      {entry.kind === 'group' ? (
                        <UsersRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                      ) : (
                        <KeyRound className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                      )}
                      <span className="min-w-0 flex-1 truncate text-sm">{entry.name}</span>
                      {entry.hiddenPassword && (
                        <span className="shrink-0 rounded-full bg-secondary px-2 py-0.5 text-[11px] text-muted-foreground">
                          password hidden
                        </span>
                      )}
                      {canManageAccess && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          title={`Remove access to ${entry.name}`}
                          disabled={accessBusy}
                          onClick={() => void revokeAccess(entry.vaultId)}
                        >
                          <X className="size-3.5" aria-hidden />
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {addingAccess && (
                <div className="space-y-2">
                  <AccessPicker
                    selected={accessSelection}
                    exclude={new Set(detail.access.map((entry) => entry.vaultId))}
                    onToggle={(vaultId) =>
                      setAccessSelection((current) => {
                        const next = new Set(current);
                        if (next.has(vaultId)) next.delete(vaultId);
                        else next.add(vaultId);
                        return next;
                      })
                    }
                  />
                  <div className="flex justify-end gap-2">
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={accessBusy}
                      onClick={() => {
                        setAddingAccess(false);
                        setAccessSelection(new Set());
                      }}
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      disabled={accessBusy || accessSelection.size === 0}
                      onClick={() => void grantSelected()}
                    >
                      {accessBusy && <Loader2 className="animate-spin" aria-hidden />}
                      Give access
                    </Button>
                  </div>
                </div>
              )}
            </div>

            {detail.lockReason && (
              <Alert variant="warning">
                <Lock aria-hidden />
                <AlertTitle>Locked</AlertTitle>
                <AlertDescription>{detail.lockReason}</AlertDescription>
              </Alert>
            )}

            <DialogFooter>
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function Detail({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <div className="flex items-center justify-between gap-4 sm:block sm:space-y-0.5">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-medium">{children}</dd>
    </div>
  );
}

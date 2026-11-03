/**
 * Every live session in the tenant.
 *
 * Defaults to active sessions only. The table is an operational view - "who is
 * signed in right now, and from where" - and expired rows would bury the handful
 * an administrator actually needs to act on.
 */

import { LogOut, MonitorSmartphone } from 'lucide-react';
import * as React from 'react';

import { PERMISSIONS, type AdminSessionRow } from '@passm/shared';

import {
  ConfirmDialog,
  Feedback,
  PageHeader,
  StatCard,
  messageOf,
  useAsyncData,
} from '@/components/admin/admin-kit';
import {
  DataTable,
  DEFAULT_QUERY,
  type Column,
  type DataTableQuery,
} from '@/components/admin/data-table';
import { RoleBadge } from '@/components/role-badge';
import { Button } from '@/components/ui/button';
import { SelectCompact } from '@/components/ui/select';
import { api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { formatDateTime, formatRelative } from '@/lib/format';

/** Condense a user-agent into something a person can scan in a table cell. */
function describeAgent(userAgent: string | null): string {
  if (!userAgent) return 'Unknown client';

  const browser =
    /Edg\//.test(userAgent) ? 'Edge'
    : /OPR\//.test(userAgent) ? 'Opera'
    : /Chrome\//.test(userAgent) ? 'Chrome'
    : /Firefox\//.test(userAgent) ? 'Firefox'
    : /Safari\//.test(userAgent) ? 'Safari'
    : 'Browser';

  const platform =
    /Windows/.test(userAgent) ? 'Windows'
    : /Macintosh|Mac OS/.test(userAgent) ? 'macOS'
    : /Android/.test(userAgent) ? 'Android'
    : /iPhone|iPad/.test(userAgent) ? 'iOS'
    : /Linux/.test(userAgent) ? 'Linux'
    : '';

  return platform ? `${browser} on ${platform}` : browser;
}

export default function AdminSessionsPage(): React.ReactElement {
  const { hasPermission } = useAuth();
  const canRevoke = hasPermission(PERMISSIONS.SESSION_REVOKE_ANY);

  const [query, setQuery] = React.useState<DataTableQuery>({
    ...DEFAULT_QUERY,
    sortBy: 'lastActivityAt',
    sortDir: 'desc',
  });
  const [status, setStatus] = React.useState('');
  const [notice, setNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = React.useState<AdminSessionRow | null>(null);

  const { data, refreshing, error, reload } = useAsyncData(
    () =>
      api.listAllSessions({
        page: query.page,
        pageSize: query.pageSize,
        sortBy: query.sortBy ?? 'lastActivityAt',
        sortDir: query.sortDir,
        ...(query.search ? { search: query.search } : {}),
        ...(status ? { status } : {}),
      }),
    [query, status],
  );

  const columns: Column<AdminSessionRow>[] = [
    {
      key: 'user',
      header: 'User',
      sortKey: 'email',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <span className="font-medium">{row.fullName}</span>
            <RoleBadge role={row.role} />
          </div>
          <p className="text-xs text-muted-foreground">{row.email}</p>
        </div>
      ),
    },
    {
      key: 'device',
      header: 'Device',
      render: (row) => (
        <div className="space-y-0.5">
          <p className="text-sm">{row.deviceName ?? describeAgent(row.userAgent)}</p>
          <p className="text-xs text-muted-foreground">{row.platform ?? 'unknown platform'}</p>
        </div>
      ),
    },
    {
      key: 'ip',
      header: 'Address',
      hideOnMobile: true,
      render: (row) => (
        <span className="font-mono text-xs text-muted-foreground">{row.ipAddress ?? '-'}</span>
      ),
    },
    {
      key: 'activity',
      header: 'Last activity',
      sortKey: 'lastActivityAt',
      render: (row) => (
        <span className="text-sm text-muted-foreground">{formatRelative(row.lastActivityAt)}</span>
      ),
    },
    {
      key: 'started',
      header: 'Started',
      sortKey: 'createdAt',
      hideOnMobile: true,
      render: (row) => (
        <span className="text-sm text-muted-foreground">{formatRelative(row.createdAt)}</span>
      ),
    },
    {
      key: 'expires',
      header: 'Expires',
      sortKey: 'expiresAt',
      hideOnMobile: true,
      render: (row) => (
        <span className="whitespace-nowrap text-xs text-muted-foreground">
          {formatDateTime(row.expiresAt)}
        </span>
      ),
    },
    ...(canRevoke
      ? [
          {
            key: 'actions',
            header: '',
            headerClassName: 'text-right',
            className: 'text-right',
            render: (row: AdminSessionRow) => (
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                onClick={() => setRevokeTarget(row)}
              >
                <LogOut aria-hidden />
                End
              </Button>
            ),
          } satisfies Column<AdminSessionRow>,
        ]
      : []),
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Sessions"
        description="Signed-in clients across the whole tenant. Ending a session takes effect on the next request, not at token expiry."
      />

      <Feedback notice={notice} error={actionError ?? error} onDismiss={() => setNotice(null)} />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          icon={MonitorSmartphone}
          label={status ? 'Matching sessions' : 'Active sessions'}
          value={(data?.total ?? 0).toLocaleString()}
        />
        <StatCard
          label="Distinct users"
          value={new Set((data?.items ?? []).map((row) => row.userId)).size}
          hint="on this page"
        />
        <StatCard
          label="Distinct addresses"
          value={new Set((data?.items ?? []).map((row) => row.ipAddress).filter(Boolean)).size}
          hint="on this page"
        />
      </div>

      <DataTable
        columns={columns}
        rows={data?.items ?? null}
        total={data?.total ?? 0}
        query={query}
        onQueryChange={setQuery}
        rowKey={(row) => row.id}
        refreshing={refreshing}
        searchPlaceholder="Search by user or address"
        emptyMessage="No sessions match these filters."
        caption="Sessions"
        toolbar={
          <SelectCompact
            value={status}
            onChange={(event) => {
              setStatus(event.target.value);
              setQuery((current) => ({ ...current, page: 1 }));
            }}
            aria-label="Filter by session status"
            className="w-auto"
          >
            <option value="">Active only</option>
            <option value="revoked">Revoked</option>
            <option value="expired">Expired</option>
            <option value="rotated">Rotated</option>
          </SelectCompact>
        }
      />

      <ConfirmDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => !open && setRevokeTarget(null)}
        title="End this session?"
        confirmLabel="End session"
        description={
          <p>
            <strong>{revokeTarget?.fullName}</strong> will be signed out on{' '}
            {revokeTarget?.deviceName ?? 'this device'}. Their other sessions are unaffected, and
            they can sign in again straight away unless the account is also locked.
          </p>
        }
        onConfirm={async () => {
          if (!revokeTarget) return;
          setActionError(null);
          try {
            await api.revokeSessionById(revokeTarget.id);
            setNotice(`Ended ${revokeTarget.fullName}'s session.`);
            await reload();
          } catch (caught) {
            setActionError(messageOf(caught, 'Could not end that session.'));
            throw caught;
          }
        }}
      />
    </div>
  );
}

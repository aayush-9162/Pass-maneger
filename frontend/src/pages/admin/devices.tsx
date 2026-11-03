/**
 * Every registered device.
 *
 * "Remembered" devices are the ones that matter: a trusted device skips the
 * step-up prompt at sign-in, so a lost laptop that is still trusted is standing
 * authorisation. Revoking trust here also ends every session bound to it.
 */

import { Laptop, ShieldOff, Smartphone, Chrome, Monitor } from 'lucide-react';
import * as React from 'react';
import { useSearchParams } from 'react-router';

import { PERMISSIONS, type AdminDeviceRow } from '@passm/shared';

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
import { Button } from '@/components/ui/button';
import { SelectCompact } from '@/components/ui/select';
import { api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { formatDateTime, formatRelative } from '@/lib/format';
import { cn } from '@/lib/utils';

const PLATFORM_ICON = {
  web: Chrome,
  extension: Chrome,
  desktop: Monitor,
  mobile: Smartphone,
  unknown: Laptop,
} as const;

export default function AdminDevicesPage(): React.ReactElement {
  const { hasPermission } = useAuth();
  const canRevoke = hasPermission(PERMISSIONS.DEVICE_REVOKE_ANY);

  const [query, setQuery] = React.useState<DataTableQuery>({
    ...DEFAULT_QUERY,
    sortBy: 'lastUsedAt',
    sortDir: 'desc',
  });
  const [status, setStatus] = React.useState('');
  const [platform, setPlatform] = React.useState('');
  const [notice, setNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = React.useState<AdminDeviceRow | null>(null);

  // Preset from the security dashboard: /admin/devices?status=trusted
  const [searchParams] = useSearchParams();
  const presetStatus = searchParams.get('status');
  React.useEffect(() => {
    if (presetStatus) setStatus(presetStatus);
  }, [presetStatus]);

  const { data, refreshing, error, reload } = useAsyncData(
    () =>
      api.listAllDevices({
        page: query.page,
        pageSize: query.pageSize,
        sortBy: query.sortBy ?? 'lastUsedAt',
        sortDir: query.sortDir,
        ...(query.search ? { search: query.search } : {}),
        ...(status ? { status } : {}),
        ...(platform ? { platform } : {}),
      }),
    [query, status, platform],
  );

  const trustedOnPage = (data?.items ?? []).filter((row) => row.trusted).length;

  const columns: Column<AdminDeviceRow>[] = [
    {
      key: 'device',
      header: 'Device',
      sortKey: 'name',
      render: (row) => {
        const Icon = PLATFORM_ICON[row.platform as keyof typeof PLATFORM_ICON] ?? Laptop;

        return (
          <div className="flex items-center gap-3">
            <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-secondary">
              <Icon className="size-4" aria-hidden />
            </span>
            <div className="min-w-0 space-y-0.5">
              <p className="truncate font-medium">{row.name}</p>
              <p className="text-xs text-muted-foreground">{row.platform}</p>
            </div>
          </div>
        );
      },
    },
    {
      key: 'user',
      header: 'Owner',
      sortKey: 'email',
      render: (row) => (
        <div className="space-y-0.5">
          <p className="text-sm font-medium">{row.fullName}</p>
          <p className="text-xs text-muted-foreground">{row.email}</p>
        </div>
      ),
    },
    {
      key: 'trust',
      header: 'Trust',
      render: (row) => (
        <div className="space-y-0.5">
          <span
            className={cn(
              'rounded-full px-2 py-0.5 text-xs',
              row.trusted
                ? 'bg-success/15 text-success'
                : row.status === 'revoked'
                  ? 'bg-destructive/15 text-destructive'
                  : 'bg-secondary text-secondary-foreground',
            )}
          >
            {row.trusted ? 'Remembered' : row.status}
          </span>
          {row.trustExpiresAt && row.trusted && (
            <p className="text-[11px] text-muted-foreground">
              until {formatDateTime(row.trustExpiresAt)}
            </p>
          )}
        </div>
      ),
    },
    {
      key: 'sessions',
      header: 'Sessions',
      hideOnMobile: true,
      render: (row) => <span className="tabular-nums">{row.activeSessionCount}</span>,
    },
    {
      key: 'ip',
      header: 'Last address',
      hideOnMobile: true,
      render: (row) => (
        <span className="font-mono text-xs text-muted-foreground">
          {row.lastIpAddress ?? '-'}
        </span>
      ),
    },
    {
      key: 'lastUsed',
      header: 'Last used',
      sortKey: 'lastUsedAt',
      render: (row) => (
        <span className="text-sm text-muted-foreground">{formatRelative(row.lastUsedAt)}</span>
      ),
    },
    ...(canRevoke
      ? [
          {
            key: 'actions',
            header: '',
            headerClassName: 'text-right',
            className: 'text-right',
            render: (row: AdminDeviceRow) =>
              row.status === 'revoked' ? (
                <span className="text-xs text-muted-foreground">Revoked</span>
              ) : (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                  onClick={() => setRevokeTarget(row)}
                >
                  <ShieldOff aria-hidden />
                  Revoke
                </Button>
              ),
          } satisfies Column<AdminDeviceRow>,
        ]
      : []),
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Devices"
        description="Client installations known to the system. Fingerprints are a change detector here, never an authentication factor - they are trivially spoofable."
      />

      <Feedback notice={notice} error={actionError ?? error} onDismiss={() => setNotice(null)} />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard icon={Laptop} label="Devices" value={(data?.total ?? 0).toLocaleString()} />
        <StatCard label="Remembered on this page" value={trustedOnPage} />
        <StatCard
          label="With live sessions"
          value={(data?.items ?? []).filter((row) => row.activeSessionCount > 0).length}
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
        searchPlaceholder="Search by owner, name or address"
        emptyMessage="No devices match these filters."
        caption="Devices"
        toolbar={
          <>
            <SelectCompact
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by trust status"
              className="w-auto"
            >
              <option value="">All statuses</option>
              <option value="trusted">Remembered</option>
              <option value="registered">Registered</option>
              <option value="revoked">Revoked</option>
            </SelectCompact>

            <SelectCompact
              value={platform}
              onChange={(event) => {
                setPlatform(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by platform"
              className="w-auto"
            >
              <option value="">All platforms</option>
              <option value="web">Web</option>
              <option value="extension">Extension</option>
              <option value="desktop">Desktop</option>
              <option value="mobile">Mobile</option>
              <option value="unknown">Unknown</option>
            </SelectCompact>
          </>
        }
      />

      <ConfirmDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => !open && setRevokeTarget(null)}
        title="Revoke this device?"
        confirmLabel="Revoke device"
        description={
          <>
            <p>
              <strong>{revokeTarget?.name}</strong> loses its remembered status, and{' '}
              {revokeTarget?.activeSessionCount ?? 0} session
              {revokeTarget?.activeSessionCount === 1 ? '' : 's'} bound to it will end immediately.
            </p>
            <p>
              {revokeTarget?.fullName} can register it again at their next sign-in if it is still
              theirs. If it is lost, also reset their password.
            </p>
          </>
        }
        onConfirm={async () => {
          if (!revokeTarget) return;
          setActionError(null);
          try {
            await api.revokeDeviceById(revokeTarget.id);
            setNotice(`${revokeTarget.name} revoked.`);
            await reload();
          } catch (caught) {
            setActionError(messageOf(caught, 'Could not revoke that device.'));
            throw caught;
          }
        }}
      />
    </div>
  );
}

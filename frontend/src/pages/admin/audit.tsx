/**
 * Audit search.
 *
 * Append-only: there is no endpoint that deletes a row, and this page offers no
 * way to hide one. Every filter the compliance spec calls for is here - user,
 * date, IP, action, device - and the facet lists are read from the trail itself,
 * so the dropdowns offer what has actually happened rather than every action the
 * code can emit.
 *
 * ## What a manager sees, and does not
 *
 * Item-level access is recorded for organisational and personal vaults alike.
 * Managers see only the organisational half; personal-vault activity needs
 * `audit:read:personal`, which only administrators hold. That is applied by the
 * API, not here - this page just says so, because a compliance surface that
 * quietly filters rows without telling you is worse than one that does not
 * filter at all.
 *
 * ## Export
 *
 * Administrators only, and the export is itself audited. There is deliberately
 * no equivalent for vault contents - see `EXPORT_POLICY` in `@passm/shared`.
 */

import { Download, Info, Lock, ShieldCheck } from 'lucide-react';
import * as React from 'react';
import { useSearchParams } from 'react-router';

import {
  AUDIT_ACTIONS,
  AUDIT_ACTION_CATEGORY,
  PERMISSIONS,
  type AuditEntryView,
} from '@passm/shared';

import { Feedback, PageHeader, messageOf, useAsyncData } from '@/components/admin/admin-kit';
import {
  DataTable,
  DEFAULT_QUERY,
  type Column,
  type DataTableQuery,
} from '@/components/admin/data-table';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SelectCompact } from '@/components/ui/select';
import { api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { formatDateTime } from '@/lib/format';
import { cn } from '@/lib/utils';

/** Human labels, so a long table reads as prose rather than as identifiers. */
const ACTION_LABELS: Record<string, string> = {
  [AUDIT_ACTIONS.LOGIN_SUCCESS]: 'Signed in',
  [AUDIT_ACTIONS.LOGIN_FAILED]: 'Failed sign-in',
  [AUDIT_ACTIONS.LOGIN_BLOCKED_LOCKED]: 'Blocked — account locked',
  [AUDIT_ACTIONS.LOGOUT]: 'Signed out',
  [AUDIT_ACTIONS.TOKEN_REFRESHED]: 'Token refreshed',
  [AUDIT_ACTIONS.TOKEN_REUSE_DETECTED]: 'Refresh token replay detected',
  [AUDIT_ACTIONS.USER_CREATED]: 'User created',
  [AUDIT_ACTIONS.USER_UPDATED]: 'User updated',
  [AUDIT_ACTIONS.USER_DISABLED]: 'User suspended',
  [AUDIT_ACTIONS.USER_ROLE_CHANGED]: 'Role changed',
  [AUDIT_ACTIONS.USER_DELETED]: 'User deleted',
  [AUDIT_ACTIONS.USER_LOCKED]: 'Locked by administrator',
  [AUDIT_ACTIONS.USER_UNLOCKED]: 'Unlocked',
  [AUDIT_ACTIONS.USER_AUTO_PROVISIONED]: 'Account created by first sign-in',
  [AUDIT_ACTIONS.DEVICE_REGISTERED]: 'Device registered',
  [AUDIT_ACTIONS.DEVICE_TRUSTED]: 'Device remembered',
  [AUDIT_ACTIONS.DEVICE_TRUST_REVOKED]: 'Device trust revoked',
  [AUDIT_ACTIONS.DEVICE_FINGERPRINT_MISMATCH]: 'Device fingerprint changed',
  [AUDIT_ACTIONS.SESSION_REVOKED]: 'Session revoked',
  [AUDIT_ACTIONS.SESSION_REVOKED_ALL]: 'All sessions revoked',
  [AUDIT_ACTIONS.SHARED_VAULT_CREATED]: 'Group or password entry created',
  [AUDIT_ACTIONS.SHARED_VAULT_UPDATED]: 'Group updated',
  [AUDIT_ACTIONS.SHARED_VAULT_DELETED]: 'Group or password entry deleted',
  [AUDIT_ACTIONS.SHARED_VAULT_GRANT_ADDED]: 'Access granted',
  [AUDIT_ACTIONS.SHARED_VAULT_GRANT_UPDATED]: 'Access changed',
  [AUDIT_ACTIONS.SHARED_VAULT_GRANT_REVOKED]: 'Access revoked',
  [AUDIT_ACTIONS.ITEM_VIEWED]: 'Password viewed',
  [AUDIT_ACTIONS.ITEM_COPIED]: 'Password copied',
  [AUDIT_ACTIONS.ITEM_FILLED]: 'Password auto-filled',
  [AUDIT_ACTIONS.ITEM_CREATED]: 'Item created',
  [AUDIT_ACTIONS.ITEM_EDITED]: 'Password edited',
  [AUDIT_ACTIONS.ITEM_DELETED]: 'Password deleted',
  [AUDIT_ACTIONS.ITEM_RESTORED]: 'Item restored',
  [AUDIT_ACTIONS.ITEM_SHARED]: 'Password shared',
  [AUDIT_ACTIONS.ITEM_EXPORT_BLOCKED]: 'Export attempt blocked',
  [AUDIT_ACTIONS.ITEM_REVEAL_BLOCKED]: 'Reveal blocked by policy',
  [AUDIT_ACTIONS.ACCESS_REQUESTED]: 'Access requested',
  [AUDIT_ACTIONS.ACCESS_APPROVED]: 'Request approved',
  [AUDIT_ACTIONS.ACCESS_DENIED]: 'Request denied',
  [AUDIT_ACTIONS.ACCESS_CANCELLED]: 'Request withdrawn',
  [AUDIT_ACTIONS.PASSWORD_HEALTH_REPORTED]: 'Health report uploaded',
  [AUDIT_ACTIONS.AUDIT_EXPORTED]: 'Audit log exported',
};

/** Actions worth colouring in a long list. */
const NOTABLE = new Set<string>([
  AUDIT_ACTIONS.TOKEN_REUSE_DETECTED,
  AUDIT_ACTIONS.USER_LOCKED,
  AUDIT_ACTIONS.SHARED_VAULT_DELETED,
  AUDIT_ACTIONS.SHARED_VAULT_GRANT_REVOKED,
  AUDIT_ACTIONS.ITEM_EXPORT_BLOCKED,
  // A user pressing against the password-access policy is exactly the signal an
  // administrator wants to notice in a long list.
  AUDIT_ACTIONS.ITEM_REVEAL_BLOCKED,
]);

function MetadataCell({
  metadata,
}: {
  metadata: Record<string, unknown> | null;
}): React.ReactElement {
  if (!metadata || Object.keys(metadata).length === 0) {
    return <span className="text-muted-foreground">-</span>;
  }

  const entries = Object.entries(metadata).slice(0, 3);

  return (
    <div className="flex flex-wrap gap-1">
      {entries.map(([key, value]) => (
        <span
          key={key}
          className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[11px] text-secondary-foreground"
          title={`${key}: ${String(value)}`}
        >
          {key}={String(value).slice(0, 18)}
        </span>
      ))}
      {Object.keys(metadata).length > entries.length && (
        <span className="text-[11px] text-muted-foreground">
          +{Object.keys(metadata).length - entries.length}
        </span>
      )}
    </div>
  );
}

export default function AdminAuditPage(): React.ReactElement {
  const { hasPermission } = useAuth();
  const canExport = hasPermission(PERMISSIONS.AUDIT_EXPORT);
  const seesPersonal = hasPermission(PERMISSIONS.AUDIT_READ_PERSONAL);

  const [query, setQuery] = React.useState<DataTableQuery>({
    ...DEFAULT_QUERY,
    pageSize: 50,
    sortDir: 'desc',
  });

  const [action, setAction] = React.useState('');
  const [outcome, setOutcome] = React.useState('');
  const [ipAddress, setIpAddress] = React.useState('');
  const [deviceId, setDeviceId] = React.useState('');
  const [actorUserId, setActorUserId] = React.useState('');
  const [from, setFrom] = React.useState('');
  const [to, setTo] = React.useState('');
  const [sharedOnly, setSharedOnly] = React.useState(false);
  const [exporting, setExporting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);

  // Deep link from the security dashboard: /admin/audit?action=…
  const [searchParams] = useSearchParams();
  const presetAction = searchParams.get('action');
  React.useEffect(() => {
    if (presetAction) setAction(presetAction);
  }, [presetAction]);

  const { data: facets } = useAsyncData(() => api.auditFacets(90), []);
  const { data: usersData } = useAsyncData(
    () => api.listUsers({ pageSize: 100, sortBy: 'lastName', sortDir: 'asc' }),
    [],
  );

  const filters = React.useMemo(
    () => ({
      ...(query.search ? { search: query.search } : {}),
      ...(action ? { action } : {}),
      ...(outcome ? { outcome: outcome as 'success' | 'failure' } : {}),
      ...(ipAddress ? { ipAddress } : {}),
      ...(deviceId ? { deviceId } : {}),
      ...(actorUserId ? { actorUserId } : {}),
      ...(from ? { from: new Date(from).toISOString() } : {}),
      // A date input gives midnight; without this the upper bound would exclude
      // everything that happened on the day the user picked.
      ...(to ? { to: new Date(`${to}T23:59:59.999Z`).toISOString() } : {}),
      ...(sharedOnly ? { sharedOnly: true } : {}),
    }),
    [query.search, action, outcome, ipAddress, deviceId, actorUserId, from, to, sharedOnly],
  );

  const { data, refreshing, error: loadError } = useAsyncData(
    () => api.searchAudit({ ...filters, page: query.page, pageSize: query.pageSize, sortDir: query.sortDir }),
    [filters, query.page, query.pageSize, query.sortDir],
  );

  const runExport = async (format: 'csv' | 'json'): Promise<void> => {
    setExporting(true);
    setError(null);
    try {
      const { blob, filename } = await api.downloadAuditExport({ ...filters, format });

      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);

      setNotice(`Exported ${filename}. The export itself is recorded in the trail.`);
    } catch (caught) {
      setError(messageOf(caught, 'The export failed.'));
    } finally {
      setExporting(false);
    }
  };

  const columns: Column<AuditEntryView>[] = [
    {
      key: 'time',
      header: 'When',
      render: (row) => (
        <span className="whitespace-nowrap text-sm">{formatDateTime(row.createdAt)}</span>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (row) => (
        <div className="space-y-0.5">
          <div className="flex items-center gap-1.5">
            <p className={cn('text-sm', NOTABLE.has(row.action) && 'font-semibold text-destructive')}>
              {ACTION_LABELS[row.action] ?? row.action}
            </p>
            {!row.isSharedResource && row.action.startsWith('item.') && (
              <Lock className="size-3 text-muted-foreground" aria-label="Personal vault" />
            )}
          </div>
          <p className="font-mono text-[11px] text-muted-foreground">{row.action}</p>
        </div>
      ),
    },
    {
      key: 'outcome',
      header: 'Outcome',
      render: (row) => (
        <span
          className={cn(
            'rounded-full px-2 py-0.5 text-xs',
            row.outcome === 'success'
              ? 'bg-success/15 text-success'
              : 'bg-destructive/15 text-destructive',
          )}
        >
          {row.outcome}
        </span>
      ),
    },
    {
      key: 'actor',
      header: 'Who',
      render: (row) => (
        <div className="space-y-0.5">
          <p className="text-sm">
            {row.actorName ?? row.actorEmail ?? (
              <span className="text-muted-foreground">anonymous</span>
            )}
          </p>
          {row.actorName && row.actorEmail && (
            <p className="text-[11px] text-muted-foreground">{row.actorEmail}</p>
          )}
        </div>
      ),
    },
    {
      key: 'target',
      header: 'On',
      hideOnMobile: true,
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.resourceName ?? row.targetName ?? row.targetEmail ?? '-'}
        </span>
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
      key: 'device',
      header: 'Device',
      hideOnMobile: true,
      render: (row) => (
        <span className="text-xs text-muted-foreground">{row.deviceName ?? '-'}</span>
      ),
    },
    {
      key: 'metadata',
      header: 'Context',
      hideOnMobile: true,
      render: (row) => <MetadataCell metadata={row.metadata} />,
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit log"
        description="Append-only. Nothing in this application deletes a row from it."
        actions={
          canExport && (
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={exporting || !data?.items.length}
                onClick={() => void runExport('csv')}
              >
                <Download aria-hidden />
                Export CSV
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={exporting || !data?.items.length}
                onClick={() => void runExport('json')}
              >
                JSON
              </Button>
            </div>
          )
        }
      />

      <Feedback notice={notice} error={error ?? loadError} onDismiss={() => setNotice(null)} />

      {!seesPersonal ? (
        <Alert>
          <Info aria-hidden />
          <AlertTitle>You are seeing the organisational trail</AlertTitle>
          <AlertDescription>
            Item access inside people&apos;s own personal vaults is excluded — that is a record of
            their private activity, and only administrators can see it. Everything concerning a
            shared vault is shown in full.
          </AlertDescription>
        </Alert>
      ) : (
        <Alert>
          <ShieldCheck aria-hidden />
          <AlertTitle>Full trail, including personal vaults</AlertTitle>
          <AlertDescription>
            Rows marked with a lock concern somebody&apos;s own vault rather than shared company
            property. Exporting is recorded in the trail as well.
          </AlertDescription>
        </Alert>
      )}

      <DataTable
        columns={columns}
        rows={data?.items ?? null}
        total={data?.total ?? 0}
        query={query}
        onQueryChange={setQuery}
        rowKey={(row) => row.id}
        refreshing={refreshing}
        searchPlaceholder="Search by email or IP address"
        emptyMessage="No entries match these filters."
        caption="Audit trail"
        toolbar={
          <>
            <SelectCompact
              value={action}
              onChange={(event) => {
                setAction(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by action"
              className="w-auto"
            >
              <option value="">All actions</option>
              {Object.entries(AUDIT_ACTION_CATEGORY).map(([prefix, label]) => {
                // Facets come from the trail, so only actions that have actually
                // occurred are offered.
                const options = (facets?.actions ?? []).filter((a) =>
                  a.action.startsWith(`${prefix}.`),
                );
                if (options.length === 0) return null;

                return (
                  <optgroup key={prefix} label={label}>
                    <option value={`${prefix}.`}>All {label.toLowerCase()}</option>
                    {options.map((entry) => (
                      <option key={entry.action} value={entry.action}>
                        {ACTION_LABELS[entry.action] ?? entry.action} ({entry.count})
                      </option>
                    ))}
                  </optgroup>
                );
              })}
            </SelectCompact>

            <SelectCompact
              value={actorUserId}
              onChange={(event) => {
                setActorUserId(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by user"
              className="w-auto"
            >
              <option value="">Anyone</option>
              {(usersData?.items ?? []).map((user) => (
                <option key={user.id} value={user.id}>
                  {user.fullName}
                </option>
              ))}
            </SelectCompact>

            <SelectCompact
              value={ipAddress}
              onChange={(event) => {
                setIpAddress(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by address"
              className="w-auto"
            >
              <option value="">Any address</option>
              {(facets?.addresses ?? []).map((entry) => (
                <option key={entry.ipAddress} value={entry.ipAddress}>
                  {entry.ipAddress} ({entry.count})
                </option>
              ))}
            </SelectCompact>

            <SelectCompact
              value={deviceId}
              onChange={(event) => {
                setDeviceId(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by device"
              className="w-auto"
            >
              <option value="">Any device</option>
              {(facets?.devices ?? []).map((entry) => (
                <option key={entry.deviceId} value={entry.deviceId}>
                  {entry.name} ({entry.count})
                </option>
              ))}
            </SelectCompact>

            <SelectCompact
              value={outcome}
              onChange={(event) => {
                setOutcome(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by outcome"
              className="w-auto"
            >
              <option value="">Any outcome</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
            </SelectCompact>

            <Input
              type="date"
              value={from}
              onChange={(event) => {
                setFrom(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="From date"
              className="h-8 w-auto text-xs"
            />
            <Input
              type="date"
              value={to}
              onChange={(event) => {
                setTo(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="To date"
              className="h-8 w-auto text-xs"
            />

            {seesPersonal && (
              <label className="flex shrink-0 items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={sharedOnly}
                  onChange={(event) => {
                    setSharedOnly(event.target.checked);
                    setQuery((current) => ({ ...current, page: 1 }));
                  }}
                  className="size-4 rounded border-input"
                />
                Shared only
              </label>
            )}
          </>
        }
      />
    </div>
  );
}

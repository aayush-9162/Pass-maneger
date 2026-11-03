/**
 * Security dashboard.
 *
 * Alerts come first and are deliberately few. A panel that emits everything it
 * can detect teaches people to scroll past it; six detections that each have an
 * obvious response get acted on. Everything below the alerts is the evidence
 * behind them.
 */

import { AlertTriangle, Info, Lock, ShieldAlert, ShieldCheck, Unlock } from 'lucide-react';
import { Link } from 'react-router';
import * as React from 'react';

import {
  PERMISSIONS,
  SECURITY_ALERT_LEVEL,
  type SecurityAlert,
  type SecurityDashboard,
} from '@passm/shared';

import {
  ConfirmDialog,
  Feedback,
  PageHeader,
  StatCard,
  messageOf,
  useAsyncData,
} from '@/components/admin/admin-kit';
import { AreaChart } from '@/components/charts';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { SelectCompact } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { formatDateTime, formatRelative } from '@/lib/format';
import { cn } from '@/lib/utils';

const WINDOW_OPTIONS = [7, 14, 30, 60, 90];

function AlertCard({ alert }: { alert: SecurityAlert }): React.ReactElement {
  const style = {
    [SECURITY_ALERT_LEVEL.CRITICAL]: {
      border: 'border-destructive/40',
      badge: 'bg-destructive/15 text-destructive',
      icon: ShieldAlert,
    },
    [SECURITY_ALERT_LEVEL.WARNING]: {
      border: 'border-warning/40',
      badge: 'bg-warning/15 text-warning',
      icon: AlertTriangle,
    },
    [SECURITY_ALERT_LEVEL.INFO]: {
      border: 'border-border',
      badge: 'bg-secondary text-secondary-foreground',
      icon: Info,
    },
  }[alert.level];

  const Icon = style.icon;

  return (
    <Card className={cn('border', style.border)}>
      <CardContent className="flex flex-col gap-3 p-5 sm:flex-row sm:items-start">
        <span
          className={cn(
            'flex size-9 shrink-0 items-center justify-center rounded-lg',
            style.badge,
          )}
        >
          <Icon className="size-4.5" aria-hidden />
        </span>

        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-medium">{alert.title}</h3>
            <span
              className={cn(
                'rounded-full px-2 py-0.5 text-xs font-medium tabular-nums',
                style.badge,
              )}
            >
              {alert.count.toLocaleString()}
            </span>
          </div>
          <p className="text-sm text-muted-foreground">{alert.detail}</p>
        </div>

        {alert.actionHref && (
          <Button asChild variant="outline" size="sm" className="shrink-0">
            <Link to={alert.actionHref}>{alert.actionLabel ?? 'Review'}</Link>
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

export default function SecurityDashboardPage(): React.ReactElement {
  const { hasPermission } = useAuth();
  const canUnlock = hasPermission(PERMISSIONS.USER_LOCK);

  const [windowDays, setWindowDays] = React.useState(30);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);
  const [unlockTarget, setUnlockTarget] = React.useState<{ id: string; name: string } | null>(null);

  const { data, error, reload } = useAsyncData<SecurityDashboard>(
    () => api.getSecurityDashboard(windowDays),
    [windowDays],
  );

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Security" />
        <Feedback notice={null} error={error} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="space-y-6">
        <PageHeader title="Security" />
        <Skeleton className="h-24" />
        <Skeleton className="h-72" />
      </div>
    );
  }

  const totalSuccess = data.loginOutcomes.reduce((sum, point) => sum + point.success, 0);
  const totalFailure = data.loginOutcomes.reduce((sum, point) => sum + point.failure, 0);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Security"
        description={`Detections over the last ${data.windowDays} days. Generated ${formatDateTime(
          data.generatedAt,
        )}.`}
        actions={
          <SelectCompact
            value={String(windowDays)}
            onChange={(event) => setWindowDays(Number(event.target.value))}
            aria-label="Reporting period"
          >
            {WINDOW_OPTIONS.map((days) => (
              <option key={days} value={days}>
                Last {days} days
              </option>
            ))}
          </SelectCompact>
        }
      />

      <Feedback notice={notice} error={actionError} onDismiss={() => setNotice(null)} />

      {data.alerts.length === 0 ? (
        <Card>
          <CardContent className="flex items-center gap-3 p-5">
            <span className="flex size-9 items-center justify-center rounded-lg bg-success/15 text-success">
              <ShieldCheck className="size-4.5" aria-hidden />
            </span>
            <div>
              <p className="font-medium">Nothing needs attention</p>
              <p className="text-sm text-muted-foreground">
                No replayed tokens, no spraying, no locked accounts and no vaults waiting on a key
                in this period.
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {data.alerts.map((alert) => (
            <AlertCard key={alert.id} alert={alert} />
          ))}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Token replays"
          value={data.tokenReuseEvents}
          hint="Sessions revoked automatically"
          tone={data.tokenReuseEvents > 0 ? 'destructive' : 'success'}
        />
        <StatCard
          label="Fingerprint changes"
          value={data.fingerprintMismatches}
          hint="Signal only - never an auth factor"
          tone={data.fingerprintMismatches > 0 ? 'warning' : 'default'}
        />
        <StatCard
          label="Idle sessions"
          value={data.staleSessions}
          hint="Active but unused for 14 days"
          tone={data.staleSessions > 0 ? 'warning' : 'default'}
        />
        <StatCard
          label="Dormant devices"
          value={data.dormantTrustedDevices}
          hint="Trusted, unused for 90 days"
          tone={data.dormantTrustedDevices > 0 ? 'warning' : 'default'}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Sign-in outcomes</CardTitle>
          <CardDescription>
            {totalSuccess.toLocaleString()} succeeded, {totalFailure.toLocaleString()} failed.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AreaChart
            series={[
              {
                label: 'Successful',
                points: data.loginOutcomes.map((point) => ({
                  date: point.date,
                  value: point.success,
                })),
                color: 'hsl(var(--success))',
              },
              {
                label: 'Failed',
                points: data.loginOutcomes.map((point) => ({
                  date: point.date,
                  value: point.failure,
                })),
                color: 'hsl(var(--destructive))',
              },
            ]}
          />
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Sources of failed sign-ins</CardTitle>
            <CardDescription>
              The column that matters is <strong>accounts</strong>: many failures against one
              account is a forgotten password, the same spread across many is spraying.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Address</TableHead>
                  <TableHead className="text-right">Attempts</TableHead>
                  <TableHead className="text-right">Accounts</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.topFailedAddresses.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="py-8 text-center text-sm text-muted-foreground">
                      No failed sign-ins in this period.
                    </TableCell>
                  </TableRow>
                ) : (
                  data.topFailedAddresses.map((row) => (
                    <TableRow key={row.ipAddress}>
                      <TableCell className="font-mono text-xs">{row.ipAddress}</TableCell>
                      <TableCell className="text-right tabular-nums">{row.attempts}</TableCell>
                      <TableCell
                        className={cn(
                          'text-right tabular-nums',
                          row.distinctAccounts >= 5 && 'font-semibold text-destructive',
                        )}
                      >
                        {row.distinctAccounts}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Most-targeted accounts</CardTitle>
            <CardDescription>Addresses attracting the most failed attempts.</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead className="text-right">Attempts</TableHead>
                  <TableHead className="text-right">Last</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.topFailedAccounts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="py-8 text-center text-sm text-muted-foreground">
                      No failed sign-ins in this period.
                    </TableCell>
                  </TableRow>
                ) : (
                  data.topFailedAccounts.map((row) => (
                    <TableRow key={row.email}>
                      <TableCell className="max-w-[14rem] truncate">{row.email}</TableCell>
                      <TableCell className="text-right tabular-nums">{row.attempts}</TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">
                        {formatRelative(row.lastAttemptAt)}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Locked accounts</CardTitle>
          <CardDescription>
            A lockout with an expiry lifts itself; an administrative lock stays until someone
            removes it.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Locked until</TableHead>
                {canUnlock && <TableHead className="text-right">Action</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.lockedAccounts.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={canUnlock ? 4 : 3}
                    className="py-8 text-center text-sm text-muted-foreground"
                  >
                    Nobody is locked out.
                  </TableCell>
                </TableRow>
              ) : (
                data.lockedAccounts.map((row) => (
                  <TableRow key={row.userId}>
                    <TableCell>
                      <div className="space-y-0.5">
                        <p className="font-medium">{row.fullName}</p>
                        <p className="text-xs text-muted-foreground">{row.email}</p>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {row.lockedUntil ? (
                        // A century out is how an indefinite administrative lock
                        // is represented; showing that date would be nonsense.
                        new Date(row.lockedUntil).getFullYear() > new Date().getFullYear() + 5 ? (
                          <span className="inline-flex items-center gap-1">
                            <Lock className="size-3.5" aria-hidden />
                            Indefinite
                          </span>
                        ) : (
                          formatDateTime(row.lockedUntil)
                        )
                      ) : (
                        '-'
                      )}
                    </TableCell>
                    {canUnlock && (
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setUnlockTarget({ id: row.userId, name: row.fullName })}
                        >
                          <Unlock aria-hidden />
                          Unlock
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={unlockTarget !== null}
        onOpenChange={(open) => !open && setUnlockTarget(null)}
        title={`Unlock ${unlockTarget?.name ?? ''}?`}
        description={
          <p>
            They will be able to sign in again immediately. The unlock is recorded in the audit
            trail.
          </p>
        }
        confirmLabel="Unlock account"
        destructive={false}
        onConfirm={async () => {
          if (!unlockTarget) return;
          setActionError(null);
          try {
            await api.unlockUser(unlockTarget.id);
            setNotice(`${unlockTarget.name} can sign in again.`);
            await reload();
          } catch (caught) {
            setActionError(messageOf(caught, 'Could not unlock that account.'));
            throw caught;
          }
        }}
      />
    </div>
  );
}

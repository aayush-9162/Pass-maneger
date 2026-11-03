/**
 * Administrative dashboard.
 *
 * Every number here is metadata: account states, row counts, session and device
 * records. Nothing on this page reads a stored password.
 */

import {
  KeyRound,
  MonitorSmartphone,
  ShieldAlert,
  UserPlus,
  Users,
  UsersRound,
} from 'lucide-react';
import { Link } from 'react-router';
import * as React from 'react';

import { ROLES, ROLE_LABEL, type AdminDashboardStats } from '@passm/shared';

import { Feedback, PageHeader, StatCard, useAsyncData } from '@/components/admin/admin-kit';
import { AreaChart, BarChart, DonutChart, Sparkline } from '@/components/charts';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { SelectCompact } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api-client';
import { formatDateTime } from '@/lib/format';

const WINDOW_OPTIONS = [7, 14, 30, 60, 90];

export default function AdminDashboardPage(): React.ReactElement {
  const [windowDays, setWindowDays] = React.useState(30);

  const { data, error, refreshing } = useAsyncData<AdminDashboardStats>(
    () => api.getDashboard(windowDays),
    [windowDays],
  );

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" />
        <Feedback notice={null} error={error} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="space-y-6">
        <PageHeader title="Dashboard" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-28" />
          ))}
        </div>
        <div className="grid gap-6 lg:grid-cols-2">
          <Skeleton className="h-72" />
          <Skeleton className="h-72" />
        </div>
      </div>
    );
  }

  const { users, vaults, access, activity } = data;

  const signInTotal = activity.logins.reduce((sum, point) => sum + point.value, 0);
  const failureTotal = activity.failedLogins.reduce((sum, point) => sum + point.value, 0);

  // Share of sign-in attempts that failed. A useful single number: a healthy
  // tenant sits in the low single digits, and a jump is visible immediately.
  const failureRate =
    signInTotal + failureTotal === 0
      ? 0
      : Math.round((failureTotal / (signInTotal + failureTotal)) * 100);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Dashboard"
        description={`Counts only - no password appears on this page. Generated ${formatDateTime(
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

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Users}
          label="Accounts"
          value={users.total.toLocaleString()}
          hint={`${users.active} active · ${users.pending} pending · ${users.locked} locked`}
        />
        <StatCard
          icon={UserPlus}
          label="Active in 30 days"
          value={users.activeLast30Days.toLocaleString()}
          hint={`${users.newLast30Days} joined in the same period`}
          chart={<Sparkline points={activity.logins} width={72} height={28} />}
        />
        <StatCard
          icon={KeyRound}
          label="Stored items"
          value={vaults.totalItems.toLocaleString()}
          hint={`in ${vaults.groups} group${vaults.groups === 1 ? '' : 's'} or standing alone`}
        />
        <StatCard
          icon={MonitorSmartphone}
          label="Active sessions"
          value={access.activeSessions.toLocaleString()}
          hint={`${access.trustedDevices} of ${access.knownDevices} devices remembered`}
          tone={access.activeSessions > 0 ? 'default' : 'warning'}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Sign-in activity</CardTitle>
            <CardDescription>
              {signInTotal.toLocaleString()} successful and {failureTotal.toLocaleString()} failed
              attempts over {windowDays} days - a {failureRate}% failure rate.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AreaChart
              series={[
                { label: 'Successful', points: activity.logins, color: 'hsl(var(--success))' },
                {
                  label: 'Failed',
                  points: activity.failedLogins,
                  color: 'hsl(var(--destructive))',
                },
              ]}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Roles</CardTitle>
            <CardDescription>Who holds what across the tenant.</CardDescription>
          </CardHeader>
          <CardContent>
            <DonutChart
              size={140}
              centerValue={users.total}
              centerLabel="accounts"
              slices={[
                { label: ROLE_LABEL[ROLES.ADMIN], value: users.byRole[ROLES.ADMIN] ?? 0 },
                { label: ROLE_LABEL[ROLES.EMPLOYEE], value: users.byRole[ROLES.EMPLOYEE] ?? 0 },
              ]}
            />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>What is stored</CardTitle>
            <CardDescription>
              Item counts by type, personal and shared combined. The type is the only thing about
              an item the server can see.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <BarChart bars={vaults.itemsByType} emptyMessage="No items stored yet." />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Vault activity</CardTitle>
            <CardDescription>Items created or changed per day.</CardDescription>
          </CardHeader>
          <CardContent>
            <AreaChart
              series={[{ label: 'Item writes', points: activity.vaultWrites }]}
              height={150}
              emptyMessage="No vault writes in this period."
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Groups</CardTitle>
            <CardDescription>Password groups and individually shared entries.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1">
              <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
                <UsersRound className="size-3.5" aria-hidden />
                Groups
              </p>
              <p className="text-2xl font-semibold tabular-nums">{vaults.groups}</p>
            </div>

            <div className="flex flex-wrap gap-2 pt-2">
              <Button asChild variant="outline" size="sm">
                <Link to="/shared">Passwords</Link>
              </Button>
              <Button asChild variant="outline" size="sm">
                <Link to="/admin/security">
                  <ShieldAlert aria-hidden />
                  Security
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {refreshing && (
        <p className="text-center text-xs text-muted-foreground">Refreshing…</p>
      )}
    </div>
  );
}

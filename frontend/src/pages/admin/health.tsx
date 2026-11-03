/**
 * Password health, org-wide.
 *
 * Every number on this page was computed in somebody's browser, because that is
 * the only place a password exists in plaintext. The server stores counts,
 * scores and flags; it has never seen a password and cannot check one.
 *
 * Two consequences are shown prominently rather than hidden:
 *
 *  - **Unassessed users are not healthy users.** Someone who has never opened
 *    their vault in a client that runs the check contributes nothing, and a
 *    dashboard that quietly excluded them would improve every time somebody
 *    stopped looking.
 *  - **Stale reports are labelled.** A report is a snapshot from the last unlock,
 *    not a live reading.
 */

import { AlertTriangle, Copy, Repeat, ShieldQuestion, Clock } from 'lucide-react';
import * as React from 'react';

import {
  HEALTH_ISSUE,
  HEALTH_ISSUE_LABEL,
  type PasswordHealthReport,
  type PasswordHealthSummary,
} from '@passm/shared';

import { Feedback, PageHeader, StatCard, useAsyncData } from '@/components/admin/admin-kit';
import {
  DataTable,
  DEFAULT_QUERY,
  type Column,
  type DataTableQuery,
} from '@/components/admin/data-table';
import { BarChart } from '@/components/charts';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { SelectCompact } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api-client';
import { formatRelative } from '@/lib/format';
import { cn } from '@/lib/utils';

/** A report older than this is shown as stale. Mirrors the API's window. */
const STALE_DAYS = 30;

function scoreTone(score: number): string {
  if (score >= 90) return 'text-success';
  if (score >= 75) return 'text-foreground';
  if (score >= 50) return 'text-warning';
  return 'text-destructive';
}

function ScoreBar({ score }: { score: number }): React.ReactElement {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-secondary">
        <div
          className={cn(
            'h-full rounded-full',
            score >= 90
              ? 'bg-success'
              : score >= 75
                ? 'bg-primary'
                : score >= 50
                  ? 'bg-warning'
                  : 'bg-destructive',
          )}
          style={{ width: `${Math.max(2, score)}%` }}
        />
      </div>
      <span className={cn('w-8 text-right text-sm font-medium tabular-nums', scoreTone(score))}>
        {score}
      </span>
    </div>
  );
}

function isStale(generatedAt: string): boolean {
  return Date.now() - new Date(generatedAt).getTime() > STALE_DAYS * 86_400_000;
}

export default function AdminHealthPage(): React.ReactElement {
  const [query, setQuery] = React.useState<DataTableQuery>({
    ...DEFAULT_QUERY,
    sortBy: 'healthScore',
    sortDir: 'asc',
  });
  const [issueFilter, setIssueFilter] = React.useState('');

  const { data: summary, error: summaryError } = useAsyncData<PasswordHealthSummary>(
    () => api.getHealthSummary(),
    [],
  );

  const { data, refreshing, error } = useAsyncData(
    () =>
      api.listHealthReports({
        page: query.page,
        pageSize: query.pageSize,
        sortBy: query.sortBy ?? 'healthScore',
        sortDir: query.sortDir,
        ...(query.search ? { search: query.search } : {}),
        ...(issueFilter ? { issue: issueFilter } : {}),
      }),
    [query, issueFilter],
  );

  const columns: Column<PasswordHealthReport>[] = [
    {
      key: 'user',
      header: 'User',
      sortKey: 'lastName',
      render: (row) => (
        <div className="space-y-0.5">
          <p className="font-medium">{row.fullName}</p>
          <p className="text-xs text-muted-foreground">{row.email}</p>
        </div>
      ),
    },
    {
      key: 'score',
      header: 'Score',
      sortKey: 'healthScore',
      render: (row) => <ScoreBar score={row.healthScore} />,
    },
    {
      key: 'weak',
      header: 'Weak',
      sortKey: 'weakCount',
      render: (row) => (
        <span className={cn('tabular-nums', row.weakCount > 0 && 'text-warning')}>
          {row.weakCount}
        </span>
      ),
    },
    {
      key: 'reused',
      header: 'Reused',
      sortKey: 'reusedCount',
      render: (row) => (
        <span className={cn('tabular-nums', row.reusedCount > 0 && 'text-warning')}>
          {row.reusedCount}
        </span>
      ),
    },
    {
      key: 'old',
      header: 'Old',
      hideOnMobile: true,
      render: (row) => <span className="tabular-nums">{row.oldCount}</span>,
    },
    {
      key: 'compromised',
      header: 'Breached',
      sortKey: 'compromisedCount',
      render: (row) =>
        !row.breachCheckPerformed ? (
          <span className="text-xs text-muted-foreground" title="No breach check was run">
            not checked
          </span>
        ) : (
          <span
            className={cn('tabular-nums', row.compromisedCount > 0 && 'font-semibold text-destructive')}
          >
            {row.compromisedCount}
          </span>
        ),
    },
    {
      key: 'items',
      header: 'Assessed',
      hideOnMobile: true,
      render: (row) => (
        <span className="text-sm tabular-nums text-muted-foreground">
          {row.assessedItems} / {row.totalItems}
        </span>
      ),
    },
    {
      key: 'generated',
      header: 'Reported',
      sortKey: 'generatedAt',
      render: (row) => (
        <span
          className={cn(
            'inline-flex items-center gap-1 text-sm',
            isStale(row.generatedAt) ? 'text-warning' : 'text-muted-foreground',
          )}
        >
          {isStale(row.generatedAt) && <Clock className="size-3.5" aria-hidden />}
          {formatRelative(row.generatedAt)}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Password health"
        description="Computed in each user's browser after they unlock their vault, then uploaded as counts and flags. No password or hash of one is ever sent."
      />

      <Feedback notice={null} error={error ?? summaryError} />

      {summary === null ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-28" />
          ))}
        </div>
      ) : (
        <>
          {summary.unreportedUsers > 0 && (
            <Alert variant="warning">
              <ShieldQuestion aria-hidden />
              <AlertTitle>
                {summary.unreportedUsers} account
                {summary.unreportedUsers === 1 ? ' has' : 's have'} never been assessed
              </AlertTitle>
              <AlertDescription>
                Their vaults are <strong>unassessed, not healthy</strong>. A report is produced the
                next time they unlock in the web console; nothing here can produce one on their
                behalf, because nothing but their own client can read their passwords.
              </AlertDescription>
            </Alert>
          )}

          {summary.compromisedCount > 0 && (
            <Alert variant="destructive">
              <AlertTriangle aria-hidden />
              <AlertTitle>
                {summary.compromisedCount} credential
                {summary.compromisedCount === 1 ? '' : 's'} found in a breach corpus
              </AlertTitle>
              <AlertDescription>
                These are known to attackers. Rotating them is the only fix - changing the master
                password does not help, because the exposure is at the site, not here.
              </AlertDescription>
            </Alert>
          )}

          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Average score"
              value={summary.averageHealthScore}
              hint={`across ${summary.reportedUsers} reporting user${
                summary.reportedUsers === 1 ? '' : 's'
              }`}
              tone={
                summary.averageHealthScore >= 80
                  ? 'success'
                  : summary.averageHealthScore >= 60
                    ? 'warning'
                    : 'destructive'
              }
            />
            <StatCard
              icon={AlertTriangle}
              label="Weak passwords"
              value={summary.weakCount.toLocaleString()}
              hint={`of ${summary.totalAssessedItems.toLocaleString()} assessed`}
              tone={summary.weakCount > 0 ? 'warning' : 'success'}
            />
            <StatCard
              icon={Copy}
              label="Reused passwords"
              value={summary.reusedCount.toLocaleString()}
              hint="one breach becomes several"
              tone={summary.reusedCount > 0 ? 'warning' : 'success'}
            />
            <StatCard
              icon={Repeat}
              label="Older than a year"
              value={summary.oldCount.toLocaleString()}
              hint={`${summary.staleReports} report${
                summary.staleReports === 1 ? '' : 's'
              } are themselves stale`}
            />
          </div>

          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Score distribution</CardTitle>
                <CardDescription>
                  How many people fall in each band. Worst first.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <BarChart
                  bars={summary.scoreDistribution.map((bucket, index) => ({
                    label: bucket.bucket,
                    value: bucket.users,
                    color:
                      index === 0
                        ? 'hsl(var(--destructive))'
                        : index === 1
                          ? 'hsl(var(--warning))'
                          : 'hsl(var(--success))',
                  }))}
                  valueFormatter={(value) => `${value} user${value === 1 ? '' : 's'}`}
                  emptyMessage="No reports uploaded yet."
                />
              </CardContent>
            </Card>
          </div>
        </>
      )}

      <DataTable
        columns={columns}
        rows={data?.items ?? null}
        total={data?.total ?? 0}
        query={query}
        onQueryChange={setQuery}
        rowKey={(row) => row.userId}
        refreshing={refreshing}
        searchPlaceholder="Search by name or email"
        emptyMessage="No reports match these filters."
        caption="Password health by user"
        toolbar={
          <>
            <SelectCompact
              value={issueFilter}
              onChange={(event) => {
                setIssueFilter(event.target.value);
                setQuery((current) => ({ ...current, page: 1 }));
              }}
              aria-label="Filter by issue"
              className="w-auto"
            >
              <option value="">Any issue</option>
              {Object.values(HEALTH_ISSUE).map((issue) => (
                <option key={issue} value={issue}>
                  Has {HEALTH_ISSUE_LABEL[issue].toLowerCase()}
                </option>
              ))}
            </SelectCompact>
          </>
        }
      />
    </div>
  );
}

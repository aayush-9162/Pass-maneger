/**
 * Overview.
 *
 * ## What changed, and why
 *
 * This page used to lead with the viewer's own session count, remembered device
 * count, and an "access level 36" figure. All three were true and none was
 * useful: nobody opens a password manager to learn how many permissions their
 * role carries, and "you are signed in on 9 other sessions" reads as an alarm
 * when it is usually the same person's other tabs.
 *
 * So it now answers the three questions somebody actually arrives with - what
 * can I get to, is anything wrong, what do I do next - and leaves account and
 * session detail to the page that exists for it.
 */

import { AlertTriangle, ArrowRight, KeyRound, Shield, Users } from 'lucide-react';
import { Link } from 'react-router';
import * as React from 'react';

import { ROLES, type MemberSharedVault, type SecurityScore } from '@passm/shared';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { cn } from '@/lib/utils';

interface Overview {
  vaults: MemberSharedVault[];
  score: SecurityScore | null;
}

/** Colour for a grade, so the score reads at a glance rather than as a number. */
function gradeTone(grade: string): string {
  if (grade === 'A' || grade === 'B') return 'text-success';
  if (grade === 'C') return 'text-warning';
  return 'text-destructive';
}

export default function DashboardPage(): React.ReactElement {
  const { user } = useAuth();
  const isAdmin = user?.role === ROLES.ADMIN;

  const [data, setData] = React.useState<Overview | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const vaults = await api.listMySharedVaults();

        // Administrator-only, and it must not sink the whole page for anyone
        // else - or when the endpoint is simply unavailable.
        let score: SecurityScore | null = null;
        if (isAdmin) {
          try {
            score = await api.getSecurityScore();
          } catch {
            score = null;
          }
        }

        if (!cancelled) setData({ vaults: vaults.vaults, score });
      } catch (caught) {
        if (!cancelled) {
          setError(caught instanceof Error ? caught.message : 'Could not load your overview.');
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isAdmin]);

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle aria-hidden />
        <AlertTitle>Could not load your overview</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  const vaults = data?.vaults ?? [];
  const itemCount = vaults.reduce((total, vault) => total + (vault.itemCount ?? 0), 0);

  return (
    <div className="mx-auto w-full max-w-5xl space-y-8">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">
          Hello, {user?.firstName ?? 'there'}
        </h1>
        <p className="mt-1 text-muted-foreground">
          {data === null
            ? 'Loading your access…'
            : itemCount === 0
              ? 'Nothing has been shared with you yet.'
              : `You can use ${itemCount} password${itemCount === 1 ? '' : 's'} across ${vaults.length} vault${vaults.length === 1 ? '' : 's'}.`}
        </p>
      </div>

      {/* What the application is for, given the most weight on the page. */}
      <Link to="/shared" className="block">
        <Card className="group transition-colors hover:border-primary/60 hover:bg-accent/40">
          <CardContent className="flex items-center gap-5 py-8">
            <div className="flex size-14 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <KeyRound className="size-7" aria-hidden />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xl font-semibold">Passwords</p>
              <p className="text-sm text-muted-foreground">
                {data === null
                  ? 'Loading…'
                  : itemCount === 0
                    ? 'Nothing here yet'
                    : `${itemCount} credential${itemCount === 1 ? '' : 's'} you can use`}
              </p>
            </div>
            <ArrowRight
              className="size-5 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-1"
              aria-hidden
            />
          </CardContent>
        </Card>
      </Link>

      {isAdmin && (
        <div className="grid gap-4 sm:grid-cols-2">
          <Link to="/admin/users" className="block">
            <Card className="group h-full transition-colors hover:border-primary/60 hover:bg-accent/40">
              <CardContent className="flex items-center gap-4 py-6">
                <div className="flex size-11 shrink-0 items-center justify-center rounded-lg bg-secondary">
                  <Users className="size-5" aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="font-medium">People</p>
                  <p className="text-sm text-muted-foreground">Add someone, or change access</p>
                </div>
                <ArrowRight
                  className="size-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-1"
                  aria-hidden
                />
              </CardContent>
            </Card>
          </Link>

          <Link to="/admin/security" className="block">
            <Card className="group h-full transition-colors hover:border-primary/60 hover:bg-accent/40">
              <CardContent className="flex items-center gap-4 py-6">
                <div className="flex size-11 shrink-0 items-center justify-center rounded-lg bg-secondary">
                  <Shield className="size-5" aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="font-medium">Security</p>
                  <div className="text-sm text-muted-foreground">
                    {data === null ? (
                      <Skeleton className="mt-1 h-4 w-28" />
                    ) : data.score ? (
                      <span>
                        Rated{' '}
                        <span className={cn('font-semibold', gradeTone(data.score.grade))}>
                          {data.score.grade}
                        </span>{' '}
                        · {data.score.score} out of 100
                      </span>
                    ) : (
                      <span>Policy, alerts and the audit trail</span>
                    )}
                  </div>
                </div>
                <ArrowRight
                  className="size-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-1"
                  aria-hidden
                />
              </CardContent>
            </Card>
          </Link>
        </div>
      )}

      {/*
        Account and session detail, deliberately last and deliberately quiet.
        Someone checking which address they signed in as, or ending a session
        they do not recognise, still gets there in one click - but it is not what
        the page opens with, because it is not why anyone came.
      */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t pt-6 text-sm text-muted-foreground">
        <span>
          Signed in as <span className="text-foreground">{user?.email}</span>
        </span>
        <Button asChild variant="link" className="h-auto p-0 text-sm">
          <Link to="/security">Sessions &amp; devices</Link>
        </Button>
      </div>
    </div>
  );
}

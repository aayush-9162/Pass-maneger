/**
 * Security posture: the score, the IP allow list, and the emergency lock.
 *
 * ## Why the score leads
 *
 * Nobody reads a settings page with sixty switches looking for the one that is
 * wrong. Everybody notices a B that used to be an A. The number exists to route
 * attention, and every point lost carries a specific finding with a specific fix
 * and a link to the page that fixes it - otherwise it is a vanity metric.
 *
 * ## Why the IP allow list has a tester
 *
 * An allow list is the control most likely to cause a self-inflicted outage.
 * The tester runs the *real* evaluation, so an administrator can check their own
 * address - and the addresses of people who are not in the room - before
 * switching enforcement on. The page also shows the caller's address and warns
 * when the current rules would not admit it.
 */

import {
  AlertTriangle,
  Check,
  Globe,
  Loader2,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Trash2,
  X,
} from 'lucide-react';
import { Link } from 'react-router';
import * as React from 'react';

import {
  IP_RULE_SCOPE,
  PRIVATE_RANGE_PRESETS,
  SCORE_AREA_LABEL,
  STEP_UP_ACTION,
  describeCidrProblem,
  ipMatchesCidr,
  type IpCheckResult,
  type IpRuleScope,
  type ScoreFinding,
} from '@passm/shared';

import { Feedback, PageHeader, messageOf, useAsyncData } from '@/components/admin/admin-kit';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { Textarea } from '@/components/ui/textarea';
import { api } from '@/lib/api-client';
import { formatDateTime, formatRelative } from '@/lib/format';
import { useStepUp } from '@/lib/step-up-context';
import { cn } from '@/lib/utils';

const GRADE_STYLE: Record<string, string> = {
  A: 'text-success',
  B: 'text-success',
  C: 'text-warning',
  D: 'text-warning',
  F: 'text-destructive',
};

const SEVERITY_STYLE: Record<ScoreFinding['severity'], string> = {
  low: 'bg-secondary text-muted-foreground',
  medium: 'bg-warning/15 text-warning',
  high: 'bg-destructive/15 text-destructive',
};

/** Circular score gauge. Pure SVG - no chart library anywhere in this app. */
function ScoreGauge({ score, grade }: { score: number; grade: string }): React.ReactElement {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const filled = (Math.max(0, Math.min(100, score)) / 100) * circumference;

  return (
    <div className="relative size-32 shrink-0">
      <svg viewBox="0 0 120 120" className="size-full -rotate-90" aria-hidden>
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          strokeWidth="10"
          className="stroke-secondary"
        />
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference - filled}`}
          className={cn('transition-all duration-700', GRADE_STYLE[grade] ?? 'text-muted-foreground')}
          stroke="currentColor"
        />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-semibold tabular-nums">{score}</span>
        <span className={cn('text-sm font-medium', GRADE_STYLE[grade])}>Grade {grade}</span>
      </div>
      <span className="sr-only">Security score {score} out of 100, grade {grade}.</span>
    </div>
  );
}

function IpRulesSection(): React.ReactElement {
  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [cidr, setCidr] = React.useState('');
  const [label, setLabel] = React.useState('');
  const [scope, setScope] = React.useState<IpRuleScope>(IP_RULE_SCOPE.GLOBAL);
  const [busy, setBusy] = React.useState(false);
  const [testIp, setTestIp] = React.useState('');
  const [testResult, setTestResult] = React.useState<IpCheckResult | null>(null);

  const { data, reload } = useAsyncData(() => api.listIpRules(), [notice]);

  const rules = data?.rules ?? [];
  const mode = data?.mode ?? 'off';
  const callerIp = data?.callerIp ?? '';

  const cidrProblem = cidr.trim().length > 0 ? describeCidrProblem(cidr) : null;

  /**
   * Would the current rules admit the administrator reading this page?
   *
   * Checked in the browser with the same matcher the server uses, so the warning
   * appears the moment a rule set becomes dangerous rather than after saving.
   */
  const callerCovered = React.useMemo(() => {
    if (!callerIp) return true;
    const active = rules.filter((rule) => rule.enabled && rule.scope === IP_RULE_SCOPE.GLOBAL);
    if (active.length === 0) return true;
    return active.some((rule) => ipMatchesCidr(callerIp, rule.cidr));
  }, [rules, callerIp]);

  const create = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await api.createIpRule({ cidr: cidr.trim(), label: label.trim(), scope });
      setNotice(`Added ${cidr.trim()}.`);
      setCreating(false);
      setCidr('');
      setLabel('');
      await reload();
    } catch (caught) {
      setError(messageOf(caught, 'Could not add that rule.'));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string, ruleLabel: string): Promise<void> => {
    setError(null);
    try {
      await api.deleteIpRule(id);
      setNotice(`Removed "${ruleLabel}".`);
      await reload();
    } catch (caught) {
      setError(messageOf(caught, 'Could not remove that rule.'));
    }
  };

  const runTest = async (): Promise<void> => {
    setError(null);
    setTestResult(null);
    try {
      setTestResult(await api.checkIp(testIp.trim()));
    } catch (caught) {
      setError(messageOf(caught, 'Could not test that address.'));
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <Globe className="size-4" aria-hidden />
            IP allow list
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Currently{' '}
            <span className="font-medium text-foreground">
              {mode === 'off' ? 'off' : mode === 'audit' ? 'in audit mode' : 'enforcing'}
            </span>
            . Change the mode on the{' '}
            <Link to="/admin/settings?category=network" className="underline">
              settings page
            </Link>
            .
          </p>
        </div>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Plus aria-hidden />
          Add range
        </Button>
      </CardHeader>

      <CardContent className="space-y-4">
        <Feedback notice={notice} error={error} onDismiss={() => setNotice(null)} />

        {mode === 'enforce' && !callerCovered && (
          <Alert variant="destructive">
            <AlertTriangle aria-hidden />
            <AlertTitle>Your own address is not covered</AlertTitle>
            <AlertDescription>
              You are connecting from <strong>{callerIp}</strong>, which no enabled global rule
              admits. You are still getting in because administrators are exempt, or because you
              are on loopback. Turn off that exemption and you will lock yourself out.
            </AlertDescription>
          </Alert>
        )}

        {mode === 'off' && rules.length > 0 && (
          <Alert>
            <AlertTriangle aria-hidden />
            <AlertTitle>These rules are not doing anything</AlertTitle>
            <AlertDescription>
              The list is switched off, so every address is admitted. Set it to audit mode for a
              week first - it logs what would be blocked without blocking anything, which is how
              you find the ranges you forgot.
            </AlertDescription>
          </Alert>
        )}

        {rules.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No rules. An empty list never blocks anyone, whatever the mode says.
          </p>
        ) : (
          <div className="divide-y rounded-lg border">
            {rules.map((rule) => (
              <div key={rule.id} className="flex flex-wrap items-center gap-3 p-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="rounded bg-secondary px-1.5 py-0.5 font-mono text-xs">
                      {rule.cidr}
                    </code>
                    <span className="text-sm font-medium">{rule.label}</span>
                    {!rule.enabled && (
                      <span className="rounded-full bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        disabled
                      </span>
                    )}
                    {rule.scope !== IP_RULE_SCOPE.GLOBAL && (
                      <span className="rounded-full bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        {rule.scope === IP_RULE_SCOPE.USER
                          ? `only ${rule.userName ?? 'one user'}`
                          : `role: ${rule.roleName}`}
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {rule.matchCount > 0
                      ? `Matched ${rule.matchCount} time${rule.matchCount === 1 ? '' : 's'}, last ${formatRelative(rule.lastMatchedAt ?? rule.createdAt)}`
                      : 'Never matched a request yet'}
                  </p>
                </div>

                <div className="flex shrink-0 gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => void api.setIpRuleEnabled(rule.id, !rule.enabled).then(reload)}
                  >
                    {rule.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Remove ${rule.label}`}
                    onClick={() => void remove(rule.id, rule.label)}
                  >
                    <Trash2 className="size-3.5" aria-hidden />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* The tester. Runs the real evaluation, not a preview of it. */}
        <div className="space-y-2 rounded-lg border bg-muted/30 p-3">
          <Label htmlFor="test-ip" className="text-sm font-medium">
            Would this address get in?
          </Label>
          <div className="flex gap-2">
            <Input
              id="test-ip"
              value={testIp}
              onChange={(event) => setTestIp(event.target.value)}
              placeholder={callerIp || '192.168.1.50'}
              className="font-mono text-sm"
            />
            <Button variant="outline" onClick={() => void runTest()} disabled={!testIp.trim()}>
              Test
            </Button>
          </div>

          {testResult && (
            <div
              className={cn(
                'flex items-start gap-2 rounded-md p-2.5 text-sm',
                testResult.effect === 'allowed'
                  ? 'bg-success/10 text-success'
                  : testResult.effect === 'would-block'
                    ? 'bg-warning/10 text-warning'
                    : 'bg-destructive/10 text-destructive',
              )}
            >
              {testResult.effect === 'allowed' ? (
                <Check className="mt-0.5 size-4 shrink-0" aria-hidden />
              ) : (
                <X className="mt-0.5 size-4 shrink-0" aria-hidden />
              )}
              <span>{testResult.reason}</span>
            </div>
          )}

          <p className="text-xs text-muted-foreground">
            Your address is <code className="font-mono">{callerIp || 'unknown'}</code>. This runs
            the same check the server performs on every request.
          </p>
        </div>
      </CardContent>

      <Dialog open={creating} onOpenChange={(open) => !open && setCreating(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Allow a network range</DialogTitle>
            <DialogDescription>
              Anyone connecting from inside this range may reach the API, subject to normal
              authentication.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="rule-cidr">Address or range</Label>
              <Input
                id="rule-cidr"
                value={cidr}
                onChange={(event) => setCidr(event.target.value)}
                placeholder="192.168.1.0/24"
                className="font-mono"
                aria-invalid={cidrProblem !== null}
              />
              {cidrProblem && <p className="text-xs text-destructive">{cidrProblem}</p>}

              <div className="flex flex-wrap gap-1.5 pt-1">
                {PRIVATE_RANGE_PRESETS.map((preset) => (
                  <button
                    key={preset.cidr}
                    type="button"
                    onClick={() => {
                      setCidr(preset.cidr);
                      if (!label) setLabel(preset.label);
                    }}
                    className="rounded-full bg-secondary px-2 py-0.5 text-xs text-secondary-foreground hover:bg-secondary/80"
                  >
                    {preset.cidr}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="rule-label">Name</Label>
              <Input
                id="rule-label"
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                placeholder="Head office LAN"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="rule-scope">Applies to</Label>
              <Select
                id="rule-scope"
                value={scope}
                onChange={(event) => setScope(event.target.value as IpRuleScope)}
              >
                <option value={IP_RULE_SCOPE.GLOBAL}>Everyone</option>
              </Select>
              <p className="text-xs text-muted-foreground">
                Rules combine as a union: a caller is admitted if any applicable rule matches.
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setCreating(false)} disabled={busy}>
              Cancel
            </Button>
            <Button
              onClick={() => void create()}
              disabled={busy || cidrProblem !== null || !cidr.trim() || !label.trim()}
            >
              {busy && <Loader2 className="animate-spin" aria-hidden />}
              Add range
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

function EmergencyLockSection(): React.ReactElement {
  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [confirming, setConfirming] = React.useState(false);
  const [reason, setReason] = React.useState('');
  const [terminate, setTerminate] = React.useState(false);
  const [busy, setBusy] = React.useState(false);

  const { runWithStepUp } = useStepUp();
  const { data, reload } = useAsyncData(() => api.getEmergencyLock(), [notice]);

  const active = data?.active ?? false;

  const toggle = async (next: boolean): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const result = await runWithStepUp(STEP_UP_ACTION.ADMIN_ACTION, () =>
        api.setEmergencyLock({
          active: next,
          reason: reason.trim(),
          ...(next ? { terminateSessions: terminate } : {}),
        }),
      );
      setNotice(result.notice);
      setConfirming(false);
      setReason('');
      setTerminate(false);
      await reload();
    } catch (caught) {
      setError(messageOf(caught, 'Could not change the emergency lock.'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className={cn(active && 'border-destructive')}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Siren className={cn('size-4', active && 'text-destructive')} aria-hidden />
          Emergency lock
        </CardTitle>
        <p className="text-sm text-muted-foreground">
          Immediately refuses all vault access except for administrators. For a suspected breach,
          when stopping everything is better than working out what happened first.
        </p>
      </CardHeader>

      <CardContent className="space-y-4">
        <Feedback notice={notice} error={error} onDismiss={() => setNotice(null)} />

        {active ? (
          <Alert variant="destructive">
            <ShieldAlert aria-hidden />
            <AlertTitle>The lock is on</AlertTitle>
            <AlertDescription>
              Nobody except an administrator can reach a password right now. They are shown:
              &ldquo;{data?.message}&rdquo;
            </AlertDescription>
          </Alert>
        ) : (
          <p className="text-sm text-muted-foreground">
            Normal operation. Everyone can reach their vaults.
          </p>
        )}

        <Button
          variant={active ? 'default' : 'destructive'}
          onClick={() => setConfirming(true)}
          disabled={busy}
        >
          {active ? (
            <>
              <ShieldCheck aria-hidden />
              Lift the lock
            </>
          ) : (
            <>
              <Siren aria-hidden />
              Engage emergency lock
            </>
          )}
        </Button>
      </CardContent>

      <Dialog open={confirming} onOpenChange={(open) => !open && setConfirming(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{active ? 'Lift the emergency lock?' : 'Engage the emergency lock?'}</DialogTitle>
            <DialogDescription>
              {active
                ? 'Everyone regains access to their vaults immediately.'
                : 'Everyone except administrators loses access to every password immediately.'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {!active && (
              <>
                <Alert variant="destructive">
                  <AlertTriangle aria-hidden />
                  <AlertDescription>
                    Nobody will be able to sign into a website, retrieve a credential, or use the
                    browser extension until you lift this. Be sure you want to stop the company
                    working.
                  </AlertDescription>
                </Alert>

                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={terminate}
                    onChange={(event) => setTerminate(event.target.checked)}
                    className="mt-0.5 size-4 rounded border-input"
                  />
                  <span>
                    <span className="font-medium">Also sign everyone out now</span>
                    <span className="block text-xs text-muted-foreground">
                      Ends every non-administrator session immediately, rather than only refusing
                      new vault requests. Use this if you believe a session is already in the wrong
                      hands.
                    </span>
                  </span>
                </label>
              </>
            )}

            <div className="space-y-2">
              <Label htmlFor="lock-reason">Reason (required, recorded in the audit trail)</Label>
              <Textarea
                id="lock-reason"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder={
                  active
                    ? 'Incident closed; credentials rotated.'
                    : 'Suspected credential compromise reported at 14:20.'
                }
                maxLength={300}
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirming(false)} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant={active ? 'default' : 'destructive'}
              onClick={() => void toggle(!active)}
              disabled={busy || reason.trim().length < 3}
            >
              {busy && <Loader2 className="animate-spin" aria-hidden />}
              {active ? 'Lift the lock' : 'Engage the lock'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

export default function AdminPosturePage(): React.ReactElement {
  const [refreshKey, setRefreshKey] = React.useState(0);
  const { data: score, error: scoreError } = useAsyncData(
    () => api.getSecurityScore(),
    [refreshKey],
  );

  const failing = (score?.findings ?? []).filter((finding) => !finding.passed);
  const passing = (score?.findings ?? []).filter((finding) => finding.passed);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security posture"
        description="How this deployment is configured, what it costs you, and the controls that stop everything in an emergency."
        actions={
          <Button variant="outline" onClick={() => setRefreshKey((key) => key + 1)}>
            <RefreshCw aria-hidden />
            Recalculate
          </Button>
        }
      />

      <Feedback notice={null} error={scoreError} />

      {score === null ? (
        <Skeleton className="h-64" />
      ) : (
        <>
          <Card>
            <CardContent className="flex flex-wrap items-center gap-6 p-6">
              <ScoreGauge score={score.score} grade={score.grade} />

              <div className="min-w-0 flex-1 space-y-3">
                <div>
                  <p className="text-sm text-muted-foreground">
                    {failing.length === 0
                      ? 'Every check passed. Worth re-reading after any policy change.'
                      : `${failing.length} finding${failing.length === 1 ? '' : 's'} worth acting on.`}
                  </p>
                  {score.previousScore !== null && score.previousScore !== score.score && (
                    <p
                      className={cn(
                        'text-sm font-medium',
                        score.score > score.previousScore ? 'text-success' : 'text-destructive',
                      )}
                    >
                      {score.score > score.previousScore ? '▲' : '▼'}{' '}
                      {Math.abs(score.score - score.previousScore)} since the last check
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    Computed {formatDateTime(score.computedAt)}
                  </p>
                </div>

                {/* Per-area bars. */}
                <div className="grid gap-2 sm:grid-cols-2">
                  {score.areas.map((area) => {
                    const ratio = area.max === 0 ? 0 : area.score / area.max;
                    return (
                      <div key={area.area} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="text-muted-foreground">
                            {SCORE_AREA_LABEL[area.area]}
                          </span>
                          <span className="tabular-nums">
                            {area.score}/{area.max}
                          </span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
                          <div
                            className={cn(
                              'h-full rounded-full transition-all',
                              ratio >= 0.9
                                ? 'bg-success'
                                : ratio >= 0.6
                                  ? 'bg-warning'
                                  : 'bg-destructive',
                            )}
                            style={{ width: `${ratio * 100}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </CardContent>
          </Card>

          {failing.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Worth fixing</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Ordered by what each one actually costs you, not by how easy it is to measure.
                </p>
              </CardHeader>
              <CardContent className="space-y-3">
                {failing.map((finding) => (
                  <div key={finding.id} className="space-y-1.5 rounded-lg border p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={cn(
                          'rounded-full px-2 py-0.5 text-[10px] font-medium uppercase',
                          SEVERITY_STYLE[finding.severity],
                        )}
                      >
                        {finding.severity}
                      </span>
                      <p className="font-medium">{finding.title}</p>
                      {finding.impact > 0 && (
                        <span className="text-xs text-muted-foreground">
                          −{finding.impact} points
                        </span>
                      )}
                    </div>

                    <p className="text-sm text-muted-foreground">{finding.detail}</p>
                    <p className="text-sm">{finding.remediation}</p>

                    {finding.actionUrl && (
                      <Link
                        to={finding.actionUrl}
                        className="inline-block text-sm font-medium text-primary hover:underline"
                      >
                        Go and fix it →
                      </Link>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {passing.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Passing checks ({passing.length})</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-1.5 sm:grid-cols-2">
                {passing.map((finding) => (
                  <p
                    key={finding.id}
                    className="flex items-start gap-1.5 text-xs text-muted-foreground"
                    title={finding.detail}
                  >
                    <Check className="mt-0.5 size-3 shrink-0 text-success" aria-hidden />
                    {finding.title}
                  </p>
                ))}
              </CardContent>
            </Card>
          )}
        </>
      )}

      <IpRulesSection />
      <EmergencyLockSection />
    </div>
  );
}

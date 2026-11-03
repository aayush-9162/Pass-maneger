/**
 * Approval queue.
 *
 * Two views of one table: requests awaiting your decision, and requests you
 * raised. They sit side by side because the same person is usually both an
 * approver for some vaults and a requester on others.
 *
 * Approving *access* creates a grant; approving a *reveal* lets the server
 * release that vault's passwords to the requester. Both take effect at once.
 */

import { Check, Clock, Inbox, KeyRound, Loader2, X } from 'lucide-react';
import * as React from 'react';

import {
  REQUEST_STATUS,
  REQUEST_TYPE,
  REQUEST_TYPE_LABEL,
  VAULT_ROLE_LABEL,
  type AccessRequest,
  type RequestStatus,
  type VaultRole,
} from '@passm/shared';

import { Feedback, PageHeader, StatCard, messageOf, useAsyncData } from '@/components/admin/admin-kit';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { SelectCompact } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { api } from '@/lib/api-client';
import { formatDateTime, formatRelative } from '@/lib/format';
import { cn } from '@/lib/utils';

const STATUS_STYLE: Record<RequestStatus, string> = {
  [REQUEST_STATUS.PENDING]: 'bg-warning/15 text-warning',
  [REQUEST_STATUS.APPROVED]: 'bg-success/15 text-success',
  [REQUEST_STATUS.DENIED]: 'bg-destructive/15 text-destructive',
  [REQUEST_STATUS.CANCELLED]: 'bg-secondary text-muted-foreground',
  [REQUEST_STATUS.EXPIRED]: 'bg-secondary text-muted-foreground',
};

function RequestCard({
  request,
  view,
  onDecide,
  onCancel,
}: {
  request: AccessRequest;
  view: 'inbox' | 'mine';
  onDecide: (request: AccessRequest, approve: boolean) => void;
  onCancel: (request: AccessRequest) => void;
}): React.ReactElement {
  const pending = request.status === REQUEST_STATUS.PENDING;
  const expiresIn = new Date(request.expiresAt).getTime() - Date.now();
  const expiringSoon = pending && expiresIn < 24 * 3600_000;

  return (
    <Card>
      <CardContent className="space-y-3 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={cn(
                  'rounded-full px-2 py-0.5 text-xs font-medium',
                  STATUS_STYLE[request.status],
                )}
              >
                {request.status}
              </span>

              <span className="inline-flex items-center gap-1 rounded-full bg-secondary px-2 py-0.5 text-xs text-secondary-foreground">
                {request.requestType === REQUEST_TYPE.REVEAL && (
                  <KeyRound className="size-3" aria-hidden />
                )}
                {REQUEST_TYPE_LABEL[request.requestType]}
              </span>

              {request.requestedRole && (
                <span className="rounded-full bg-secondary px-2 py-0.5 text-xs text-secondary-foreground">
                  as {VAULT_ROLE_LABEL[request.requestedRole as VaultRole]}
                </span>
              )}
            </div>

            <p className="font-medium">{request.vaultName}</p>
            <p className="text-sm text-muted-foreground">
              {view === 'inbox' ? (
                <>
                  <span className="text-foreground">{request.requesterName}</span> ({request.requesterEmail})
                </>
              ) : (
                'Your request'
              )}{' '}
              · {formatRelative(request.createdAt)}
            </p>
          </div>

          {pending && (
            <div className="flex shrink-0 gap-2">
              {view === 'inbox' ? (
                <>
                  <Button size="sm" variant="outline" onClick={() => onDecide(request, false)}>
                    <X aria-hidden />
                    Deny
                  </Button>
                  <Button size="sm" onClick={() => onDecide(request, true)}>
                    <Check aria-hidden />
                    Approve
                  </Button>
                </>
              ) : (
                <Button size="sm" variant="outline" onClick={() => onCancel(request)}>
                  Withdraw
                </Button>
              )}
            </div>
          )}
        </div>

        <blockquote className="border-l-2 pl-3 text-sm text-muted-foreground">
          {request.reason}
        </blockquote>

        {pending && (
          <p
            className={cn(
              'flex items-center gap-1.5 text-xs',
              expiringSoon ? 'text-warning' : 'text-muted-foreground',
            )}
          >
            <Clock className="size-3.5" aria-hidden />
            Lapses {formatRelative(request.expiresAt)} if nobody decides
          </p>
        )}

        {request.decidedAt && (
          <div className="space-y-1 border-t pt-3 text-xs text-muted-foreground">
            <p>
              {request.status === REQUEST_STATUS.APPROVED ? 'Approved' : 'Decided'} by{' '}
              <span className="text-foreground">{request.decidedByName ?? 'someone'}</span> on{' '}
              {formatDateTime(request.decidedAt)}
            </p>
            {request.decisionNote && <p>“{request.decisionNote}”</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function AdminApprovalsPage(): React.ReactElement {
  const [view, setView] = React.useState<'inbox' | 'mine'>('inbox');
  const [status, setStatus] = React.useState<string>(REQUEST_STATUS.PENDING);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [decision, setDecision] = React.useState<{
    request: AccessRequest;
    approve: boolean;
  } | null>(null);
  const [note, setNote] = React.useState('');
  const [busy, setBusy] = React.useState(false);

  const { data, error: loadError, reload } = useAsyncData(
    () => api.listApprovals({ view, ...(status ? { status } : {}), pageSize: 50 }),
    [view, status, notice],
  );

  const { data: countData } = useAsyncData(() => api.pendingApprovalCount(), [notice]);

  const submitDecision = async (): Promise<void> => {
    if (!decision) return;

    setBusy(true);
    setError(null);
    try {
      const result = await api.decideAccessRequest(decision.request.id, {
        approve: decision.approve,
        ...(note.trim() ? { note: note.trim() } : {}),
      });

      setNotice(result.message);
      setDecision(null);
      setNote('');
      await reload();
    } catch (caught) {
      setError(messageOf(caught, 'Could not record that decision.'));
    } finally {
      setBusy(false);
    }
  };

  const cancel = async (request: AccessRequest): Promise<void> => {
    setError(null);
    try {
      await api.cancelAccessRequest(request.id);
      setNotice('Request withdrawn.');
      await reload();
    } catch (caught) {
      setError(messageOf(caught, 'Could not withdraw that request.'));
    }
  };

  const items = data?.items ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Approvals"
        description="Requests to join a vault, or to be given the key to a password that is hidden from someone."
      />

      <Feedback notice={notice} error={error ?? loadError} onDismiss={() => setNotice(null)} />

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          icon={Inbox}
          label="Awaiting your decision"
          value={countData?.pending ?? 0}
          tone={(countData?.pending ?? 0) > 0 ? 'warning' : 'success'}
        />
        <StatCard label="Shown" value={items.length} hint={`${view === 'inbox' ? 'inbox' : 'raised by you'}`} />
        <StatCard
          label="Pending here"
          value={items.filter((r) => r.status === REQUEST_STATUS.PENDING).length}
        />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="inline-flex rounded-lg border p-0.5" role="tablist">
          {(['inbox', 'mine'] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="tab"
              aria-selected={view === option}
              onClick={() => setView(option)}
              className={cn(
                'rounded-md px-3 py-1.5 text-sm transition-colors',
                view === option
                  ? 'bg-secondary font-medium text-secondary-foreground'
                  : 'text-muted-foreground hover:text-foreground',
              )}
            >
              {option === 'inbox' ? 'To decide' : 'My requests'}
            </button>
          ))}
        </div>

        <SelectCompact
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          aria-label="Filter by status"
          className="w-auto"
        >
          <option value="">Any status</option>
          {Object.values(REQUEST_STATUS).map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </SelectCompact>
      </div>

      {data === null ? (
        <div className="space-y-3">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="space-y-2 py-12 text-center">
            <Inbox className="mx-auto size-8 text-muted-foreground" aria-hidden />
            <p className="font-medium">Nothing here</p>
            <p className="mx-auto max-w-md text-sm text-muted-foreground">
              {view === 'inbox'
                ? 'No requests are waiting on you. You see requests for vaults where you hold share or admin rights.'
                : 'You have not raised any requests matching this filter.'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((request) => (
            <RequestCard
              key={request.id}
              request={request}
              view={view}
              onDecide={(target, approve) => {
                setDecision({ request: target, approve });
                setNote('');
              }}
              onCancel={(target) => void cancel(target)}
            />
          ))}
        </div>
      )}

      <Dialog open={decision !== null} onOpenChange={(open) => !open && setDecision(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {decision?.approve ? 'Approve' : 'Deny'} this request?
            </DialogTitle>
            <DialogDescription>
              {decision?.request.requesterName} asked for{' '}
              {decision?.request.requestType === REQUEST_TYPE.REVEAL
                ? 'the passwords hidden from them'
                : 'access'}{' '}
              on <strong>{decision?.request.vaultName}</strong>.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2">
            <label htmlFor="decision-note" className="text-sm font-medium">
              Note {decision?.approve ? '(optional)' : '(recommended)'}
            </label>
            <Textarea
              id="decision-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder={
                decision?.approve
                  ? 'Approved for the migration window.'
                  : 'Explain why, so they know what to do differently.'
              }
              maxLength={500}
            />
            <p className="text-xs text-muted-foreground">
              Shown to the requester and recorded in the audit trail.
            </p>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDecision(null)} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant={decision?.approve ? 'default' : 'destructive'}
              disabled={busy}
              onClick={() => void submitDecision()}
            >
              {busy && <Loader2 className="animate-spin" aria-hidden />}
              {decision?.approve ? 'Approve' : 'Deny'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

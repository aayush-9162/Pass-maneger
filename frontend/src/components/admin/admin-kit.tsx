/**
 * Shared pieces of the admin panel: page headers, statistic cards, confirmation
 * dialogs and the hooks every list page needs.
 *
 * These exist so the eleven admin screens are consistent by construction rather
 * than by discipline - particularly the destructive-action dialog, which several
 * screens use and which must look and behave identically every time so that
 * "this one is different" is a visible signal rather than a surprise.
 */

import { AlertTriangle, Check, Loader2, type LucideIcon } from 'lucide-react';
import * as React from 'react';
import { useSearchParams } from 'react-router';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ApiError } from '@/lib/api-client';
import { cn } from '@/lib/utils';

// ---------------------------------------------------------------------------
// Page chrome
// ---------------------------------------------------------------------------

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}): React.ReactElement {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function StatCard({
  icon: Icon,
  label,
  value,
  hint,
  tone = 'default',
  chart,
}: {
  icon?: LucideIcon;
  label: string;
  value: string | number;
  hint?: React.ReactNode;
  tone?: 'default' | 'success' | 'warning' | 'destructive';
  chart?: React.ReactNode;
}): React.ReactElement {
  const toneClass = {
    default: 'bg-secondary text-secondary-foreground',
    success: 'bg-success/15 text-success',
    warning: 'bg-warning/15 text-warning',
    destructive: 'bg-destructive/15 text-destructive',
  }[tone];

  return (
    <Card>
      <CardContent className="flex items-start gap-4 p-5">
        {Icon && (
          <span className={cn('flex size-10 shrink-0 items-center justify-center rounded-lg', toneClass)}>
            <Icon className="size-5" aria-hidden />
          </span>
        )}

        <div className="min-w-0 flex-1 space-y-0.5">
          <p className="text-sm text-muted-foreground">{label}</p>
          <p className="text-2xl font-semibold tabular-nums">{value}</p>
          {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
        </div>

        {chart && <div className="shrink-0 self-end">{chart}</div>}
      </CardContent>
    </Card>
  );
}

/** Transient success and error banners, with the same behaviour on every page. */
export function Feedback({
  notice,
  error,
  onDismiss,
}: {
  notice: string | null;
  error: string | null;
  onDismiss?: () => void;
}): React.ReactElement | null {
  React.useEffect(() => {
    if (!notice || !onDismiss) return undefined;
    const timer = setTimeout(onDismiss, 6000);
    return () => clearTimeout(timer);
  }, [notice, onDismiss]);

  if (!notice && !error) return null;

  return (
    <div className="space-y-3">
      {error && (
        <Alert variant="destructive">
          <AlertTriangle aria-hidden />
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {notice && (
        <Alert variant="success">
          <Check aria-hidden />
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Confirmation
// ---------------------------------------------------------------------------

/**
 * Confirm a destructive action.
 *
 * `confirmPhrase` requires the operator to type an exact string - the account's
 * email, the vault's name - before the button enables. Reserved for actions that
 * cannot be undone; using it for everything trains people to type without
 * reading, which is worse than not having it at all.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Confirm',
  confirmPhrase,
  confirmPhraseLabel,
  destructive = true,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: React.ReactNode;
  confirmLabel?: string;
  confirmPhrase?: string;
  confirmPhraseLabel?: string;
  destructive?: boolean;
  onConfirm: () => Promise<void> | void;
}): React.ReactElement {
  const [typed, setTyped] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (open) {
      setTyped('');
      setError(null);
    }
  }, [open]);

  const phraseMatches =
    confirmPhrase === undefined || typed.trim().toLowerCase() === confirmPhrase.toLowerCase();

  const confirm = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      onOpenChange(false);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription asChild>
            <div className="space-y-2">{description}</div>
          </DialogDescription>
        </DialogHeader>

        {confirmPhrase && (
          <div className="space-y-2">
            <Label htmlFor="confirm-phrase">
              {confirmPhraseLabel ?? `Type ${confirmPhrase} to confirm`}
            </Label>
            <Input
              id="confirm-phrase"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder={confirmPhrase}
            />
          </div>
        )}

        {error && (
          <Alert variant="destructive">
            <AlertTriangle aria-hidden />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            disabled={busy || !phraseMatches}
            onClick={() => void confirm()}
          >
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/** Turn any thrown value into a message worth showing a person. */
export function messageOf(error: unknown, fallback = 'Something went wrong.'): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return fallback;
}

/**
 * A query-string parameter as React state.
 *
 * The only thing the admin panel needs from the URL is "which record is open".
 * Keeping it in the query string means deep links and the back button both
 * work; each change pushes a history entry.
 */
export function useQueryParam(
  key: string,
): [string | null, (value: string | null) => void] {
  const [searchParams, setSearchParams] = useSearchParams();

  const update = React.useCallback(
    (next: string | null) => {
      setSearchParams((params) => {
        if (next === null) params.delete(key);
        else params.set(key, next);
        return params;
      });
    },
    [key, setSearchParams],
  );

  return [searchParams.get(key), update];
}

/**
 * Load data, with a stale-while-refetching pattern.
 *
 * The previous rows stay on screen during a refetch instead of being replaced by
 * a skeleton. Filtering a table should not make it disappear and reappear -
 * that reads as a page reload and loses the user's place.
 */
export function useAsyncData<T>(
  load: () => Promise<T>,
  deps: React.DependencyList,
): {
  data: T | null;
  error: string | null;
  refreshing: boolean;
  reload: () => Promise<void>;
} {
  const [data, setData] = React.useState<T | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [refreshing, setRefreshing] = React.useState(false);

  const loadRef = React.useRef(load);
  loadRef.current = load;

  const run = React.useCallback(async () => {
    setRefreshing(true);
    try {
      setData(await loadRef.current());
      setError(null);
    } catch (caught) {
      setError(messageOf(caught, 'Could not load this data.'));
    } finally {
      setRefreshing(false);
    }
  }, []);

  React.useEffect(() => {
    let cancelled = false;

    void (async () => {
      setRefreshing(true);
      try {
        const result = await loadRef.current();
        // Guards against an out-of-order response overwriting a newer one: a
        // slow page-1 request must not clobber the page-2 rows the user is
        // already looking at.
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (caught) {
        if (!cancelled) setError(messageOf(caught, 'Could not load this data.'));
      } finally {
        if (!cancelled) setRefreshing(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, refreshing, reload: run };
}

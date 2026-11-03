/**
 * Security alerts.
 *
 * ## Why a bell rather than an email
 *
 * "A new device signed in as you" is the single most useful security signal in a
 * password manager, because the server cannot tell a stolen password from a real
 * one and the account holder can, instantly. Putting it where they already are
 * beats a mail nobody reads.
 *
 * ## Restraint
 *
 * Each alert type is switchable by an administrator and repeat events collapse
 * inside a window, both handled server-side. An alert channel that cries wolf is
 * worse than none: people learn to clear the badge without reading, and then
 * miss the one that mattered.
 */

import { AlertTriangle, Bell, Check, Info, ShieldAlert, X } from 'lucide-react';
import { Link } from 'react-router';
import * as React from 'react';

import { NOTIFICATION_SEVERITY, type SecurityNotification } from '@passm/shared';

import { Button } from '@/components/ui/button';
import { api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { formatRelative } from '@/lib/format';
import { cn } from '@/lib/utils';

const SEVERITY_ICON = {
  [NOTIFICATION_SEVERITY.INFO]: Info,
  [NOTIFICATION_SEVERITY.WARNING]: AlertTriangle,
  [NOTIFICATION_SEVERITY.CRITICAL]: ShieldAlert,
};

const SEVERITY_STYLE = {
  [NOTIFICATION_SEVERITY.INFO]: 'text-muted-foreground',
  [NOTIFICATION_SEVERITY.WARNING]: 'text-warning',
  [NOTIFICATION_SEVERITY.CRITICAL]: 'text-destructive',
};

/** How often the unread count is refreshed while the panel is closed. */
const POLL_INTERVAL_MS = 60_000;

export function NotificationBell(): React.ReactElement | null {
  const { user } = useAuth();
  const [open, setOpen] = React.useState(false);
  const [items, setItems] = React.useState<SecurityNotification[]>([]);
  const [unread, setUnread] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const panelRef = React.useRef<HTMLDivElement | null>(null);

  const load = React.useCallback(async (): Promise<void> => {
    if (!user) return;
    setLoading(true);
    try {
      const result = await api.listNotifications({ pageSize: 20 });
      setItems([...result.items]);
      setUnread(result.unreadCount);
    } catch {
      // A failed poll is not worth an error banner over the whole app.
    } finally {
      setLoading(false);
    }
  }, [user]);

  React.useEffect(() => {
    if (!user) return undefined;
    void load();
    const timer = setInterval(() => void load(), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [user, load]);

  // Close on an outside click, so the panel behaves like every other popover.
  React.useEffect(() => {
    if (!open) return undefined;

    const onPointerDown = (event: PointerEvent): void => {
      if (panelRef.current && !panelRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') setOpen(false);
    };

    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  const markAllRead = async (): Promise<void> => {
    await api.markNotificationsRead([]);
    setItems((current) =>
      current.map((item) => ({ ...item, readAt: item.readAt ?? new Date().toISOString() })),
    );
    setUnread(0);
  };

  const dismiss = async (id: string): Promise<void> => {
    await api.dismissNotification(id);
    setItems((current) => current.filter((item) => item.id !== id));
    void load();
  };

  if (!user) return null;

  return (
    <div className="relative" ref={panelRef}>
      <Button
        variant="ghost"
        size="icon"
        aria-label={unread > 0 ? `Security alerts (${unread} unread)` : 'Security alerts'}
        aria-expanded={open}
        onClick={() => {
          setOpen((current) => !current);
          if (!open) void load();
        }}
        className="relative"
      >
        <Bell className="size-4" aria-hidden />
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex size-4 items-center justify-center rounded-full bg-destructive text-[10px] font-medium text-destructive-foreground">
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </Button>

      {open && (
        <div className="absolute right-0 z-50 mt-2 w-[22rem] max-w-[calc(100vw-2rem)] overflow-hidden rounded-lg border bg-popover shadow-lg">
          <div className="flex items-center justify-between border-b px-3 py-2">
            <p className="text-sm font-medium">Security alerts</p>
            {unread > 0 && (
              <Button variant="ghost" size="sm" onClick={() => void markAllRead()}>
                <Check className="size-3.5" aria-hidden />
                Mark all read
              </Button>
            )}
          </div>

          <div className="max-h-[26rem] overflow-y-auto">
            {loading && items.length === 0 ? (
              <p className="px-3 py-8 text-center text-sm text-muted-foreground">Loading…</p>
            ) : items.length === 0 ? (
              <div className="space-y-1 px-3 py-8 text-center">
                <Bell className="mx-auto size-6 text-muted-foreground" aria-hidden />
                <p className="text-sm font-medium">Nothing to report</p>
                <p className="text-xs text-muted-foreground">
                  You will be told here if a new device signs in, or your password changes.
                </p>
              </div>
            ) : (
              items.map((item) => {
                const Icon = SEVERITY_ICON[item.severity];
                return (
                  <article
                    key={item.id}
                    className={cn(
                      'group flex gap-2.5 border-b px-3 py-2.5 last:border-b-0',
                      !item.readAt && 'bg-primary/[0.04]',
                    )}
                  >
                    <Icon
                      className={cn('mt-0.5 size-4 shrink-0', SEVERITY_STYLE[item.severity])}
                      aria-hidden
                    />

                    <div className="min-w-0 flex-1 space-y-1">
                      <p className="text-sm font-medium leading-snug">{item.title}</p>
                      <p className="text-xs leading-relaxed text-muted-foreground">{item.body}</p>

                      <div className="flex items-center gap-2 pt-0.5">
                        <span className="text-[11px] text-muted-foreground">
                          {formatRelative(item.createdAt)}
                        </span>
                        {item.actionUrl && (
                          <Link
                            to={item.actionUrl}
                            onClick={() => setOpen(false)}
                            className="text-[11px] font-medium text-primary hover:underline"
                          >
                            {item.actionLabel ?? 'Open'}
                          </Link>
                        )}
                      </div>
                    </div>

                    <button
                      type="button"
                      aria-label="Dismiss"
                      onClick={() => void dismiss(item.id)}
                      className="shrink-0 self-start rounded p-0.5 text-muted-foreground opacity-0 transition-opacity hover:text-foreground focus:opacity-100 group-hover:opacity-100"
                    >
                      <X className="size-3.5" aria-hidden />
                    </button>
                  </article>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}

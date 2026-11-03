/**
 * Idle warning before the console signs itself out.
 *
 * ## Why warn at all
 *
 * A vault that locks silently mid-task reads as a bug. The predictable response
 * is that someone asks for the timeout to be raised, or an administrator raises
 * it pre-emptively - so the absence of a warning makes the *actual* security
 * posture worse, not better. A few seconds of notice keeps a short timeout
 * tolerable.
 *
 * ## Why it does not auto-extend
 *
 * The button is an explicit "I am here". Extending on mousemove would defeat the
 * whole control: a page with an animation, or a desk with a cat on it, would
 * hold the session open indefinitely.
 */

import { Lock, ShieldCheck } from 'lucide-react';
import * as React from 'react';

import { Button } from '@/components/ui/button';
import { useIdleSignOut } from '@/lib/idle-context';

export function IdleWarning(): React.ReactElement | null {
  const { warningAt: lockWarningAt, staySignedIn, signOutNow } = useIdleSignOut();
  const [secondsLeft, setSecondsLeft] = React.useState(0);

  React.useEffect(() => {
    if (lockWarningAt === null) {
      setSecondsLeft(0);
      return undefined;
    }

    const tick = (): void => {
      setSecondsLeft(Math.max(0, Math.ceil((lockWarningAt - Date.now()) / 1000)));
    };

    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, [lockWarningAt]);

  if (lockWarningAt === null) return null;

  return (
    <div
      role="alertdialog"
      aria-live="assertive"
      aria-label="About to sign out"
      className="fixed inset-x-0 bottom-0 z-50 border-t bg-background/95 p-4 shadow-lg backdrop-blur sm:inset-x-auto sm:bottom-4 sm:right-4 sm:max-w-sm sm:rounded-lg sm:border"
    >
      <div className="flex items-start gap-3">
        <Lock className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden />

        <div className="min-w-0 flex-1 space-y-2">
          <div className="space-y-1">
            <p className="text-sm font-medium">Signing you out</p>
            <p className="text-xs text-muted-foreground">
              No activity for a while. PassM signs out in{' '}
              <span className="font-medium tabular-nums text-foreground">{secondsLeft}s</span> and
              you will need to sign in with Google again.
            </p>
          </div>

          <div className="flex gap-2">
            <Button size="sm" onClick={staySignedIn}>
              <ShieldCheck aria-hidden />
              I&rsquo;m still here
            </Button>
            <Button size="sm" variant="outline" onClick={signOutNow}>
              Sign out now
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

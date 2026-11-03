/**
 * Two-step verification: confirm it is you with Google.
 *
 * ## What it protects
 *
 * A hijacked session, and to a lesser degree an unlocked, unattended screen. The
 * vault is already open by the time this fires, so it is not protecting the
 * *data* from the network - it is confirming that the person at the keyboard
 * can complete a Google sign-in as the account holder before something
 * consequential happens.
 *
 * ## The protocol, client side
 *
 *   1. Ask the server for a challenge. It returns a challenge id and a random
 *      nonce.
 *   2. Render Google's button with that nonce. Google embeds it in the ID token
 *      it returns.
 *   3. Send the token. The server verifies it belongs to this account and
 *      carries this nonce, so a token from the original sign-in - or from an
 *      earlier confirmation - cannot satisfy it.
 *
 * ## Why a context rather than a hook per call site
 *
 * A step-up can be demanded by *any* request, at any time, because whether it is
 * required is a server-side policy the client does not control. So the pattern
 * is: wrap the call, catch `STEP_UP_REQUIRED`, raise the dialog, replay. Doing
 * that per call site would mean every mutating action grew the same twenty
 * lines, and the one that was forgotten would surface as an unexplained error.
 */

import { Loader2 } from 'lucide-react';
import * as React from 'react';

import { ERROR_CODES, STEP_UP_ACTION, type StepUpAction } from '@passm/shared';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ApiError, api } from '@/lib/api-client';
import { renderGoogleButton } from '@/lib/google-identity';

/** Human wording for what is being confirmed. */
const ACTION_PROMPT: Record<StepUpAction, string> = {
  [STEP_UP_ACTION.REVEAL]: 'reveal this password',
  [STEP_UP_ACTION.EXPORT]: 'export this data',
  [STEP_UP_ACTION.ADMIN_ACTION]: 'perform this administrative action',
  [STEP_UP_ACTION.SETTINGS_CHANGE]: 'change the security policy',
};

interface StepUpContextValue {
  /**
   * Run `operation`, handling a step-up demand transparently.
   *
   * If the server refuses with `STEP_UP_REQUIRED`, the dialog is raised and the
   * operation is replayed once the user has confirmed with Google. Any other
   * error propagates unchanged.
   */
  runWithStepUp: <T>(action: StepUpAction, operation: () => Promise<T>) => Promise<T>;
  /** Prompt for confirmation directly, without an operation to replay. */
  verify: (action: StepUpAction) => Promise<boolean>;
}

const StepUpContext = React.createContext<StepUpContextValue | null>(null);

interface PendingPrompt {
  action: StepUpAction;
  resolve: (verified: boolean) => void;
}

function messageOf(caught: unknown): string {
  if (caught instanceof ApiError && caught.code === ERROR_CODES.STEP_UP_FAILED) {
    return 'That Google account could not confirm this action. Use the account you signed in with.';
  }
  if (caught instanceof ApiError) return caught.message;
  if (caught instanceof Error) return caught.message;
  return 'Could not confirm it is you. Try again.';
}

export function StepUpProvider({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement {
  const [pending, setPending] = React.useState<PendingPrompt | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  /** A fresh challenge per attempt; bumping it re-runs the effect below. */
  const [attempt, setAttempt] = React.useState(0);
  // The dialog renders into a portal, so the button's container exists only
  // once it opens. A callback ref turns its arrival into a re-render.
  const [buttonHost, setButtonHost] = React.useState<HTMLDivElement | null>(null);

  const close = React.useCallback((verified: boolean) => {
    setPending((current) => {
      current?.resolve(verified);
      return null;
    });
    setError(null);
    setBusy(false);
  }, []);

  const prompt = React.useCallback(
    (action: StepUpAction): Promise<boolean> =>
      new Promise<boolean>((resolve) => {
        setError(null);
        setPending({ action, resolve });
      }),
    [],
  );

  // Issue a challenge and bind Google's button to its nonce.
  React.useEffect(() => {
    if (!pending || !buttonHost) return undefined;
    let cancelled = false;

    void (async () => {
      try {
        const challenge = await api.createStepUpChallenge(pending.action);
        if (cancelled) return;

        await renderGoogleButton(
          buttonHost,
          (credential) => {
            void (async () => {
              setBusy(true);
              setError(null);
              try {
                await api.verifyStepUp(challenge.challengeId, credential);
                close(true);
              } catch (caught) {
                setError(messageOf(caught));
                setBusy(false);
                // Challenges are single-use; the next try needs a new one.
                setAttempt((value) => value + 1);
              }
            })();
          },
          { nonce: challenge.nonce, text: 'continue_with', width: 300 },
        );
      } catch (caught) {
        if (!cancelled) setError(messageOf(caught));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [pending, buttonHost, attempt, close]);

  const runWithStepUp = React.useCallback(
    async <T,>(action: StepUpAction, operation: () => Promise<T>): Promise<T> => {
      try {
        return await operation();
      } catch (caught) {
        if (!(caught instanceof ApiError) || caught.code !== ERROR_CODES.STEP_UP_REQUIRED) {
          throw caught;
        }

        const verified = await prompt(action);
        if (!verified) throw caught;

        // Replay once. A second refusal is a real failure, not a missing
        // confirmation, and is allowed to propagate.
        return operation();
      }
    },
    [prompt],
  );

  const value = React.useMemo<StepUpContextValue>(
    () => ({ runWithStepUp, verify: prompt }),
    [runWithStepUp, prompt],
  );

  return (
    <StepUpContext.Provider value={value}>
      {children}

      <Dialog open={pending !== null} onOpenChange={(open) => !open && close(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm it is you</DialogTitle>
            <DialogDescription>
              Continue with your Google account to{' '}
              {pending ? ACTION_PROMPT[pending.action] : 'continue'}.
            </DialogDescription>
          </DialogHeader>

          <div className="flex min-h-11 items-center justify-center">
            {busy && (
              <span className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin" aria-hidden />
                Confirming...
              </span>
            )}
            <div ref={setButtonHost} className={busy ? 'hidden' : undefined} />
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => close(false)} disabled={busy}>
              Cancel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </StepUpContext.Provider>
  );
}

export function useStepUp(): StepUpContextValue {
  const context = React.useContext(StepUpContext);
  if (!context) {
    throw new Error('useStepUp must be used inside a StepUpProvider.');
  }
  return context;
}

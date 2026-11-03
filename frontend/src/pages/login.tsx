import { AlertCircle, Loader2, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router';
import * as React from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { renderGoogleButton } from '@/lib/google-identity';

/**
 * Sign-in page: Google is the only way in.
 *
 * Google's own button does the sign-in and hands back an ID token, which the
 * API verifies and exchanges for a session. Accounts outside the company's
 * Google Workspace domain are refused by the server, which says so.
 *
 * A locked account is reported with its retry window, because the user can act
 * on it.
 */
export default function LoginPage(): React.ReactElement {
  const navigate = useNavigate();
  const { loginWithGoogle, user, initializing, busy, error, clearError } = useAuth();

  const buttonRef = React.useRef<HTMLDivElement>(null);
  const [rememberDevice, setRememberDevice] = React.useState(false);
  const [lockoutSeconds, setLockoutSeconds] = React.useState<number | null>(null);
  const [buttonError, setButtonError] = React.useState<string | null>(null);

  // Google's button keeps the callback it was rendered with, so the checkbox is
  // read through a ref rather than captured once.
  const rememberRef = React.useRef(rememberDevice);
  rememberRef.current = rememberDevice;

  // Already signed in (e.g. navigated here manually): go straight through.
  React.useEffect(() => {
    if (!initializing && user) navigate('/shared', { replace: true });
  }, [initializing, user, navigate]);

  const handleCredential = React.useCallback(
    async (credential: string): Promise<void> => {
      clearError();
      setLockoutSeconds(null);

      try {
        await loginWithGoogle(credential, rememberRef.current);
        navigate('/shared', { replace: true });
      } catch (caught) {
        if (caught instanceof ApiError && caught.retryAfter !== undefined) {
          setLockoutSeconds(caught.retryAfter);
        }
        // The message is already in the context's `error`; nothing else to do.
      }
    },
    [clearError, loginWithGoogle, navigate],
  );

  React.useEffect(() => {
    if (initializing || user || !buttonRef.current) return;

    renderGoogleButton(buttonRef.current, (credential) => void handleCredential(credential)).catch(
      (caught: unknown) => {
        setButtonError(caught instanceof Error ? caught.message : 'Google sign-in could not load.');
      },
    );
  }, [initializing, user, handleCredential]);

  if (initializing) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="size-5 animate-spin text-muted-foreground" aria-hidden />
      </div>
    );
  }

  const shownError = error ?? buttonError;

  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <ShieldCheck className="size-6" aria-hidden />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">
              {import.meta.env.VITE_APP_NAME ?? 'PassM'}
            </h1>
            <p className="text-sm text-muted-foreground">
              Internal password manager - authorised staff only
            </p>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Sign in</CardTitle>
            <CardDescription>Use your company Google account to continue.</CardDescription>
          </CardHeader>

          <CardContent className="space-y-4">
            {shownError && (
              <Alert variant="destructive">
                <AlertCircle aria-hidden />
                <AlertDescription>
                  {shownError}
                  {lockoutSeconds !== null && (
                    <span className="mt-1 block text-xs">
                      Try again in about {Math.ceil(lockoutSeconds / 60)} minute
                      {Math.ceil(lockoutSeconds / 60) === 1 ? '' : 's'}, or contact an
                      administrator.
                    </span>
                  )}
                </AlertDescription>
              </Alert>
            )}

            <div className="flex min-h-11 items-center justify-center">
              {busy ? (
                <span className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                  Signing in...
                </span>
              ) : null}
              {/* Google renders its button in here. Hidden, not unmounted, while busy. */}
              <div ref={buttonRef} className={busy ? 'hidden' : undefined} />
            </div>

            <div className="flex items-start gap-2 rounded-md border bg-muted/40 p-3">
              <Checkbox
                id="rememberDevice"
                checked={rememberDevice}
                onCheckedChange={(checked) => setRememberDevice(checked === true)}
                disabled={busy}
                className="mt-0.5"
              />
              <div className="space-y-1">
                <Label htmlFor="rememberDevice" className="cursor-pointer">
                  Remember this device
                </Label>
                <p className="text-xs text-muted-foreground">
                  Skips extra verification on this browser. Only use it on a device that is
                  yours alone - never a shared workstation.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground">
          Anyone with a company Google account can sign in. Ask an administrator for access to
          passwords.
        </p>
      </div>
    </main>
  );
}

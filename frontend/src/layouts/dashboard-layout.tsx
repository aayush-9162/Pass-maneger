import { Loader2 } from 'lucide-react';
import * as React from 'react';
import { Outlet, useNavigate } from 'react-router';

import { AppShell } from '@/components/app-shell';
import { EmergencyLockBanner } from '@/components/security/emergency-lock-banner';
import { IdleWarning } from '@/components/security/idle-warning';
import { useAuth } from '@/lib/auth-context';
import { IdleSignOutProvider } from '@/lib/idle-context';
import { SecurityPolicyProvider } from '@/lib/security-policy-context';
import { StepUpProvider } from '@/lib/step-up-context';

/**
 * Guard for every authenticated page.
 *
 * One redirect: no session -> `/login`.
 *
 * It mirrors a rule the API enforces independently - without a valid token every
 * request 401s - so this layout exists to show the right screen, not to be the
 * thing that stops anyone.
 */
export function DashboardLayout(): React.ReactElement {
  const navigate = useNavigate();
  const { user, initializing } = useAuth();

  React.useEffect(() => {
    if (!initializing && !user) navigate('/login', { replace: true });
  }, [initializing, user, navigate]);

  if (initializing || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="size-5 animate-spin text-muted-foreground" aria-hidden />
        <span className="sr-only">Loading</span>
      </div>
    );
  }

  /**
   * Provider order matters.
   *
   * - `SecurityPolicyProvider` is outermost because the idle sign-out and the
   *   clipboard read their settings from it.
   * - `StepUpProvider` wraps the app so any page can replay a request through a
   *   Google confirmation, and so the dialog renders above everything.
   */
  return (
    <SecurityPolicyProvider>
      <StepUpProvider>
        <IdleSignOutProvider>
          <EmergencyLockBanner />
          <AppShell>
            <Outlet />
          </AppShell>
          <IdleWarning />
        </IdleSignOutProvider>
      </StepUpProvider>
    </SecurityPolicyProvider>
  );
}

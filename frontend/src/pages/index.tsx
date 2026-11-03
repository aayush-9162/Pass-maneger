import { Loader2 } from 'lucide-react';
import { useNavigate } from 'react-router';
import * as React from 'react';

import { useAuth } from '@/lib/auth-context';

/**
 * Entry point.
 *
 * Waits for the silent refresh to settle before redirecting, so a signed-in user
 * reloading the page is not bounced to the login screen and back.
 */
export default function IndexPage(): React.ReactElement {
  const navigate = useNavigate();
  const { user, initializing } = useAuth();

  React.useEffect(() => {
    if (initializing) return;
    navigate(user ? '/shared' : '/login', { replace: true });
  }, [initializing, user, navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="flex items-center gap-3 text-muted-foreground">
        <Loader2 className="size-5 animate-spin" aria-hidden />
        <span className="text-sm">Restoring your session...</span>
      </div>
    </div>
  );
}

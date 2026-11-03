/**
 * Banner shown while the emergency lock is on.
 *
 * Ordinary users have their vault access refused server-side; without this they
 * would see a wall of failed requests and conclude the system is broken. Saying
 * plainly that it is deliberate, and who to contact, is the difference between a
 * controlled incident and a flood of helpdesk tickets.
 *
 * Administrators see it too - they are exempt from the lock and can still work,
 * so they need a persistent reminder that everyone else cannot. A lock nobody
 * remembers to lift is the failure mode this guards against.
 */

import { ShieldAlert } from 'lucide-react';
import { Link } from 'react-router';
import * as React from 'react';

import { useAuth } from '@/lib/auth-context';
import { useSecurityPolicy } from '@/lib/security-policy-context';

export function EmergencyLockBanner(): React.ReactElement | null {
  const { policy, loaded } = useSecurityPolicy();
  const { user } = useAuth();

  if (!loaded || !policy.emergencyLockActive) return null;

  const isAdmin = user?.role === 'admin';

  return (
    <div
      role="alert"
      className="sticky top-0 z-50 border-b border-destructive/30 bg-destructive/10 px-4 py-2.5 text-destructive"
    >
      <div className="mx-auto flex max-w-6xl items-start gap-2.5">
        <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden />

        <div className="min-w-0 flex-1 text-sm">
          <p className="font-medium">
            {isAdmin ? 'Emergency lock is active' : 'Access is temporarily suspended'}
          </p>
          <p className="text-destructive/90">
            {policy.emergencyLockMessage}
            {isAdmin && (
              <>
                {' '}
                You can still work because administrators are exempt. Everyone else is locked out
                until you{' '}
                <Link to="/admin/settings?category=emergency" className="font-medium underline">
                  lift the lock
                </Link>
                .
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  );
}

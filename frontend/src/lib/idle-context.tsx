/**
 * Idle sign-out.
 *
 * The console holds nothing that outlives the session - passwords are fetched
 * from the server one at a time when someone asks - so "locking" an unattended
 * console means signing it out. This provider runs the administrator-configured
 * idle timer (`vaultAutoLockMinutes`, with a warning `vaultAutoLockWarningSeconds`
 * ahead) and the optional sign-out when the tab is hidden.
 *
 * Both are client-side: a modified browser can ignore them. The server's own
 * session idle timeout is the control that cannot be skipped.
 */

import * as React from 'react';

import { useAuth } from './auth-context';
import { useSecurityPolicy } from './security-policy-context';

/**
 * Interaction that counts as "still here".
 *
 * Scroll and mousemove are deliberately excluded: a nudged desk, a cat, or a
 * page that animates should not hold a session open indefinitely.
 */
const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = ['keydown', 'click', 'focus'];

interface IdleContextValue {
  /** Epoch ms at which the sign-out fires, while the warning is showing. */
  warningAt: number | null;
  /** "I am still here" - clears the warning and restarts the countdown. */
  staySignedIn: () => void;
  signOutNow: () => void;
}

const IdleContext = React.createContext<IdleContextValue | null>(null);

export function IdleSignOutProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const { logout } = useAuth();
  const { policy, loaded } = useSecurityPolicy();

  const [warningAt, setWarningAt] = React.useState<number | null>(null);
  const signOutTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const warnTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTimers = React.useCallback(() => {
    if (signOutTimer.current) clearTimeout(signOutTimer.current);
    if (warnTimer.current) clearTimeout(warnTimer.current);
    signOutTimer.current = null;
    warnTimer.current = null;
    setWarningAt(null);
  }, []);

  const signOutNow = React.useCallback(() => {
    clearTimers();
    void logout();
  }, [clearTimers, logout]);

  /**
   * Arm the timers from the live policy.
   *
   * Two timers, not one: the warning fires first so the user can say they are
   * still there. A console that signs out mid-sentence reads as a bug and trains
   * people to lengthen the timeout, which is the opposite of what it is for.
   */
  const schedule = React.useCallback(() => {
    clearTimers();
    if (!loaded || policy.vaultAutoLockMinutes <= 0) return;

    const signOutAfterMs = policy.vaultAutoLockMinutes * 60_000;
    const warnAfterMs = signOutAfterMs - Math.max(policy.vaultAutoLockWarningSeconds, 0) * 1000;

    if (policy.vaultAutoLockWarningSeconds > 0 && warnAfterMs > 0) {
      warnTimer.current = setTimeout(() => {
        setWarningAt(Date.now() + (signOutAfterMs - warnAfterMs));
      }, warnAfterMs);
    }

    signOutTimer.current = setTimeout(signOutNow, signOutAfterMs);
  }, [clearTimers, loaded, policy.vaultAutoLockMinutes, policy.vaultAutoLockWarningSeconds, signOutNow]);

  React.useEffect(() => {
    const reset = (): void => schedule();

    for (const event of ACTIVITY_EVENTS) window.addEventListener(event, reset);
    schedule();

    return () => {
      for (const event of ACTIVITY_EVENTS) window.removeEventListener(event, reset);
      clearTimers();
    };
  }, [schedule, clearTimers]);

  // Aggressive and off by default: suits a shared workstation, irritates
  // everywhere else - which is why it is a setting rather than a decision here.
  React.useEffect(() => {
    if (!policy.lockOnTabHidden) return undefined;

    const onVisibilityChange = (): void => {
      if (document.visibilityState === 'hidden') signOutNow();
    };

    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, [policy.lockOnTabHidden, signOutNow]);

  const value = React.useMemo(
    () => ({ warningAt, staySignedIn: schedule, signOutNow }),
    [warningAt, schedule, signOutNow],
  );

  return <IdleContext.Provider value={value}>{children}</IdleContext.Provider>;
}

export function useIdleSignOut(): IdleContextValue {
  const context = React.useContext(IdleContext);
  if (!context) throw new Error('useIdleSignOut must be used inside <IdleSignOutProvider>.');
  return context;
}

/**
 * Live security policy for the browser.
 *
 * The client needs a handful of policy values to behave correctly: how long
 * before the vault auto-locks, how long a copied password stays on the
 * clipboard, whether an idle warning appears. Those are administrator decisions,
 * so they have to come from the server rather than be hardcoded here.
 *
 * ## The honest framing
 *
 * Everything this context supplies is *browser-enforced*. A patched client can
 * ignore all of it. That is not a flaw in the design, it is what "client-side
 * setting" means - the server cannot police what a browser does with memory it
 * has already been given. The admin settings page badges these accordingly, and
 * the values that genuinely matter (session lifetime, lockout, step-up) are
 * enforced server-side and are *not* in this payload.
 *
 * ## Failure policy
 *
 * If the policy cannot be fetched, the shipped defaults apply. Failing closed
 * here would mean a brief API hiccup locks a user's vault mid-edit, which trades
 * a real usability cost for no security gain - the server-side controls are
 * unaffected either way.
 */

import * as React from 'react';

import {
  CLIENT_VISIBLE_SETTING_KEYS,
  SECURITY_SETTING_DEFAULTS,
  type ClientSecuritySettings,
} from '@passm/shared';

import { api } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';

/** Shipped defaults, narrowed to the client-visible slice. */
const FALLBACK = Object.fromEntries(
  CLIENT_VISIBLE_SETTING_KEYS.map((key) => [key, SECURITY_SETTING_DEFAULTS[key]]),
) as unknown as ClientSecuritySettings;

interface SecurityPolicyContextValue {
  policy: ClientSecuritySettings;
  /** False while the first fetch is in flight; the fallback is in use until then. */
  loaded: boolean;
  /** True when this deployment serves HTTPS. */
  tlsActive: boolean;
  reload: () => Promise<void>;
}

const SecurityPolicyContext = React.createContext<SecurityPolicyContextValue>({
  policy: FALLBACK,
  loaded: false,
  tlsActive: false,
  reload: async () => undefined,
});

/**
 * How often the policy is re-read.
 *
 * Ten minutes. An administrator tightening the auto-lock window should see it
 * take effect across the company without asking anyone to reload, but polling
 * more often would be a request per user per minute for a value that changes
 * perhaps twice a year.
 */
const REFRESH_INTERVAL_MS = 10 * 60_000;

export function SecurityPolicyProvider({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement {
  const { user } = useAuth();
  const [policy, setPolicy] = React.useState<ClientSecuritySettings>(FALLBACK);
  const [loaded, setLoaded] = React.useState(false);
  const [tlsActive, setTlsActive] = React.useState(false);

  const load = React.useCallback(async (): Promise<void> => {
    if (!user) return;

    try {
      const result = await api.getSecurityPolicy();
      setPolicy(result.policy);
      setTlsActive(result.tlsActive);
    } catch {
      // Keep whatever is in place - the defaults on first load, or the last
      // good policy afterwards. See the failure policy above.
    } finally {
      setLoaded(true);
    }
  }, [user]);

  React.useEffect(() => {
    if (!user) {
      setPolicy(FALLBACK);
      setLoaded(false);
      return undefined;
    }

    void load();
    const timer = setInterval(() => void load(), REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [user, load]);

  const value = React.useMemo<SecurityPolicyContextValue>(
    () => ({ policy, loaded, tlsActive, reload: load }),
    [policy, loaded, tlsActive, load],
  );

  return (
    <SecurityPolicyContext.Provider value={value}>{children}</SecurityPolicyContext.Provider>
  );
}

export function useSecurityPolicy(): SecurityPolicyContextValue {
  return React.useContext(SecurityPolicyContext);
}

/**
 * Authentication state for the console.
 *
 * On mount the provider attempts a silent refresh. If the browser still holds a
 * valid httpOnly refresh cookie, the user lands back in the app without
 * re-authenticating; otherwise they are treated as signed out. That single
 * attempt is why the access token can live in memory only - a page reload costs
 * one request rather than a login.
 *
 * Route protection is client-side only. The console is static files with no
 * server of its own to make an authorisation decision; the API is the real
 * enforcement point, and redirects here are purely for user experience.
 */

import { useNavigate } from 'react-router';
import * as React from 'react';

import { permissionsForRole, type Permission, type PublicUser, type RoleName } from '@passm/shared';

import { ApiError, api, onSessionEnded, refreshSession } from './api-client';
import { forgetGoogleSelection } from './google-identity';

interface AuthState {
  user: PublicUser | null;
  /** True until the initial silent refresh completes. */
  initializing: boolean;
  /** True while a login or logout is in flight. */
  busy: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  /** Exchange the ID token from Google's sign-in button for a PassM session. */
  loginWithGoogle: (credential: string, rememberDevice: boolean) => Promise<void>;
  logout: (allDevices?: boolean) => Promise<void>;
  refresh: () => Promise<void>;
  /** Re-read the profile, e.g. after changing the password. */
  reloadProfile: () => Promise<void>;
  hasPermission: (permission: Permission) => boolean;
  hasRole: (...roles: RoleName[]) => boolean;
  clearError: () => void;
}

const AuthContext = React.createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  const navigate = useNavigate();
  const [state, setState] = React.useState<AuthState>({
    user: null,
    initializing: true,
    busy: false,
    error: null,
  });

  /** Load the profile using the current access token. */
  const loadProfile = React.useCallback(async (): Promise<PublicUser | null> => {
    try {
      const profile = await api.getProfile();
      return profile.user;
    } catch {
      return null;
    }
  }, []);

  // --- Silent bootstrap ----------------------------------------------------
  React.useEffect(() => {
    let cancelled = false;

    void (async () => {
      const refreshed = await refreshSession();
      const user = refreshed ? await loadProfile() : null;

      if (!cancelled) {
        setState((previous) => ({ ...previous, user, initializing: false }));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [loadProfile]);

  // --- React to a session ending mid-use -----------------------------------
  React.useEffect(() => {
    // Fired by the API client when a request proves the session is gone -
    // revoked by an admin, replayed refresh token, or simply expired.
    return onSessionEnded(() => {
      setState((previous) => ({
        ...previous,
        user: null,
        error: 'Your session ended. Please sign in again.',
      }));
      navigate('/login', { replace: true });
    });
  }, [navigate]);

  const loginWithGoogle = React.useCallback(
    async (credential: string, rememberDevice: boolean) => {
      setState((previous) => ({ ...previous, busy: true, error: null }));

      try {
        const result = await api.loginWithGoogle({ credential, rememberDevice });
        setState((previous) => ({
          ...previous,
          user: result.user,
          busy: false,
          error: null,
        }));
      } catch (error) {
        const message =
          error instanceof ApiError
            ? error.message
            : 'Sign-in failed. Please try again.';
        setState((previous) => ({ ...previous, busy: false, error: message }));
        throw error;
      }
    },
    [],
  );

  const logout = React.useCallback(
    async (allDevices = false) => {
      setState((previous) => ({ ...previous, busy: true }));
      try {
        await api.logout(allDevices);
      } catch {
        // A failed logout must still clear local state: the user asked to leave.
      } finally {
        // Otherwise Google may offer to sign straight back in as the same
        // account, which on a shared machine is the opposite of signing out.
        forgetGoogleSelection();

        setState({ user: null, initializing: false, busy: false, error: null });
        navigate('/login', { replace: true });
      }
    },
    [navigate],
  );

  const refresh = React.useCallback(async () => {
    const refreshed = await refreshSession();
    const user = refreshed ? await loadProfile() : null;
    setState((previous) => ({ ...previous, user }));
  }, [loadProfile]);

  const reloadProfile = React.useCallback(async () => {
    const user = await loadProfile();
    setState((previous) => ({ ...previous, user }));
  }, [loadProfile]);

  const hasPermission = React.useCallback(
    (permission: Permission) => {
      if (!state.user) return false;
      // Derived from the role rather than read from the token, matching how the
      // API resolves it. UI gating is convenience only - the server decides.
      return permissionsForRole(state.user.role).includes(permission);
    },
    [state.user],
  );

  const hasRole = React.useCallback(
    (...roles: RoleName[]) => (state.user ? roles.includes(state.user.role) : false),
    [state.user],
  );

  const clearError = React.useCallback(() => {
    setState((previous) => ({ ...previous, error: null }));
  }, []);

  const value = React.useMemo<AuthContextValue>(
    () => ({
      ...state,
      loginWithGoogle,
      logout,
      refresh,
      reloadProfile,
      hasPermission,
      hasRole,
      clearError,
    }),
    [state, loginWithGoogle, logout, refresh, reloadProfile, hasPermission, hasRole, clearError],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used inside <AuthProvider>.');
  }
  return context;
}

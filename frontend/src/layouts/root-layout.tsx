import * as React from 'react';
import { Outlet } from 'react-router';

import { AuthProvider } from '@/lib/auth-context';
import { ThemeProvider } from '@/lib/theme';

/**
 * Providers shared by every route.
 *
 * Rendered inside the router rather than around it because `AuthProvider`
 * navigates to `/login` when a session ends, and navigation hooks only work
 * beneath `RouterProvider`.
 */
export function RootLayout(): React.ReactElement {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Outlet />
      </AuthProvider>
    </ThemeProvider>
  );
}

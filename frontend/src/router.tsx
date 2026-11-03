/**
 * Route table.
 *
 * Every page is loaded on demand, so signing in does not download the admin
 * panel and the Passwords page does not wait for the charts. Layouts are
 * imported eagerly: they are small, and every authenticated page needs them.
 */

import { Loader2 } from 'lucide-react';
import type * as React from 'react';
import { createBrowserRouter, type RouteObject } from 'react-router';

import { AdminLayout } from './layouts/admin-layout';
import { DashboardLayout } from './layouts/dashboard-layout';
import { RootLayout } from './layouts/root-layout';

/** Lazy route whose module default-exports the page component. */
function page(load: () => Promise<{ default: React.ComponentType }>): RouteObject['lazy'] {
  return async () => ({ Component: (await load()).default });
}

/** Shown while the first page's code downloads. */
function RouteLoading(): React.ReactElement {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Loader2 className="size-5 animate-spin text-muted-foreground" aria-hidden />
      <span className="sr-only">Loading</span>
    </div>
  );
}

export const router = createBrowserRouter([
  {
    Component: RootLayout,
    HydrateFallback: RouteLoading,
    children: [
      { index: true, lazy: page(() => import('./pages/index')) },
      { path: 'login', lazy: page(() => import('./pages/login')) },
      {
        Component: DashboardLayout,
        children: [
          { path: 'shared', lazy: page(() => import('./pages/shared')) },
          { path: 'dashboard', lazy: page(() => import('./pages/dashboard')) },
          { path: 'security', lazy: page(() => import('./pages/security')) },
          {
            path: 'admin',
            Component: AdminLayout,
            children: [
              { index: true, lazy: page(() => import('./pages/admin/index')) },
              { path: 'approvals', lazy: page(() => import('./pages/admin/approvals')) },
              { path: 'audit', lazy: page(() => import('./pages/admin/audit')) },
              { path: 'devices', lazy: page(() => import('./pages/admin/devices')) },
              { path: 'health', lazy: page(() => import('./pages/admin/health')) },
              { path: 'posture', lazy: page(() => import('./pages/admin/posture')) },
              { path: 'roles', lazy: page(() => import('./pages/admin/roles')) },
              { path: 'security', lazy: page(() => import('./pages/admin/security')) },
              { path: 'sessions', lazy: page(() => import('./pages/admin/sessions')) },
              { path: 'settings', lazy: page(() => import('./pages/admin/settings')) },
              { path: 'users', lazy: page(() => import('./pages/admin/users')) },
            ],
          },
        ],
      },
      { path: '*', lazy: page(() => import('./pages/not-found')) },
    ],
  },
], {
  // `/passmadmin` in a production build (vite.config.ts `base`), `/` in dev.
  basename: import.meta.env.BASE_URL.replace(/\/$/, '') || '/',
});

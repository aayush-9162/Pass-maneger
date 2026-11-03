/**
 * Advanced-area chrome.
 *
 * The console's core pages - Passwords, People, Activity, Settings - sit in
 * the top bar and render full-width, no second navigation. Everything else
 * (dashboards, sessions, devices, approvals, posture) is occasional-use and
 * lives behind the "Advanced" entry, which is the only place this sidebar
 * appears.
 *
 * Items are filtered by permission. That is presentation only - the API
 * enforces the same rules on every request, and hiding a link is never what
 * keeps anyone out.
 */

import {
  CheckSquare,
  LayoutDashboard,
  MonitorSmartphone,
  ShieldAlert,
  ShieldCheck,
  Stethoscope,
  type LucideIcon,
} from 'lucide-react';
import * as React from 'react';
import { Link, Outlet, useLocation } from 'react-router';

import { PERMISSIONS, type Permission } from '@passm/shared';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useAuth } from '@/lib/auth-context';
import { cn } from '@/lib/utils';

interface AdminNavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  permission: Permission;
  /** Grouping heading in the sidebar. */
  section: 'Monitoring' | 'Access';
}

/**
 * Core pages that live under /admin but belong to the top bar. They render
 * full-width, without this sidebar - the sidebar is Advanced-only.
 */
const CORE_ROUTES = ['/admin/users', '/admin/audit', '/admin/settings'];

const NAV_ITEMS: AdminNavItem[] = [
  {
    href: '/admin',
    label: 'Dashboard',
    icon: LayoutDashboard,
    permission: PERMISSIONS.ANALYTICS_READ,
    section: 'Monitoring',
  },
  {
    href: '/admin/security',
    label: 'Security',
    icon: ShieldAlert,
    permission: PERMISSIONS.ANALYTICS_READ,
    section: 'Monitoring',
  },
  {
    href: '/admin/posture',
    label: 'Posture & score',
    icon: ShieldCheck,
    permission: PERMISSIONS.ANALYTICS_READ,
    section: 'Monitoring',
  },
  {
    href: '/admin/health',
    label: 'Password health',
    icon: Stethoscope,
    permission: PERMISSIONS.PASSWORD_HEALTH_READ_ANY,
    section: 'Monitoring',
  },
  {
    href: '/admin/sessions',
    label: 'Sessions',
    icon: MonitorSmartphone,
    permission: PERMISSIONS.SESSION_READ_ANY,
    section: 'Access',
  },
  {
    href: '/admin/devices',
    label: 'Devices',
    icon: MonitorSmartphone,
    permission: PERMISSIONS.DEVICE_READ_ANY,
    section: 'Access',
  },
  {
    href: '/admin/approvals',
    label: 'Approvals',
    icon: CheckSquare,
    permission: PERMISSIONS.SHARED_VAULT_READ,
    section: 'Access',
  },
  {
    href: '/admin/roles',
    label: 'Roles',
    icon: ShieldCheck,
    permission: PERMISSIONS.ROLE_READ,
    section: 'Access',
  },
];

const SECTION_ORDER: AdminNavItem['section'][] = ['Monitoring', 'Access'];

export function AdminLayout(): React.ReactElement {
  const { pathname } = useLocation();
  const { hasPermission, initializing } = useAuth();

  const visible = NAV_ITEMS.filter((item) => hasPermission(item.permission));

  if (initializing) {
    return <div className="py-16 text-center text-sm text-muted-foreground">Loading…</div>;
  }

  // People, Activity and Settings are top-bar pages that happen to live under
  // /admin. They get the full width; the Advanced sidebar is not theirs.
  if (CORE_ROUTES.some((route) => pathname.startsWith(route))) {
    return <Outlet />;
  }

  // Someone who holds none of the admin permissions has landed here by typing
  // the URL. Saying so is better than an empty page or a silent redirect that
  // makes it look like the section does not exist.
  if (visible.length === 0) {
    return (
      <Alert variant="destructive">
        <ShieldAlert aria-hidden />
        <AlertTitle>You do not have access to the admin panel</AlertTitle>
        <AlertDescription>
          Ask an administrator if you need it. Every attempt to reach this area is recorded.
        </AlertDescription>
      </Alert>
    );
  }

  const isActive = (href: string): boolean =>
    href === '/admin' ? pathname === '/admin' : pathname.startsWith(href);

  return (
    <div className="flex flex-col gap-6 lg:flex-row lg:gap-8">
      {/* Sidebar on large screens; a horizontal scroller below that. */}
      <nav
        aria-label="Admin"
        className="shrink-0 lg:w-56"
      >
        <div className="flex gap-1 overflow-x-auto pb-2 lg:hidden">
          {visible.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              aria-current={isActive(item.href) ? 'page' : undefined}
              className={cn(
                'flex shrink-0 items-center gap-2 rounded-md px-3 py-1.5 text-sm',
                isActive(item.href)
                  ? 'bg-secondary text-secondary-foreground'
                  : 'text-muted-foreground',
              )}
            >
              <item.icon className="size-4" aria-hidden />
              {item.label}
            </Link>
          ))}
        </div>

        <div className="hidden space-y-6 lg:block">
          {SECTION_ORDER.map((section) => {
            const items = visible.filter((item) => item.section === section);
            if (items.length === 0) return null;

            return (
              <div key={section} className="space-y-1">
                <p className="px-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  {section}
                </p>
                {items.map((item) => (
                  <Link
                    key={item.href}
                    to={item.href}
                    aria-current={isActive(item.href) ? 'page' : undefined}
                    className={cn(
                      'flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors',
                      isActive(item.href)
                        ? 'bg-secondary font-medium text-secondary-foreground'
                        : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                    )}
                  >
                    <item.icon className="size-4 shrink-0" aria-hidden />
                    {item.label}
                  </Link>
                ))}
              </div>
            );
          })}
        </div>
      </nav>

      <div className="min-w-0 flex-1">
        <Outlet />
      </div>
    </div>
  );
}

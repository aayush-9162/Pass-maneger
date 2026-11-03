/**
 * Application frame: a single top bar - brand, navigation, identity - with the
 * full width below it left for content.
 *
 * A sidebar variant was tried and rejected: with four destinations the column
 * spent 90% of its height on nothing, and the owner preferred the navigation
 * where it started. The modern treatment stayed - the gradient active pill, the
 * typeface, the identity menu - only its position moved back up.
 *
 * Navigation is filtered by permission so people are not shown doors they
 * cannot open. Presentation only - the API enforces the same rules, so hiding
 * a link is never the control that keeps anyone out.
 */

import {
  ClipboardList,
  KeyRound,
  LogOut,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import { Link, useLocation } from 'react-router';
import * as React from 'react';

import { PERMISSIONS, type Permission } from '@passm/shared';

import { RoleBadge } from '@/components/role-badge';
import { NotificationBell } from '@/components/security/notification-bell';
import { ThemeToggle } from '@/components/theme-toggle';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useAuth } from '@/lib/auth-context';
import { initials } from '@/lib/format';
import { cn } from '@/lib/utils';

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Hidden unless the signed-in user holds this permission. */
  permission?: Permission;
}

/*
 * Four doors, in the order the work happens: put passwords in, add the people,
 * see what happened, tune the rules. Everything else - dashboards, sessions,
 * posture, approvals - is real but occasional, so it lives behind "Advanced"
 * rather than widening this bar.
 */
const NAV_ITEMS: NavItem[] = [
  {
    href: '/shared',
    label: 'Passwords',
    icon: KeyRound,
    permission: PERMISSIONS.SHARED_VAULT_READ,
  },
  {
    href: '/admin/users',
    label: 'People',
    icon: Users,
    permission: PERMISSIONS.USER_READ,
  },
  {
    href: '/admin/audit',
    label: 'Activity',
    icon: ClipboardList,
    permission: PERMISSIONS.AUDIT_READ,
  },
  {
    href: '/admin/settings',
    label: 'Settings',
    icon: SlidersHorizontal,
    permission: PERMISSIONS.SETTINGS_READ,
  },
  {
    href: '/admin',
    label: 'Advanced',
    icon: Wrench,
    permission: PERMISSIONS.ANALYTICS_READ,
  },
];

function Brand(): React.ReactElement {
  return (
    <Link to="/shared" className="flex items-center gap-2.5 font-semibold">
      <span className="flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-violet-500 text-primary-foreground shadow-md shadow-primary/25">
        <ShieldCheck className="size-5" aria-hidden />
      </span>
      <span className="text-lg tracking-tight">
        {import.meta.env.VITE_APP_NAME ?? 'PassM'}
      </span>
      {import.meta.env.VITE_ENVIRONMENT_LABEL && (
        <span className="rounded bg-warning/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-warning">
          {import.meta.env.VITE_ENVIRONMENT_LABEL}
        </span>
      )}
    </Link>
  );
}

/** The signed-in user's menu: identity, sessions link, both sign-outs. */
function UserMenu(): React.ReactElement | null {
  const { user, logout, busy } = useAuth();
  if (!user) return null;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="gap-2.5 rounded-xl px-2">
          <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-primary/20 to-violet-500/20 text-xs font-bold text-primary">
            {initials(user.firstName, user.lastName)}
          </span>
          <span className="hidden text-sm font-medium xl:inline">{user.fullName}</span>
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel>
          <div className="space-y-1">
            <p className="text-sm font-medium">{user.fullName}</p>
            <p className="truncate text-xs font-normal text-muted-foreground">{user.email}</p>
            <div className="pt-1">
              <RoleBadge role={user.role} />
            </div>
          </div>
        </DropdownMenuLabel>

        <DropdownMenuSeparator />

        <DropdownMenuItem asChild>
          <Link to="/security">
            <ShieldCheck aria-hidden />
            Sessions &amp; devices
          </Link>
        </DropdownMenuItem>

        <DropdownMenuSeparator />

        <DropdownMenuItem destructive disabled={busy} onSelect={() => void logout(false)}>
          <LogOut aria-hidden />
          Sign out
        </DropdownMenuItem>

        <DropdownMenuItem destructive disabled={busy} onSelect={() => void logout(true)}>
          <LogOut aria-hidden />
          Sign out everywhere
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AppShell({ children }: { children: React.ReactNode }): React.ReactElement {
  const { pathname } = useLocation();
  const { hasPermission } = useAuth();

  const visibleItems = NAV_ITEMS.filter(
    (item) => !item.permission || hasPermission(item.permission),
  );

  const isActive = (href: string): boolean => {
    // "Advanced" (/admin) must not light up when a core page that merely lives
    // under /admin - People, Activity, Settings - is the one that is open.
    if (href === '/admin') {
      return (
        pathname === '/admin' ||
        (pathname.startsWith('/admin/') &&
          !NAV_ITEMS.some(
            (item) => item.href !== '/admin' && pathname.startsWith(item.href),
          ))
      );
    }
    return pathname === href || pathname.startsWith(`${href}/`);
  };

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur">
        <div className="container flex h-16 items-center justify-between gap-6">
          <div className="flex min-w-0 items-center gap-8">
            <Brand />

            <nav aria-label="Main" className="hidden items-center gap-1.5 md:flex">
              {visibleItems.map((item) => {
                const active = isActive(item.href);
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    aria-current={active ? 'page' : undefined}
                    className={cn(
                      'flex items-center gap-2 rounded-xl px-3.5 py-2 text-sm font-medium transition-all',
                      active
                        ? 'bg-gradient-to-r from-primary to-violet-500 text-primary-foreground shadow-md shadow-primary/25'
                        : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                    )}
                  >
                    <item.icon className="size-[18px]" aria-hidden />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <NotificationBell />
            <ThemeToggle />
            <UserMenu />
          </div>
        </div>

        {/* Compact navigation for small screens. */}
        <nav
          aria-label="Main (compact)"
          className="container flex gap-1 overflow-x-auto pb-2 md:hidden"
        >
          {visibleItems.map((item) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                to={item.href}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'flex shrink-0 items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium',
                  active
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent',
                )}
              >
                <item.icon className="size-4" aria-hidden />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </header>

      <main className="container flex-1 py-8">{children}</main>

      <footer className="border-t py-4">
        <div className="container text-xs text-muted-foreground">
          Internal company use only. Activity on this system is logged and audited.
        </div>
      </footer>
    </div>
  );
}

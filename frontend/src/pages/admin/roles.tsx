/**
 * Roles and the permission matrix.
 *
 * Read-only, and deliberately so. Roles are compile-time constants in
 * `@passm/shared` and the matrix that maps them to permissions is a source file,
 * not a database table. That is a design decision worth stating on the page
 * itself: a permission matrix that can be edited at runtime is one that can be
 * edited by anyone who reaches the database, and an authorisation model nobody
 * can review in a diff.
 */

import { ShieldCheck } from 'lucide-react';
import * as React from 'react';

import { PERMISSIONS, ROLE_LABEL, type RoleSummary } from '@passm/shared';

import { Feedback, PageHeader, useAsyncData } from '@/components/admin/admin-kit';
import { RoleBadge } from '@/components/role-badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { api } from '@/lib/api-client';

/**
 * Group permissions for display.
 *
 * The key prefix (`user:`, `vault:`, ...) is the natural grouping and is already
 * the convention every permission follows, so the headings come from the data
 * rather than from a second list that could drift out of step with it.
 */
const GROUP_LABELS: Record<string, string> = {
  user: 'User administration',
  role: 'Roles',
  group: 'Groups',
  shared_vault: 'Shared vaults',
  session: 'Sessions',
  device: 'Devices',
  vault: 'Personal vault',
  audit: 'Audit',
  analytics: 'Reporting',
  password_health: 'Password health',
};

const ALL_PERMISSIONS = Object.values(PERMISSIONS);

function groupOf(permission: string): string {
  return permission.split(':')[0] ?? 'other';
}

export default function AdminRolesPage(): React.ReactElement {
  const { data, error } = useAsyncData(() => api.listRoles(), []);

  const roles: RoleSummary[] = data?.roles ?? [];

  const grouped = React.useMemo(() => {
    const map = new Map<string, string[]>();
    for (const permission of ALL_PERMISSIONS) {
      const key = groupOf(permission);
      const existing = map.get(key);
      if (existing) existing.push(permission);
      else map.set(key, [permission]);
    }
    return [...map];
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Roles"
        description="Who can do what. Three roles, and the matrix below is the whole of the authorisation model."
      />

      <Feedback notice={null} error={error} />

      <Alert>
        <ShieldCheck aria-hidden />
        <AlertTitle>The matrix is code, not configuration</AlertTitle>
        <AlertDescription>
          Roles and their permissions are defined in the shared package and compiled into the API,
          the console and the extension together. There is no endpoint that edits them, which means
          a change to who can do what goes through review and shows up in a diff - and cannot be
          made by someone who reaches the database.
        </AlertDescription>
      </Alert>

      <div className="grid gap-4 sm:grid-cols-3">
        {data === null
          ? Array.from({ length: 3 }, (_, index) => <Skeleton key={index} className="h-32" />)
          : roles.map((role) => (
              <Card key={role.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between gap-2">
                    <CardTitle className="text-base">
                      {ROLE_LABEL[role.name] ?? role.label}
                    </CardTitle>
                    <RoleBadge role={role.name} />
                  </div>
                  <CardDescription>{role.description ?? 'No description.'}</CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-2xl font-semibold tabular-nums">{role.userCount}</p>
                  <p className="text-xs text-muted-foreground">
                    account{role.userCount === 1 ? '' : 's'} · {role.permissions.length} permissions
                  </p>
                </CardContent>
              </Card>
            ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Permission matrix</CardTitle>
          <CardDescription>
            Note what is absent: no role reads a password by itself. That takes a grant on the
            group that holds it, and every grant is in the audit trail.
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[16rem]">Permission</TableHead>
                {roles.map((role) => (
                  <TableHead key={role.id} className="text-center">
                    {ROLE_LABEL[role.name] ?? role.label}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>

            <TableBody>
              {grouped.map(([group, permissions]) => (
                <React.Fragment key={group}>
                  <TableRow className="bg-muted/40 hover:bg-muted/40">
                    <TableCell
                      colSpan={roles.length + 1}
                      className="py-2 text-xs font-medium uppercase tracking-wide text-muted-foreground"
                    >
                      {GROUP_LABELS[group] ?? group}
                    </TableCell>
                  </TableRow>

                  {permissions.map((permission) => (
                    <TableRow key={permission}>
                      <TableCell className="font-mono text-xs">{permission}</TableCell>
                      {roles.map((role) => (
                        <TableCell key={role.id} className="text-center">
                          {role.permissions.includes(permission) ? (
                            <span className="text-success" aria-label="granted">
                              ✓
                            </span>
                          ) : (
                            <span className="text-muted-foreground/40" aria-label="not granted">
                              ·
                            </span>
                          )}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

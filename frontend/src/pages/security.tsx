import { AlertTriangle, Check, Laptop, Loader2, MonitorSmartphone, Trash2, X } from 'lucide-react';
import * as React from 'react';

import type { DeviceInfo, SessionInfo } from '@passm/shared';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
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
import { useAuth } from '@/lib/auth-context';
import { formatDateTime, formatRelative } from '@/lib/format';

/**
 * Self-service security page: every place the account is signed in, and every
 * device it has remembered, with the ability to end either.
 *
 * This is the screen a user reaches for when something feels wrong, so both
 * destructive actions are immediate and clearly labelled rather than buried
 * behind settings.
 */
export default function SecurityPage(): React.ReactElement {
  const { logout } = useAuth();

  const [sessions, setSessions] = React.useState<SessionInfo[] | null>(null);
  const [devices, setDevices] = React.useState<DeviceInfo[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [pendingId, setPendingId] = React.useState<string | null>(null);
  const [renamingId, setRenamingId] = React.useState<string | null>(null);
  const [renameValue, setRenameValue] = React.useState('');

  const load = React.useCallback(async () => {
    try {
      const [sessionResult, deviceResult] = await Promise.all([
        api.listSessions(),
        api.listDevices(),
      ]);
      setSessions(sessionResult.sessions);
      setDevices(deviceResult.devices);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not load your security details.');
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const revokeSession = async (session: SessionInfo): Promise<void> => {
    setPendingId(session.id);
    setNotice(null);
    try {
      const result = await api.revokeSession(session.id);
      // Ending your own session is a logout: send the user to the sign-in page
      // rather than leaving them on a screen whose token is now dead.
      if (result.wasCurrentSession) {
        await logout(false);
        return;
      }
      setNotice('That session has been signed out.');
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not end that session.');
    } finally {
      setPendingId(null);
    }
  };

  const revokeDevice = async (device: DeviceInfo): Promise<void> => {
    setPendingId(device.id);
    setNotice(null);
    try {
      const result = await api.revokeDevice(device.id);
      if (result.wasCurrentDevice) {
        // Its sessions are gone, including this one.
        await logout(false);
        return;
      }
      setNotice(`"${device.name}" has been removed and its sessions ended.`);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not remove that device.');
    } finally {
      setPendingId(null);
    }
  };

  const saveRename = async (device: DeviceInfo): Promise<void> => {
    const name = renameValue.trim();
    if (!name || name === device.name) {
      setRenamingId(null);
      return;
    }

    setPendingId(device.id);
    try {
      await api.renameDevice(device.id, name);
      setRenamingId(null);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not rename that device.');
    } finally {
      setPendingId(null);
    }
  };

  return (
    <div className="space-y-8">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Sessions &amp; devices</h1>
        <p className="text-sm text-muted-foreground">
          Review where your account is signed in. Anything you do not recognise should be ended
          immediately, followed by a password change.
        </p>
      </header>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle aria-hidden />
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {notice && (
        <Alert variant="success">
          <Check aria-hidden />
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      )}

      {/* ------------------------------------------------------------------ */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MonitorSmartphone className="size-5" aria-hidden />
            Active sessions
          </CardTitle>
          <CardDescription>
            Each session is one sign-in. Ending one immediately invalidates its tokens.
          </CardDescription>
        </CardHeader>

        <CardContent>
          {!sessions ? (
            <div className="space-y-2">
              <Skeleton className="h-12" />
              <Skeleton className="h-12" />
            </div>
          ) : sessions.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">No active sessions.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>IP address</TableHead>
                  <TableHead>Last activity</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((session) => (
                  <TableRow key={session.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{session.deviceName ?? 'Unknown device'}</span>
                        {session.isCurrent && <Badge variant="success">This device</Badge>}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{session.ipAddress ?? '-'}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatRelative(session.lastActivityAt)}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatDateTime(session.expiresAt)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                        disabled={pendingId === session.id}
                        onClick={() => void revokeSession(session)}
                      >
                        {pendingId === session.id ? (
                          <Loader2 className="animate-spin" aria-hidden />
                        ) : (
                          <Trash2 aria-hidden />
                        )}
                        {session.isCurrent ? 'Sign out' : 'End session'}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* ------------------------------------------------------------------ */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Laptop className="size-5" aria-hidden />
            Known devices
          </CardTitle>
          <CardDescription>
            Removing a device withdraws its &quot;remember me&quot; grant and ends every session
            it holds.
          </CardDescription>
        </CardHeader>

        <CardContent>
          {!devices ? (
            <div className="space-y-2">
              <Skeleton className="h-12" />
              <Skeleton className="h-12" />
            </div>
          ) : devices.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No devices registered yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Platform</TableHead>
                  <TableHead>Trust</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((device) => (
                  <TableRow key={device.id}>
                    <TableCell>
                      {renamingId === device.id ? (
                        <div className="flex items-center gap-1">
                          <Input
                            value={renameValue}
                            onChange={(event) => setRenameValue(event.target.value)}
                            className="h-8 max-w-[14rem]"
                            aria-label="Device name"
                            autoFocus
                            onKeyDown={(event) => {
                              if (event.key === 'Enter') void saveRename(device);
                              if (event.key === 'Escape') setRenamingId(null);
                            }}
                          />
                          <Button
                            size="icon"
                            variant="ghost"
                            className="size-8"
                            aria-label="Save name"
                            onClick={() => void saveRename(device)}
                          >
                            <Check aria-hidden />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="size-8"
                            aria-label="Cancel rename"
                            onClick={() => setRenamingId(null)}
                          >
                            <X aria-hidden />
                          </Button>
                        </div>
                      ) : (
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{device.name}</span>
                          {device.isCurrent && <Badge variant="success">This device</Badge>}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-sm capitalize text-muted-foreground">
                      {device.platform}
                    </TableCell>
                    <TableCell>
                      {device.trusted ? (
                        <Badge variant="success">
                          Remembered until {formatDateTime(device.trustExpiresAt)}
                        </Badge>
                      ) : device.status === 'revoked' ? (
                        <Badge variant="destructive">Blocked</Badge>
                      ) : (
                        <Badge variant="outline">Not remembered</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatRelative(device.lastUsedAt)}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        {renamingId !== device.id && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setRenamingId(device.id);
                              setRenameValue(device.name);
                            }}
                          >
                            Rename
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                          disabled={pendingId === device.id}
                          onClick={() => void revokeDevice(device)}
                        >
                          {pendingId === device.id ? (
                            <Loader2 className="animate-spin" aria-hidden />
                          ) : (
                            <Trash2 aria-hidden />
                          )}
                          Remove
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

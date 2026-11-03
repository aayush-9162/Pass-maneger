import { ROLE_LABEL, ROLES, USER_STATUS, type RoleName, type UserStatus } from '@passm/shared';

import { Badge } from '@/components/ui/badge';

/** Colour follows privilege level, so an admin row is visually obvious in a list. */
const ROLE_VARIANT: Record<RoleName, 'default' | 'secondary' | 'outline'> = {
  [ROLES.ADMIN]: 'default',
  [ROLES.EMPLOYEE]: 'outline',
};

export function RoleBadge({ role }: { role: RoleName }): React.ReactElement {
  return <Badge variant={ROLE_VARIANT[role] ?? 'outline'}>{ROLE_LABEL[role] ?? role}</Badge>;
}

const STATUS_VARIANT: Record<UserStatus, 'success' | 'warning' | 'destructive' | 'secondary'> = {
  [USER_STATUS.ACTIVE]: 'success',
  [USER_STATUS.PENDING]: 'secondary',
  [USER_STATUS.LOCKED]: 'warning',
  [USER_STATUS.SUSPENDED]: 'destructive',
};

const STATUS_LABEL: Record<UserStatus, string> = {
  [USER_STATUS.ACTIVE]: 'Active',
  [USER_STATUS.PENDING]: 'Pending first sign-in',
  [USER_STATUS.LOCKED]: 'Locked',
  [USER_STATUS.SUSPENDED]: 'Suspended',
};

export function StatusBadge({ status }: { status: UserStatus }): React.ReactElement {
  return <Badge variant={STATUS_VARIANT[status] ?? 'secondary'}>{STATUS_LABEL[status] ?? status}</Badge>;
}

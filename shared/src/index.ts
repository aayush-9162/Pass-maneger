/**
 * @passm/shared - single source of truth for cross-package contracts.
 *
 * Anything imported by more than one of backend / frontend / browser-extension
 * belongs here. This entry point must stay dependency-free and runtime-agnostic
 * (no Node built-ins, no DOM APIs) so it can be bundled anywhere.
 */

export * from './constants/roles';
export * from './constants/permissions';
export * from './constants/sharing';
export * from './constants/collaboration';
export * from './constants/crypto';
export * from './constants/security';
export * from './constants/api';
export * from './constants/errors';

export * from './types/api';
export * from './types/user';
export * from './types/device';
export * from './types/session';
export * from './types/auth';
export * from './types/audit';
export * from './types/vault';
export * from './types/sharing';
export * from './types/health';
export * from './types/admin';
export * from './types/collaboration';
export * from './types/security';

export * from './utils/password-generator';
export * from './utils/password-health';
export * from './utils/ip';

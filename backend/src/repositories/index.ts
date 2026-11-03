/** Barrel for the repository layer (the only place that speaks SQL). */

export { roleRepository, clearRoleCache } from './role.repository';
export {
  userRepository,
  type AdminUserRecord,
  type CreateUserInput,
  type ListUsersFilter,
  type UpdateUserProfileInput,
} from './user.repository';
export { sessionRepository, type CreateSessionInput } from './session.repository';
export { deviceRepository, type UpsertDeviceInput } from './device.repository';
export {
  auditLogRepository,
  type CreateAuditLogInput,
  type ListAuditLogsFilter,
} from './audit-log.repository';
export { loginAttemptRepository, type CreateLoginAttemptInput } from './login-attempt.repository';
export {
  sharedVaultRepository,
  type CreateSharedVaultInput,
  type ListSharedVaultsFilter,
  type UpdateSharedVaultInput,
} from './shared-vault.repository';
export {
  passwordHealthRepository,
  type ListReportsFilter,
  type UpsertReportInput,
} from './password-health.repository';
export { analyticsRepository } from './analytics.repository';
export {
  accessRequestRepository,
  type CreateRequestInput,
  type ListRequestsFilter,
} from './access-request.repository';

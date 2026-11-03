-- ===========================================================================
-- PassM - schema
-- Target: MySQL 8.0.19 or newer (CHECK constraints, JSON, and the row-alias
-- form of ON DUPLICATE KEY UPDATE used by the grant and device upserts).
--
-- One file because the project has never shipped: the twelve migrations that
-- built the old schema were folded into this one when sign-in moved to Google
-- and encryption moved to the server. Add a new numbered file for any change
-- from here on - the runner refuses an edited file that has already run.
--
-- Model
--   * Sign-in is Google only. `users` holds no password material at all.
--   * A password lives in `shared_vault_items`. A "group" is a vault of
--     kind 'group'; an individual password is a vault of kind 'item' wrapping
--     exactly one entry, so sharing either is the same grant.
--   * Access is a grant: user -> vault, with a role and restrictions.
--   * Item contents are AES-256-GCM envelopes written by the server under
--     ENCRYPTION_KEY. The database alone decrypts nothing; the database plus
--     that key decrypts everything. There are no per-user or per-vault keys.
--
-- Conventions
--   * InnoDB / utf8mb4 everywhere.
--   * Primary keys are application-generated UUIDv4 as CHAR(36) ascii.
--   * DATETIME(3) in UTC (the pool sets `timezone: 'Z'`).
--   * Hash columns are CHAR(64) ascii = hex HMAC-SHA-256 / SHA-256.
--   * IP addresses are VARCHAR(45).
--
-- Prerequisite (once, as a privileged user):
--   CREATE DATABASE passm CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
--   CREATE USER 'passm_app'@'%' IDENTIFIED BY '<strong-password>';
--   GRANT SELECT, INSERT, UPDATE, DELETE ON passm.* TO 'passm_app'@'%';
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- Roles. Ids are fixed literals shared with ROLES in @passm/shared.
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
  id          CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  name        VARCHAR(32)  NOT NULL COMMENT 'admin | manager | employee',
  label       VARCHAR(64)  NOT NULL,
  description VARCHAR(255) NULL,
  level       SMALLINT UNSIGNED NOT NULL COMMENT 'Privilege weight; higher wins',
  is_system   TINYINT(1)   NOT NULL DEFAULT 1,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_roles_name (name)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

INSERT INTO roles (id, name, label, description, level) VALUES
  ('11111111-1111-4111-8111-111111111111', 'admin', 'Administrator',
   'Full control: provisions users, assigns roles, revokes any session or device, reads the audit trail.', 100),
  ('22222222-2222-4222-8222-222222222222', 'manager', 'Manager',
   'Read-only oversight: can view users, their sessions and devices, and the audit trail. Cannot provision or revoke.', 50),
  ('33333333-3333-4333-8333-333333333333', 'employee', 'Employee',
   'Standard user: uses the passwords shared with them.', 10);

-- ---------------------------------------------------------------------------
-- Users. Identity comes from Google; nothing here can authenticate anyone.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
  id                CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  email             VARCHAR(255) NOT NULL COMMENT 'Always stored lowercase',
  google_subject    VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL
                    COMMENT 'Google `sub` claim, linked on first sign-in. Stable across email renames.',
  first_name        VARCHAR(100) NOT NULL,
  last_name         VARCHAR(100) NOT NULL,
  job_title         VARCHAR(100) NULL,
  role_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  status            ENUM('active', 'pending', 'locked', 'suspended') NOT NULL DEFAULT 'pending'
                    COMMENT 'pending = created but never signed in',
  locked_until      DATETIME(3)  NULL COMMENT 'Administrative lock expiry; far future for an open-ended lock',
  lock_reason       VARCHAR(200) NULL,
  locked_by_user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  last_login_at     DATETIME(3)  NULL,
  last_login_ip     VARCHAR(45)  NULL,
  created_by        CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL
                    COMMENT 'Admin who created the account; NULL when created by its own first sign-in',
  created_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at        DATETIME(3)  NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  UNIQUE KEY uq_users_google_subject (google_subject),
  KEY idx_users_role (role_id),
  KEY idx_users_status (status),
  KEY idx_users_deleted_at (deleted_at),
  KEY idx_users_created_at (created_at),
  CONSTRAINT fk_users_role       FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_users_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT fk_users_locked_by  FOREIGN KEY (locked_by_user_id) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT chk_users_email_lowercase CHECK (email = LOWER(email)),
  CONSTRAINT chk_users_email_shape     CHECK (email LIKE '%_@_%._%')
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Devices and sessions
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
  id                  CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  user_id             CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  device_id           VARCHAR(64)  NOT NULL COMMENT 'Client-generated stable identifier (UUIDv4)',
  name                VARCHAR(120) NOT NULL DEFAULT 'Unknown device',
  platform            ENUM('web', 'extension', 'desktop', 'mobile', 'unknown') NOT NULL DEFAULT 'unknown',
  fingerprint_hash    CHAR(64) CHARACTER SET ascii COLLATE ascii_general_ci NULL
                      COMMENT 'SHA-256 of client-reported signals',
  status              ENUM('registered', 'trusted', 'revoked') NOT NULL DEFAULT 'registered',
  approval_state      ENUM('approved', 'pending', 'rejected') NOT NULL DEFAULT 'approved',
  approved_by_user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  approved_at         DATETIME(3)  NULL,
  trust_token_hash    CHAR(64) CHARACTER SET ascii COLLATE ascii_general_ci NULL
                      COMMENT 'HMAC-SHA-256 of the device-trust token',
  trust_granted_at    DATETIME(3)  NULL,
  trust_expires_at    DATETIME(3)  NULL,
  last_ip_address     VARCHAR(45)  NULL,
  last_user_agent     VARCHAR(512) NULL,
  last_used_at        DATETIME(3)  NULL,
  created_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_devices_user_device (user_id, device_id),
  KEY idx_devices_user_status (user_id, status),
  KEY idx_devices_approval (approval_state, created_at),
  KEY idx_devices_trust_expires (trust_expires_at),
  KEY idx_devices_last_used (last_used_at),
  CONSTRAINT fk_devices_user     FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_devices_approver FOREIGN KEY (approved_by_user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE sessions (
  id                          CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  user_id                     CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  device_id                   CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  refresh_token_hash          CHAR(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL
                              COMMENT 'HMAC-SHA-256 of the current refresh token',
  previous_refresh_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_general_ci NULL
                              COMMENT 'Superseded token; a hit here means replay',
  refresh_token_generation    INT UNSIGNED NOT NULL DEFAULT 0,
  status                      ENUM('active', 'rotated', 'revoked', 'expired') NOT NULL DEFAULT 'active',
  ip_address                  VARCHAR(45)  NULL,
  user_agent                  VARCHAR(512) NULL,
  created_at                  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  last_activity_at            DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires_at                  DATETIME(3)  NOT NULL,
  absolute_expires_at         DATETIME(3)  NULL COMMENT 'Hard deadline fixed at sign-in',
  revoked_at                  DATETIME(3)  NULL,
  revoked_reason              VARCHAR(64)  NULL COMMENT 'See SESSION_REVOKE_REASON in @passm/shared',
  PRIMARY KEY (id),
  UNIQUE KEY uq_sessions_refresh_token_hash (refresh_token_hash),
  KEY idx_sessions_previous_hash (previous_refresh_token_hash),
  KEY idx_sessions_user_status (user_id, status),
  KEY idx_sessions_device (device_id),
  KEY idx_sessions_expires_at (expires_at),
  KEY idx_sessions_absolute_expiry (absolute_expires_at),
  KEY idx_sessions_last_activity (last_activity_at),
  CONSTRAINT fk_sessions_user   FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_sessions_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- Every Google sign-in attempt, kept for the sign-in analytics. Pruned by the
-- maintenance job.
CREATE TABLE login_attempts (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email          VARCHAR(255) NOT NULL COMMENT 'As asserted by Google, or as submitted; may not exist',
  ip_address     VARCHAR(45)  NOT NULL,
  user_id        CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  successful     TINYINT(1)   NOT NULL,
  failure_reason VARCHAR(64)  NULL,
  user_agent     VARCHAR(512) NULL,
  created_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_login_attempts_email_created (email, created_at),
  KEY idx_login_attempts_ip_created (ip_address, created_at),
  KEY idx_login_attempts_success_created (successful, created_at),
  KEY idx_login_attempts_created (created_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Password groups ("shared vaults") and their contents
-- ---------------------------------------------------------------------------
CREATE TABLE shared_vaults (
  id                         CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  name                       VARCHAR(150) NOT NULL,
  description                VARCHAR(500) NULL,
  color                      VARCHAR(24)  NULL COMMENT 'UI token, e.g. "amber". Cosmetic only.',
  kind                       ENUM('group', 'item') NOT NULL DEFAULT 'group'
                             COMMENT 'group = named collection; item = wrapper around one individual password',
  require_approval_to_join   TINYINT(1)   NOT NULL DEFAULT 0,
  require_approval_to_reveal TINYINT(1)   NOT NULL DEFAULT 0
                             COMMENT 'Passwords are released only after an approved reveal request',
  status                     ENUM('active', 'archived') NOT NULL DEFAULT 'active',
  revision                   INT UNSIGNED NOT NULL DEFAULT 1,
  created_by                 CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  created_at                 DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at                 DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at                 DATETIME(3)  NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_shared_vaults_name (name),
  KEY idx_shared_vaults_kind (kind, deleted_at),
  KEY idx_shared_vaults_status (status, deleted_at),
  CONSTRAINT fk_shared_vaults_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE shared_vault_grants (
  id              CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  shared_vault_id CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  subject_type    ENUM('user') NOT NULL,
  subject_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  permissions     VARCHAR(120) NOT NULL COMMENT 'Comma-separated subset of read,edit,delete,share,admin',
  access_role     ENUM('owner', 'admin', 'editor', 'viewer') NOT NULL DEFAULT 'viewer'
                  COMMENT 'Named preset; `permissions` is what the API enforces',
  hidden_password TINYINT(1)   NOT NULL DEFAULT 0 COMMENT 'The server never releases passwords to this member',
  copy_only       TINYINT(1)   NOT NULL DEFAULT 0 COMMENT 'Clients copy or fill but do not display',
  no_edit         TINYINT(1)   NOT NULL DEFAULT 0,
  no_delete       TINYINT(1)   NOT NULL DEFAULT 0,
  granted_by      CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_grants_vault_subject (shared_vault_id, subject_type, subject_id),
  KEY idx_grants_subject (subject_type, subject_id),
  CONSTRAINT fk_grants_vault      FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_grants_granted_by FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE shared_vault_items (
  id               CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  shared_vault_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  type             ENUM('login', 'secure_note', 'card', 'identity', 'ssh_key', 'api_key') NOT NULL,
  encrypted_data   TEXT NOT NULL COMMENT 'Server envelope of name, username, URLs, notes. AAD binds it to the item id.',
  encrypted_secret TEXT NULL COMMENT 'Server envelope of the password and TOTP, released separately',
  favorite         TINYINT(1)   NOT NULL DEFAULT 0,
  revision         INT UNSIGNED NOT NULL DEFAULT 1,
  created_by       CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  updated_by       CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  created_at       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at       DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  deleted_at       DATETIME(3)  NULL,
  PRIMARY KEY (id),
  KEY idx_shared_items_vault_updated (shared_vault_id, deleted_at, updated_at),
  CONSTRAINT fk_shared_items_vault      FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_shared_items_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT fk_shared_items_updated_by FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE access_requests (
  id                CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  shared_vault_id   CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  requester_user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  request_type      ENUM('access', 'reveal', 'elevate') NOT NULL
                    COMMENT 'access = join, reveal = see hidden passwords, elevate = more rights',
  requested_role    ENUM('owner', 'admin', 'editor', 'viewer') NULL,
  item_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  reason            VARCHAR(500) NOT NULL,
  status            ENUM('pending', 'approved', 'denied', 'cancelled', 'expired') NOT NULL DEFAULT 'pending',
  decided_by        CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  decided_at        DATETIME(3)  NULL,
  decision_note     VARCHAR(500) NULL,
  expires_at        DATETIME(3)  NOT NULL,
  created_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_requests_vault_status (shared_vault_id, status),
  KEY idx_requests_requester (requester_user_id, status),
  KEY idx_requests_status_created (status, created_at),
  CONSTRAINT fk_requests_vault      FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_requests_requester  FOREIGN KEY (requester_user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_requests_decided_by FOREIGN KEY (decided_by) REFERENCES users (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Password health
-- ---------------------------------------------------------------------------
CREATE TABLE password_health_reports (
  user_id                CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  total_items            INT UNSIGNED NOT NULL DEFAULT 0,
  assessed_items         INT UNSIGNED NOT NULL DEFAULT 0,
  weak_count             INT UNSIGNED NOT NULL DEFAULT 0,
  reused_count           INT UNSIGNED NOT NULL DEFAULT 0,
  old_count              INT UNSIGNED NOT NULL DEFAULT 0,
  compromised_count      INT UNSIGNED NOT NULL DEFAULT 0,
  health_score           TINYINT UNSIGNED NOT NULL DEFAULT 100 COMMENT '0-100',
  breach_check_performed TINYINT(1)   NOT NULL DEFAULT 0 COMMENT 'False means "not checked", not "clean"',
  generated_at           DATETIME(3)  NOT NULL,
  created_at             DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at             DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (user_id),
  KEY idx_health_score (health_score),
  KEY idx_health_generated (generated_at),
  CONSTRAINT fk_health_reports_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE password_health_findings (
  user_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  item_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  shared_vault_id CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  severity        ENUM('critical', 'high', 'medium', 'low', 'ok') NOT NULL,
  issues          VARCHAR(120) NOT NULL COMMENT 'Comma-separated: weak,reused,old,compromised,short,missing',
  strength_score  TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '0-4',
  entropy_bits    SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  password_length SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  age_days        INT UNSIGNED NULL,
  duplicate_count SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (user_id, item_id),
  KEY idx_findings_severity (user_id, severity),
  CONSTRAINT fk_health_findings_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Security policy and monitoring
-- ---------------------------------------------------------------------------
CREATE TABLE security_settings (
  setting_key        VARCHAR(64) NOT NULL,
  setting_value      JSON        NOT NULL,
  updated_by_user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  created_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (setting_key),
  CONSTRAINT fk_security_settings_user FOREIGN KEY (updated_by_user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE ip_rules (
  id                 CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  cidr               VARCHAR(64)  NOT NULL,
  label              VARCHAR(128) NOT NULL,
  scope              ENUM('global', 'user', 'role') NOT NULL DEFAULT 'global',
  user_id            CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  role_name          VARCHAR(50)  NULL,
  enabled            TINYINT(1)   NOT NULL DEFAULT 1,
  match_count        BIGINT UNSIGNED NOT NULL DEFAULT 0,
  last_matched_at    DATETIME(3)  NULL,
  created_by_user_id CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  created_at         DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at         DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_ip_rules_scope_cidr (scope, user_id, role_name, cidr),
  KEY idx_ip_rules_enabled (enabled, scope),
  CONSTRAINT fk_ip_rules_user    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_ip_rules_creator FOREIGN KEY (created_by_user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE security_notifications (
  id           CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  user_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  type         VARCHAR(48)  NOT NULL,
  severity     ENUM('info', 'warning', 'critical') NOT NULL DEFAULT 'info',
  title        VARCHAR(160) NOT NULL,
  body         VARCHAR(600) NOT NULL,
  metadata     JSON         NULL,
  action_url   VARCHAR(255) NULL,
  action_label VARCHAR(64)  NULL,
  read_at      DATETIME(3)  NULL,
  created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_notifications_user_unread (user_id, read_at, created_at),
  KEY idx_notifications_created (created_at),
  CONSTRAINT fk_notifications_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- A Google re-confirmation before a sensitive action. `nonce` is passed to
-- Google and must come back inside the ID token.
CREATE TABLE step_up_challenges (
  id             CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  user_id        CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  session_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  action         VARCHAR(32) NOT NULL,
  nonce          VARCHAR(88) NOT NULL COMMENT 'base64url, 64 random bytes',
  verified_at    DATETIME(3) NULL,
  verified_until DATETIME(3) NULL,
  attempts       TINYINT UNSIGNED NOT NULL DEFAULT 0,
  expires_at     DATETIME(3) NOT NULL,
  created_at     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_step_up_user_action (user_id, action, verified_until),
  KEY idx_step_up_expires (expires_at),
  CONSTRAINT fk_step_up_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE security_score_history (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  score         TINYINT UNSIGNED NOT NULL,
  grade         CHAR(1) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  areas         JSON NOT NULL,
  finding_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  computed_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_score_history_computed (computed_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Audit trail. Append-only; no foreign keys so it survives user deletion.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_logs (
  id                 CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  action             VARCHAR(64)  NOT NULL COMMENT 'See AUDIT_ACTIONS in @passm/shared',
  outcome            ENUM('success', 'failure') NOT NULL,
  actor_user_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL COMMENT 'NULL before authentication',
  actor_email        VARCHAR(255) NULL COMMENT 'Denormalised so the trail survives renames',
  target_user_id     CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  resource_type      VARCHAR(32)  NULL,
  resource_id        CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  is_shared_resource TINYINT(1)   NOT NULL DEFAULT 0 COMMENT '1 = organisational property, visible to managers',
  session_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  device_id          CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  ip_address         VARCHAR(45)  NULL,
  user_agent         VARCHAR(512) NULL,
  request_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
  metadata           JSON         NULL COMMENT 'Non-sensitive context; never tokens or secrets',
  created_at         DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_audit_created_at (created_at),
  KEY idx_audit_action_created (action, created_at),
  KEY idx_audit_actor_created (actor_user_id, created_at),
  KEY idx_audit_target_created (target_user_id, created_at),
  KEY idx_audit_resource (resource_type, resource_id, created_at),
  KEY idx_audit_shared_created (is_shared_resource, created_at),
  KEY idx_audit_outcome_created (outcome, created_at),
  KEY idx_audit_ip_created (ip_address, created_at),
  KEY idx_audit_device_created (device_id, created_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

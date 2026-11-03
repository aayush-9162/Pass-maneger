-- ===========================================================================
-- Default groups: every new account is granted these automatically.
--
-- `auto_grant_role` NULL means the group is not a default. Otherwise it is the
-- role a new account receives on it, at the moment the account is created -
-- by a first Google sign-in or by an administrator. Accounts that already
-- exist are not touched. Owner is deliberately not offered: a default group
-- must not hand control of itself to everyone who joins the company.
-- ===========================================================================

ALTER TABLE shared_vaults
  ADD COLUMN auto_grant_role ENUM('admin', 'editor', 'viewer') NULL
      COMMENT 'Role every new account receives on this group; NULL = not a default group'
      AFTER require_approval_to_reveal,
  ADD KEY idx_shared_vaults_auto_grant (auto_grant_role);

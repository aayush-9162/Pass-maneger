-- ============================================================================
-- PassVault Database Schema
-- Zero-Knowledge Password Manager — MySQL
--
-- Run once:  mysql -u root -p < schema.sql
-- ============================================================================

CREATE DATABASE IF NOT EXISTS passvault
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE passvault;

-- ── Users ──────────────────────────────────────────────────────────────────
-- password_hash : bcrypt hash of the LOGIN password (NOT the master password)
-- salt          : base64-encoded 32-byte random salt used by the CLIENT for
--                 PBKDF2 key derivation from the master password.
--                 The server stores it but never uses it for decryption.
-- ───────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id            CHAR(36)     NOT NULL PRIMARY KEY,
  email         VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  salt          VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

  INDEX idx_users_email (email)
) ENGINE=InnoDB;

-- ── Vault ──────────────────────────────────────────────────────────────────
-- encrypted_data : AES-256-GCM ciphertext + 128-bit auth tag (base64)
-- iv             : 96-bit initialization vector (base64)
--
-- SECURITY: The server treats these columns as OPAQUE BLOBS.
--           No server-side code ever decrypts, inspects, or validates
--           the plaintext content. Decryption is client-only.
-- ───────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vault (
  id             CHAR(36) NOT NULL PRIMARY KEY,
  user_id        CHAR(36) NOT NULL,
  encrypted_data TEXT     NOT NULL,
  iv             VARCHAR(64) NOT NULL,
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  INDEX idx_vault_user_id (user_id),
  CONSTRAINT fk_vault_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

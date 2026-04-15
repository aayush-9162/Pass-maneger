/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  PassVault — Client-Side Cryptography Module                            ║
 * ║                                                                          ║
 * ║  Zero-knowledge encryption using the Web Crypto API (SubtleCrypto).     ║
 * ║  ALL encryption and decryption happens EXCLUSIVELY in the browser.      ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * ┌──────────────────────────────────────────────────────────────────────────┐
 * │  DATA FLOW                                                               │
 * │                                                                          │
 * │  USER ENTERS MASTER PASSWORD (never stored, never transmitted)          │
 * │        │                                                                 │
 * │        ▼                                                                 │
 * │  ┌─────────────────────────────────────────────────┐                    │
 * │  │  PBKDF2 (300,000 iterations, SHA-256)           │                    │
 * │  │  masterPassword + salt → AES-256-GCM CryptoKey  │                    │
 * │  └──────────────────────┬──────────────────────────┘                    │
 * │                         │                                                │
 * │           ┌─────────────┼─────────────┐                                 │
 * │           ▼             ▼             ▼                                  │
 * │       ENCRYPT       DECRYPT       VERIFY                                │
 * │           │             │             │                                  │
 * │           ▼             ▼             ▼                                  │
 * │    {ciphertext,iv}  {plaintext}   true/false                            │
 * │           │                                                              │
 * │           ▼                                                              │
 * │    SENT TO SERVER (blind storage — server never decrypts)               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY INVARIANTS:
 *  1. Master password NEVER leaves this module
 *  2. CryptoKey is non-extractable — browser refuses to export raw key bytes
 *  3. Every encryption uses a fresh 96-bit random IV (AES-GCM requirement)
 *  4. AES-GCM provides authenticated encryption (confidentiality + integrity)
 *  5. 300k PBKDF2 iterations make brute-force from a stolen DB infeasible
 *
 * UPGRADE PATH:
 *  deriveKey() is the only PBKDF2-coupled function. To upgrade to Argon2id
 *  (via a WASM build), replace ONLY that function. encryptData/decryptData
 *  don't care how the CryptoKey was derived.
 */

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * PBKDF2 iteration count.
 * 300,000 with SHA-256 exceeds OWASP 2024 recommendations. At this level
 * each brute-force guess costs ~300k hash operations, making offline attacks
 * on a stolen database infeasible for reasonable password entropy.
 * Derivation completes in 200-800ms on modern hardware.
 */
const PBKDF2_ITERATIONS = 300_000;

/** AES key size in bits. AES-256 provides a 256-bit security level. */
const AES_KEY_LENGTH_BITS = 256;

/**
 * Initialization vector length in bytes.
 * NIST SP 800-38D mandates 96-bit (12-byte) IVs for AES-GCM.
 * Other lengths trigger an internal GHASH step that weakens the
 * birthday-bound guarantee from 2^32 to something smaller.
 */
const IV_BYTE_LENGTH = 12;

/**
 * GCM authentication tag length in bits. 128 is the maximum and
 * provides the strongest integrity guarantee. We set it explicitly
 * rather than relying on the default to prevent accidental weakening.
 */
const TAG_LENGTH_BITS = 128;

/** Sentinel embedded in key-verification records. */
const KEY_CHECK_SENTINEL = 'passvault-key-check-v1';

// ─── Custom Error Types ──────────────────────────────────────────────────────

/**
 * Base error for all cryptographic operations.
 * Carries an optional `cause` for error-chain debugging.
 */
export class CryptoError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'CryptoError';
    if (cause) this.cause = cause;
  }
}

/** Thrown when PBKDF2 key derivation fails (bad inputs or SubtleCrypto error). */
export class KeyDerivationError extends CryptoError {
  constructor(message, cause) {
    super(message, cause);
    this.name = 'KeyDerivationError';
  }
}

/** Thrown when decryption fails (wrong key, tampered data, corrupt IV). */
export class DecryptionError extends CryptoError {
  constructor(message, cause) {
    super(message, cause);
    this.name = 'DecryptionError';
  }
}

// ─── Key Derivation ──────────────────────────────────────────────────────────

/**
 * Derives a non-extractable AES-256-GCM CryptoKey from a master password
 * and a per-user salt using PBKDF2-HMAC-SHA256.
 *
 * Steps:
 *  1. UTF-8 encode the master password
 *  2. Import it as non-extractable PBKDF2 key material
 *  3. Run PBKDF2 with 300k iterations + user salt → AES-256-GCM key
 *
 * The returned CryptoKey:
 *  - Lives ONLY in browser memory (stored in React state by AuthContext)
 *  - Has extractable=false, so crypto.subtle.exportKey() will reject
 *  - Is garbage-collected when the React state reference is cleared (lock/logout)
 *  - Can only be passed to crypto.subtle.encrypt/decrypt
 *
 * @param {string} masterPassword — User's master password. Used transiently.
 * @param {string} saltBase64 — Base64-encoded 32-byte salt from the server DB.
 * @returns {Promise<CryptoKey>} Non-extractable AES-256-GCM encryption key.
 * @throws {KeyDerivationError} If inputs are invalid or SubtleCrypto fails.
 */
export async function deriveKey(masterPassword, saltBase64) {
  // ── Input validation ──────────────────────────────────────────────────
  if (!masterPassword || typeof masterPassword !== 'string') {
    throw new KeyDerivationError(
      'Master password is required and must be a non-empty string'
    );
  }
  if (!saltBase64 || typeof saltBase64 !== 'string') {
    throw new KeyDerivationError(
      'Salt is required and must be a non-empty base64 string'
    );
  }

  try {
    const encoder = new TextEncoder();

    // Decode the base64 salt from the server back to raw bytes
    const saltBytes = base64ToUint8Array(saltBase64);
    if (saltBytes.byteLength < 16) {
      throw new KeyDerivationError(
        `Salt too short: got ${saltBytes.byteLength} bytes, need at least 16`
      );
    }

    // Step 1: Import the master password as PBKDF2 key material.
    //   extractable: false  → the password bytes cannot be read back out
    //   usages: ['deriveKey'] → this material can ONLY be used for derivation
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(masterPassword),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    // Step 2: Derive the AES-256-GCM key.
    //   extractable: false  → the derived key cannot be exported
    //   usages: ['encrypt', 'decrypt'] → it can only encrypt/decrypt
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: AES_KEY_LENGTH_BITS },
      false,
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  } catch (err) {
    // Re-throw our own errors as-is, wrap anything else
    if (err instanceof KeyDerivationError) throw err;
    throw new KeyDerivationError('Key derivation failed', err);
  }
}

// ─── Encryption ──────────────────────────────────────────────────────────────

/**
 * Encrypts a JavaScript object with AES-256-GCM.
 *
 * Steps:
 *  1. JSON.stringify(data) → UTF-8 bytes
 *  2. Generate a fresh 96-bit random IV via crypto.getRandomValues()
 *  3. AES-GCM encrypt → ciphertext || 128-bit auth tag
 *  4. Base64-encode both ciphertext and IV for JSON transport
 *
 * CRITICAL: A fresh random IV is generated for EVERY call. Reusing an IV
 * with the same key under AES-GCM catastrophically breaks both
 * confidentiality AND authenticity. With 96-bit random IVs, collision
 * probability stays below 2^-32 for up to ~4 billion encryptions.
 *
 * @param {object} data — Plaintext object, e.g. { site, username, password }
 * @param {CryptoKey} key — Derived AES-256-GCM key from deriveKey()
 * @returns {Promise<{ encryptedData: string, iv: string }>}
 *   Base64-encoded ciphertext (with appended auth tag) and IV.
 * @throws {CryptoError} If inputs are invalid or encryption fails.
 */
export async function encryptData(data, key) {
  if (!data || typeof data !== 'object') {
    throw new CryptoError('Data must be a non-null object');
  }
  if (!key) {
    throw new CryptoError('Encryption key is required — is the vault unlocked?');
  }

  try {
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(JSON.stringify(data));

    // Generate a cryptographically random IV for this single operation.
    // The OS CSPRNG backs crypto.getRandomValues (e.g. /dev/urandom,
    // BCryptGenRandom on Windows).
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));

    // Encrypt. The output ArrayBuffer contains: ciphertext || 128-bit GCM tag.
    // SubtleCrypto handles the tag internally — it's appended to the ciphertext.
    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_LENGTH_BITS },
      key,
      plaintextBytes
    );

    // Base64-encode for transport. The server stores these as opaque strings.
    return {
      encryptedData: uint8ArrayToBase64(new Uint8Array(ciphertextBuffer)),
      iv: uint8ArrayToBase64(iv),
    };
  } catch (err) {
    if (err instanceof CryptoError) throw err;
    throw new CryptoError('Encryption failed', err);
  }
}

// ─── Decryption ──────────────────────────────────────────────────────────────

/**
 * Decrypts AES-256-GCM ciphertext back to a JavaScript object.
 *
 * Steps:
 *  1. Base64-decode ciphertext and IV
 *  2. Validate IV length (must be exactly 12 bytes)
 *  3. AES-GCM decrypt (verifies 128-bit auth tag atomically)
 *  4. UTF-8 decode → JSON.parse → return the object
 *
 * Failure modes (all throw DecryptionError):
 *  - Wrong key          → GCM auth tag mismatch → OperationError
 *  - Tampered ciphertext → GCM auth tag mismatch → OperationError
 *  - Corrupted IV        → GCM auth tag mismatch → OperationError
 *  - Truncated data      → SubtleCrypto rejects
 *  - Invalid JSON        → wrong key produced garbage bytes
 *
 * @param {string} encryptedDataBase64 — Base64-encoded ciphertext from server
 * @param {string} ivBase64 — Base64-encoded IV from server
 * @param {CryptoKey} key — Derived AES-256-GCM key
 * @returns {Promise<object>} The original plaintext object.
 * @throws {DecryptionError} On any decryption or integrity failure.
 */
export async function decryptData(encryptedDataBase64, ivBase64, key) {
  if (!encryptedDataBase64 || typeof encryptedDataBase64 !== 'string') {
    throw new DecryptionError('Encrypted data must be a non-empty string');
  }
  if (!ivBase64 || typeof ivBase64 !== 'string') {
    throw new DecryptionError('IV must be a non-empty string');
  }
  if (!key) {
    throw new DecryptionError('Decryption key is required — is the vault unlocked?');
  }

  try {
    const ciphertextBytes = base64ToUint8Array(encryptedDataBase64);
    const ivBytes = base64ToUint8Array(ivBase64);

    // Enforce the NIST-mandated 96-bit IV length
    if (ivBytes.byteLength !== IV_BYTE_LENGTH) {
      throw new DecryptionError(
        `Invalid IV length: got ${ivBytes.byteLength} bytes, expected ${IV_BYTE_LENGTH}`
      );
    }

    // Decrypt and verify the auth tag in one atomic operation.
    // If the tag doesn't match, SubtleCrypto throws an OperationError.
    const plaintextBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, tagLength: TAG_LENGTH_BITS },
      key,
      ciphertextBytes
    );

    // Decode the plaintext bytes back to a string
    const decoder = new TextDecoder();
    const jsonString = decoder.decode(plaintextBuffer);

    // Parse the JSON — if somehow garbled, this catches it
    try {
      const parsed = JSON.parse(jsonString);
      if (typeof parsed !== 'object' || parsed === null) {
        throw new DecryptionError('Decrypted payload is not a valid JSON object');
      }
      return parsed;
    } catch (parseErr) {
      if (parseErr instanceof DecryptionError) throw parseErr;
      throw new DecryptionError(
        'Decrypted data is not valid JSON — wrong master password?',
        parseErr
      );
    }
  } catch (err) {
    if (err instanceof DecryptionError) throw err;

    // OperationError from SubtleCrypto = GCM auth tag verification failed.
    // This is the EXPECTED failure when the wrong key is used.
    if (err.name === 'OperationError') {
      throw new DecryptionError(
        'Decryption failed — wrong master password or corrupted data',
        err
      );
    }

    throw new DecryptionError('Decryption failed unexpectedly', err);
  }
}

// ─── Key Verification ────────────────────────────────────────────────────────

/**
 * Creates a verification record: encrypts a known sentinel with the key.
 *
 * This lets us check on subsequent unlocks whether the derived key is
 * correct BEFORE decrypting the entire vault. If decryption of the
 * sentinel fails, we know immediately the master password was wrong.
 *
 * @param {CryptoKey} key — The derived key to create a verifier for.
 * @returns {Promise<{ encryptedData: string, iv: string }>}
 */
export async function createKeyVerifier(key) {
  return encryptData(
    { sentinel: KEY_CHECK_SENTINEL, ts: Date.now() },
    key
  );
}

/**
 * Tests whether a derived key can decrypt the stored verification record
 * and produce the expected sentinel value.
 *
 * @param {string} encryptedDataBase64 — Stored verifier ciphertext.
 * @param {string} ivBase64 — Stored verifier IV.
 * @param {CryptoKey} key — The key to test.
 * @returns {Promise<boolean>} true if the key is correct.
 */
export async function verifyKey(encryptedDataBase64, ivBase64, key) {
  try {
    const result = await decryptData(encryptedDataBase64, ivBase64, key);
    return result?.sentinel === KEY_CHECK_SENTINEL;
  } catch {
    return false;
  }
}

// ─── Base64 Utilities ────────────────────────────────────────────────────────
//
// Browser-safe base64 encoding/decoding for byte arrays.
// We can't use Node's Buffer here; atob/btoa work with Latin-1 binary strings.

/**
 * Encodes a Uint8Array → base64 string.
 * Processes in 8 KB chunks to avoid call-stack overflow on large payloads.
 */
function uint8ArrayToBase64(bytes) {
  const CHUNK = 8192;
  let binary = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const slice = bytes.subarray(i, i + CHUNK);
    binary += String.fromCharCode.apply(null, slice);
  }
  return btoa(binary);
}

/**
 * Decodes a base64 string → Uint8Array.
 */
function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

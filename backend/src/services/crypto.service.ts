/**
 * Cryptographic primitives.
 *
 * Two concerns, kept apart:
 *
 *  1. **Secrets at rest** -> AES-256-GCM under ENCRYPTION_KEY. Every stored
 *     password lives in one of these envelopes. The key lives outside the
 *     database, so a dump alone decrypts nothing - and the dump plus the key
 *     decrypts everything, which is why ENCRYPTION_KEY is the one secret this
 *     deployment cannot afford to lose or leak.
 *  2. **Token hashing** -> HMAC-SHA-256 under a subkey derived from the same
 *     key, so refresh and trust tokens are stored as values a dump cannot
 *     replay.
 *
 * Every function is deliberately small and side-effect free so the choices above
 * can be audited in one sitting.
 */

import crypto from 'node:crypto';

import {
  AES_ALGORITHM,
  AES_IV_BYTES,
  AES_KEY_BYTES,
  CIPHER_ENVELOPE_VERSION,
} from '@passm/shared';

import { env } from '../config/env';
import { InternalError } from '../utils/errors';

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/** Decoded AES keys, indexed by key id, so ciphertext is self-describing. */
const encryptionKeys = new Map<string, Buffer>();

function loadKeys(): void {
  if (encryptionKeys.size > 0) return;

  const primary = Buffer.from(env.crypto.encryptionKey, 'base64');
  if (primary.length !== AES_KEY_BYTES) {
    // Unreachable: env.ts validates the length. Kept as a tripwire in case the
    // validation is ever relaxed.
    throw new InternalError('ENCRYPTION_KEY must decode to exactly 32 bytes.');
  }
  encryptionKeys.set(env.crypto.encryptionKeyId, primary);

  // The previous key is decrypt-only: it lets a key rotation proceed without a
  // flag-day re-encryption of every existing row.
  if (env.crypto.previousEncryptionKey) {
    encryptionKeys.set(
      env.crypto.previousEncryptionKeyId,
      Buffer.from(env.crypto.previousEncryptionKey, 'base64'),
    );
  }
}

/**
 * Purpose-separated subkey derived from the master encryption key via HKDF.
 *
 * Reusing one key for both encryption and token hashing would be a cross-purpose
 * key reuse bug; HKDF gives an independent key per purpose from a single
 * configured secret, so operators still manage exactly one value.
 */
function deriveSubkey(purpose: string): Buffer {
  loadKeys();
  const masterKey = encryptionKeys.get(env.crypto.encryptionKeyId) as Buffer;
  return Buffer.from(
    crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), `passm/${purpose}/v1`, 32),
  );
}

let tokenHashKey: Buffer | null = null;

function getTokenHashKey(): Buffer {
  tokenHashKey ??= deriveSubkey('token-hash');
  return tokenHashKey;
}

// ---------------------------------------------------------------------------
// AES-256-GCM (secrets at rest)
// ---------------------------------------------------------------------------

/**
 * Encrypt `plaintext` into a self-describing envelope:
 *
 * ```
 * v1.<keyId>.<iv-b64url>.<authTag-b64url>.<ciphertext-b64url>
 * ```
 *
 * GCM is authenticated encryption: `decrypt` fails loudly if a single byte of
 * the ciphertext, IV or tag was altered, so stored secrets are tamper-evident
 * rather than silently corrupted.
 *
 * @param aad Optional additional authenticated data - pass a stable value such
 *   as the owning user id to bind the ciphertext to its row. A blob copied to
 *   another user's row then fails authentication.
 */
export function encrypt(plaintext: string, aad?: string): string {
  loadKeys();

  const keyId = env.crypto.encryptionKeyId;
  const key = encryptionKeys.get(keyId);
  if (!key) throw new InternalError('Encryption key is not available.');

  // A fresh random IV per message. Never reuse an IV with the same key: with
  // GCM that leaks the XOR of the plaintexts and breaks authentication entirely.
  const iv = crypto.randomBytes(AES_IV_BYTES);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);

  if (aad !== undefined) cipher.setAAD(Buffer.from(aad, 'utf8'));

  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [
    CIPHER_ENVELOPE_VERSION,
    keyId,
    iv.toString('base64url'),
    authTag.toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

/**
 * Decrypt an envelope produced by {@link encrypt}.
 *
 * @throws {InternalError} on a malformed envelope, an unknown key id, or a
 *   failed authentication check.
 */
export function decrypt(envelope: string, aad?: string): string {
  loadKeys();

  const parts = envelope.split('.');
  if (parts.length !== 5) {
    throw new InternalError('Malformed ciphertext envelope.');
  }

  const [version, keyId, ivPart, tagPart, ciphertextPart] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];

  if (version !== CIPHER_ENVELOPE_VERSION) {
    throw new InternalError(`Unsupported ciphertext version "${version}".`);
  }

  const key = encryptionKeys.get(keyId);
  if (!key) {
    throw new InternalError(
      `Ciphertext was encrypted with key "${keyId}", which is not configured. ` +
        'Restore it via ENCRYPTION_KEY_PREVIOUS to decrypt legacy rows.',
    );
  }

  try {
    const decipher = crypto.createDecipheriv(
      AES_ALGORITHM,
      key,
      Buffer.from(ivPart, 'base64url'),
    );
    decipher.setAuthTag(Buffer.from(tagPart, 'base64url'));
    if (aad !== undefined) decipher.setAAD(Buffer.from(aad, 'utf8'));

    return Buffer.concat([
      decipher.update(Buffer.from(ciphertextPart, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch (error) {
    // Do not surface the underlying reason: distinguishing "bad tag" from "bad
    // padding" is a padding-oracle-style information leak.
    throw new InternalError('Failed to decrypt stored secret.', { cause: error });
  }
}

/** True when a stored envelope was encrypted with a non-current key. */
export function needsReEncryption(envelope: string): boolean {
  const keyId = envelope.split('.')[1];
  return keyId !== undefined && keyId !== env.crypto.encryptionKeyId;
}

// ---------------------------------------------------------------------------
// Hashing / comparison helpers
// ---------------------------------------------------------------------------

/**
 * Keyed hash for storing a token.
 *
 * HMAC rather than a plain SHA-256: the key lives in the environment, so an
 * attacker with only a database dump cannot verify guessed tokens offline. The
 * output is 64 hex characters, matching the CHAR(64) columns.
 */
export function hashToken(token: string): string {
  return crypto.createHmac('sha256', getTokenHashKey()).update(token, 'utf8').digest('hex');
}

/** Unkeyed SHA-256, for non-secret values such as device fingerprints. */
export function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Constant-time string comparison.
 *
 * Compares digests rather than the raw inputs so that unequal lengths do not
 * short-circuit (and therefore do not leak length through timing).
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const digestA = crypto.createHash('sha256').update(a, 'utf8').digest();
  const digestB = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

/** URL-safe random token (default 256 bits). */
export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

export const cryptoService = {
  encrypt,
  decrypt,
  needsReEncryption,
  hashToken,
  sha256Hex,
  timingSafeEqual,
  randomToken,
};

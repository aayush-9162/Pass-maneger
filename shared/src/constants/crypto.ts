/**
 * Server-side encryption parameters.
 *
 * Every stored secret - item contents, MFA seeds, anything else confidential -
 * is an AES-256-GCM envelope written by the API under ENCRYPTION_KEY. These
 * values are part of the storage format: changing them needs a migration path,
 * never an in-place edit.
 */

export const AES_ALGORITHM = 'aes-256-gcm' as const;
export const AES_KEY_BYTES = 32; // 256-bit key
export const AES_IV_BYTES = 12; // 96-bit nonce, the GCM-recommended size

/** Envelope format prefix so encrypted blobs are self describing. */
export const CIPHER_ENVELOPE_VERSION = 'v1' as const;

/**
 * Secret generator.  `npm run generate:secrets`
 *
 * Prints a ready-to-paste block of cryptographically strong values for .env.
 * Writes to stdout only - nothing is persisted, so re-running is always safe.
 */

import crypto from 'node:crypto';

/** 64 hex chars = 256 bits of entropy, safe for HMAC/JWT signing keys. */
const hexSecret = (): string => crypto.randomBytes(32).toString('hex');

/** 32 raw bytes, base64 - exactly what AES-256-GCM requires. */
const aesKey = (): string => crypto.randomBytes(32).toString('base64');

/** Strong, typeable bootstrap password (no ambiguous characters). */
function bootstrapPassword(length = 24): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
  const bytes = crypto.randomBytes(length * 2);
  let output = '';
  for (let i = 0; output.length < length && i < bytes.length; i += 1) {
    // Rejection sampling keeps the distribution uniform (no modulo bias).
    const byte = bytes[i] as number;
    if (byte >= 256 - (256 % alphabet.length)) continue;
    output += alphabet[byte % alphabet.length];
  }
  return output;
}

process.stdout.write(
  [
    '',
    '# ---------------------------------------------------------------------------',
    '# Generated secrets - copy into backend/.env',
    '# Store production values in a secret manager, not in a file on disk.',
    '# ---------------------------------------------------------------------------',
    `JWT_ACCESS_SECRET=${hexSecret()}`,
    `JWT_REFRESH_SECRET=${hexSecret()}`,
    `JWT_DEVICE_TRUST_SECRET=${hexSecret()}`,
    `ENCRYPTION_KEY=${aesKey()}`,
    '',
    '# Optional bootstrap admin password (used only by `npm run db:seed`):',
    `SEED_ADMIN_PASSWORD=${bootstrapPassword()}`,
    '',
  ].join('\n'),
);

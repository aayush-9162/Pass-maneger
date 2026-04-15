/**
 * Cryptographically secure password generator.
 *
 * Uses crypto.getRandomValues() (backed by the OS CSPRNG) for all
 * randomness. Guarantees at least one character from each enabled
 * character class, then fills the rest from the combined charset
 * and Fisher-Yates shuffles with secure random indices.
 */

const CHARSETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits:    '0123456789',
  symbols:   '!@#$%^&*()_+-=[]{}|;:,.<>?',
};

/**
 * Generates a random password with guaranteed character-class diversity.
 *
 * @param {number} length — Desired length (minimum: 8, default: 20)
 * @param {object} options — Toggle character classes on/off
 * @param {boolean} options.lowercase — Include a-z (default: true)
 * @param {boolean} options.uppercase — Include A-Z (default: true)
 * @param {boolean} options.digits — Include 0-9 (default: true)
 * @param {boolean} options.symbols — Include special chars (default: true)
 * @returns {string} The generated password
 */
export function generatePassword(length = 20, options = {}) {
  const {
    lowercase = true,
    uppercase = true,
    digits = true,
    symbols = true,
  } = options;

  // Build the pool of enabled character classes
  let fullCharset = '';
  const requiredPools = [];

  if (lowercase) { fullCharset += CHARSETS.lowercase; requiredPools.push(CHARSETS.lowercase); }
  if (uppercase) { fullCharset += CHARSETS.uppercase; requiredPools.push(CHARSETS.uppercase); }
  if (digits)    { fullCharset += CHARSETS.digits;    requiredPools.push(CHARSETS.digits);    }
  if (symbols)   { fullCharset += CHARSETS.symbols;   requiredPools.push(CHARSETS.symbols);   }

  // Fallback if everything was disabled
  if (fullCharset.length === 0) {
    fullCharset = CHARSETS.lowercase + CHARSETS.uppercase + CHARSETS.digits;
    requiredPools.push(CHARSETS.lowercase, CHARSETS.uppercase, CHARSETS.digits);
  }

  const finalLength = Math.max(length, requiredPools.length, 8);

  // Guarantee at least one character from each enabled class
  const chars = requiredPools.map((pool) => secureRandomChar(pool));

  // Fill the rest from the combined charset
  for (let i = chars.length; i < finalLength; i++) {
    chars.push(secureRandomChar(fullCharset));
  }

  // Fisher-Yates shuffle with cryptographically secure random indices
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

/** Pick a random character from a string using secure randomness. */
function secureRandomChar(charset) {
  return charset[secureRandomInt(charset.length)];
}

/** Return a cryptographically random integer in [0, max). */
function secureRandomInt(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

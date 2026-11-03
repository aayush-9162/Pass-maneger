/**
 * Password generator.
 *
 * Lives in the shared package so the web console, the extension and any future
 * client produce identically-distributed passwords from identical options - a
 * generator that differs per client is a subtle way to end up with weaker
 * passwords on whichever client got less attention.
 *
 * Randomness comes from `globalThis.crypto.getRandomValues`, which is present in
 * browsers, service workers and Node 19+. `Math.random` is never used: it is
 * seeded predictably and is not fit for generating credentials.
 */

export interface PasswordGeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  /**
   * Generate syllables instead of random characters.
   *
   * Trades entropy per character for memorability. When enabled, the character
   * class switches are ignored except for `numbers` and `symbols`, which append
   * a separator group.
   */
  pronounceable: boolean;
  /** Drop characters that are easily confused: O/0, l/1/I. */
  excludeAmbiguous: boolean;
  /** Minimum count of each enabled class. Guarantees policy compliance. */
  minNumbers: number;
  minSymbols: number;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordGeneratorOptions = {
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  pronounceable: false,
  excludeAmbiguous: true,
  minNumbers: 1,
  minSymbols: 1,
};

export const PASSWORD_LENGTH_BOUNDS = { min: 8, max: 128 } as const;

const CHARACTER_SETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?',
} as const;

/** Characters that are hard to tell apart in common UI fonts. */
const AMBIGUOUS = new Set(['O', '0', 'o', 'l', '1', 'I', '|', 'B', '8', 'S', '5', 'Z', '2']);

/**
 * Cryptographically strong random bytes.
 *
 * @throws when no Web Crypto implementation is available, rather than silently
 *   degrading to a predictable source - a generator that quietly becomes weak is
 *   worse than one that fails loudly.
 */
/**
 * Minimal structural type for the Web Crypto RNG.
 *
 * Declared here rather than relying on the DOM lib: this package compiles
 * without DOM types so it stays usable from Node, a service worker and a
 * browser alike.
 */
interface RandomSource {
  getRandomValues<T extends Uint8Array>(array: T): T;
}

function randomBytes(count: number): Uint8Array {
  const cryptoApi = (globalThis as { crypto?: RandomSource }).crypto;

  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error(
      'No cryptographically secure random source is available. ' +
        'A browser needs a secure context (HTTPS or localhost) for this.',
    );
  }

  const buffer = new Uint8Array(count);
  cryptoApi.getRandomValues(buffer);
  return buffer;
}

/**
 * Uniform random integer in `[0, max)`.
 *
 * Uses rejection sampling. The obvious `bytes[0] % max` is biased whenever `max`
 * does not divide 256: with a 10-character alphabet the first 6 characters
 * become measurably more likely, which is a real if modest loss of entropy.
 */
function randomInt(max: number): number {
  if (max <= 0) throw new Error('randomInt requires a positive bound.');
  if (max > 256) {
    // Two bytes cover every alphabet this generator uses.
    const limit = 65536 - (65536 % max);
    for (;;) {
      const bytes = randomBytes(2);
      const value = ((bytes[0] as number) << 8) | (bytes[1] as number);
      if (value < limit) return value % max;
    }
  }

  const limit = 256 - (256 % max);
  for (;;) {
    const byte = randomBytes(1)[0] as number;
    if (byte < limit) return byte % max;
  }
}

/** Uniform random character from a string alphabet. */
function randomFrom(source: string): string {
  return source[randomInt(source.length)] as string;
}

/** Uniform random element from a list (syllable parts). */
function randomElement<T>(items: readonly T[]): T {
  return items[randomInt(items.length)] as T;
}

/** Fisher-Yates shuffle driven by the CSPRNG. */
function shuffle(items: string[]): string[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    const temp = items[i] as string;
    items[i] = items[j] as string;
    items[j] = temp;
  }
  return items;
}

function applyAmbiguityFilter(source: string, exclude: boolean): string {
  return exclude ? [...source].filter((character) => !AMBIGUOUS.has(character)).join('') : source;
}

// ---------------------------------------------------------------------------
// Pronounceable generation
// ---------------------------------------------------------------------------

/**
 * Syllable parts.
 *
 * Digraphs ("ch", "th") are included so the output reads like language rather
 * than like a spelling drill. `q` is omitted: it needs a following `u`, which
 * would require special-casing for no benefit.
 */
const ONSETS = [
  'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'w', 'z',
  'br', 'cl', 'cr', 'dr', 'fl', 'fr', 'gl', 'gr', 'pl', 'pr', 'sl', 'sp', 'st', 'tr',
  'ch', 'sh', 'th',
];

const NUCLEI = ['a', 'e', 'i', 'o', 'u', 'ai', 'ea', 'ee', 'ie', 'oa', 'oo', 'ou'];

const CODAS = ['', '', '', 'b', 'd', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'ng', 'nk', 'st'];

/**
 * Build a pronounceable base of at least `targetLength` characters.
 *
 * Entropy is roughly `log2(34 * 12 * 16)` ~= 12.7 bits per syllable, against
 * ~6.5 bits per character for a full random alphabet. `estimatePasswordEntropy`
 * accounts for that, so the strength readout stays honest rather than flattering
 * the pronounceable option.
 */
function generatePronounceableBase(targetLength: number): string {
  let output = '';

  while (output.length < targetLength) {
    output += randomElement(ONSETS) + randomElement(NUCLEI) + randomElement(CODAS);
  }

  return output.slice(0, targetLength);
}

/**
 * Capitalise roughly every third character position that begins a syllable, so a
 * pronounceable password can still satisfy an uppercase requirement without
 * becoming Title Case Everywhere.
 */
function addUppercase(value: string): string {
  const characters = [...value];
  const positions = Math.max(1, Math.floor(characters.length / 6));

  for (let i = 0; i < positions; i += 1) {
    const index = randomInt(characters.length);
    characters[index] = (characters[index] as string).toUpperCase();
  }

  return characters.join('');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a password.
 *
 * Guarantees the requested minimum counts for each enabled class, then shuffles,
 * so the result always satisfies a composition policy without the mandated
 * characters being predictably positioned at the start.
 *
 * @throws when the options are contradictory (no character classes enabled, or
 *   minimums that exceed the length).
 */
export function generatePassword(
  options: Partial<PasswordGeneratorOptions> = {},
): string {
  const config: PasswordGeneratorOptions = { ...DEFAULT_PASSWORD_OPTIONS, ...options };

  const length = Math.min(
    Math.max(Math.floor(config.length), PASSWORD_LENGTH_BOUNDS.min),
    PASSWORD_LENGTH_BOUNDS.max,
  );

  if (config.pronounceable) {
    return generatePronounceablePassword(config, length);
  }

  const pools: string[] = [];
  if (config.uppercase) pools.push(applyAmbiguityFilter(CHARACTER_SETS.uppercase, config.excludeAmbiguous));
  if (config.lowercase) pools.push(applyAmbiguityFilter(CHARACTER_SETS.lowercase, config.excludeAmbiguous));
  if (config.numbers) pools.push(applyAmbiguityFilter(CHARACTER_SETS.numbers, config.excludeAmbiguous));
  if (config.symbols) pools.push(applyAmbiguityFilter(CHARACTER_SETS.symbols, config.excludeAmbiguous));

  const usable = pools.filter((pool) => pool.length > 0);
  if (usable.length === 0) {
    throw new Error('Enable at least one character type.');
  }

  const required: string[] = [];

  // One of each enabled class, plus any extra minimums that were asked for.
  for (const pool of usable) required.push(randomFrom(pool));

  if (config.numbers) {
    const pool = applyAmbiguityFilter(CHARACTER_SETS.numbers, config.excludeAmbiguous);
    for (let i = 1; i < config.minNumbers && pool.length > 0; i += 1) required.push(randomFrom(pool));
  }
  if (config.symbols) {
    const pool = applyAmbiguityFilter(CHARACTER_SETS.symbols, config.excludeAmbiguous);
    for (let i = 1; i < config.minSymbols && pool.length > 0; i += 1) required.push(randomFrom(pool));
  }

  if (required.length > length) {
    throw new Error(
      `The required character minimums (${required.length}) exceed the requested length (${length}).`,
    );
  }

  const combined = usable.join('');
  const characters = [...required];
  while (characters.length < length) characters.push(randomFrom(combined));

  return shuffle(characters).join('');
}

/** Pronounceable variant: syllables, with digits and symbols appended as a group. */
function generatePronounceablePassword(
  config: PasswordGeneratorOptions,
  length: number,
): string {
  // Reserve room for the trailing digit/symbol group so the total length is
  // exactly what was asked for.
  const suffixCount =
    (config.numbers ? Math.max(1, config.minNumbers) : 0) +
    (config.symbols ? Math.max(1, config.minSymbols) : 0);

  const baseLength = Math.max(4, length - suffixCount);
  let base = generatePronounceableBase(baseLength);

  if (config.uppercase) base = addUppercase(base);

  const suffix: string[] = [];
  if (config.numbers) {
    const pool = applyAmbiguityFilter(CHARACTER_SETS.numbers, config.excludeAmbiguous);
    for (let i = 0; i < Math.max(1, config.minNumbers); i += 1) suffix.push(randomFrom(pool));
  }
  if (config.symbols) {
    const pool = applyAmbiguityFilter(CHARACTER_SETS.symbols, config.excludeAmbiguous);
    for (let i = 0; i < Math.max(1, config.minSymbols); i += 1) suffix.push(randomFrom(pool));
  }

  return (base + shuffle(suffix).join('')).slice(0, length);
}

/**
 * Entropy of the *generator*, in bits.
 *
 * Measures how hard the password is to guess given the options used - which is
 * the only thing that can be measured here. It says nothing about a password a
 * human typed in, and it deliberately reports the lower value for pronounceable
 * output rather than pretending syllables carry per-character entropy.
 */
export function estimatePasswordEntropy(
  password: string,
  options: Partial<PasswordGeneratorOptions> = {},
): number {
  const config: PasswordGeneratorOptions = { ...DEFAULT_PASSWORD_OPTIONS, ...options };

  if (config.pronounceable) {
    const perSyllable = Math.log2(ONSETS.length * NUCLEI.length * CODAS.length);
    // Roughly three characters per syllable.
    const syllables = Math.max(1, Math.floor(password.length / 3));
    const suffixBits =
      (config.numbers ? Math.log2(10) * Math.max(1, config.minNumbers) : 0) +
      (config.symbols ? Math.log2(CHARACTER_SETS.symbols.length) * Math.max(1, config.minSymbols) : 0);

    return Math.round(syllables * perSyllable + suffixBits);
  }

  let poolSize = 0;
  if (config.uppercase) poolSize += applyAmbiguityFilter(CHARACTER_SETS.uppercase, config.excludeAmbiguous).length;
  if (config.lowercase) poolSize += applyAmbiguityFilter(CHARACTER_SETS.lowercase, config.excludeAmbiguous).length;
  if (config.numbers) poolSize += applyAmbiguityFilter(CHARACTER_SETS.numbers, config.excludeAmbiguous).length;
  if (config.symbols) poolSize += applyAmbiguityFilter(CHARACTER_SETS.symbols, config.excludeAmbiguous).length;

  if (poolSize <= 1) return 0;
  return Math.round(password.length * Math.log2(poolSize));
}

export type PasswordStrength = 'weak' | 'fair' | 'good' | 'strong';

/**
 * Bucket an entropy estimate.
 *
 * Thresholds follow the usual guidance: below 60 bits is within reach of a
 * determined offline attack, 80+ is comfortable, 120+ is beyond foreseeable
 * brute force.
 */
export function passwordStrength(entropyBits: number): {
  strength: PasswordStrength;
  label: string;
} {
  if (entropyBits < 60) return { strength: 'weak', label: 'Weak' };
  if (entropyBits < 80) return { strength: 'fair', label: 'Fair' };
  if (entropyBits < 120) return { strength: 'good', label: 'Good' };
  return { strength: 'strong', label: 'Strong' };
}

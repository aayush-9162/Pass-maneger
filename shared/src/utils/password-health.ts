/**
 * Password health assessment.
 *
 * Runs in whichever client just decrypted the vault, because that is the only
 * place a password exists in plaintext. Every function here is pure and takes
 * the password as an argument; nothing is stored, hashed for upload, or logged.
 *
 * The distinction from `password-generator.ts` matters: that module measures the
 * entropy of a *generator* given its options, which is exact. This one measures
 * an *observed* password, which is inherently an estimate - the true entropy of
 * "Summer2024!" depends on how the person chose it, and no function can know
 * that. So the estimate deliberately errs pessimistic: pattern penalties are
 * applied generously, because calling a bad password good is the failure that
 * costs something.
 */

/** Findings, mirrored from `types/health.ts` to keep this module import-light. */
import {
  HEALTH_ISSUE,
  HEALTH_SEVERITY,
  HEALTH_THRESHOLDS,
  type HealthIssue,
  type HealthSeverity,
} from '../types/health';

/**
 * Passwords common enough that they are effectively public.
 *
 * A deliberately small, curated list rather than a bundled corpus: shipping ten
 * thousand entries to every client would cost more than it catches, and anything
 * beyond the obvious is better handled by a real breach check. These are the
 * ones that appear in the first page of every leaked-credential list.
 */
const COMMON_PASSWORDS: readonly string[] = [
  '123456', '123456789', '12345678', '12345', '1234567', '1234567890', '111111', '000000',
  'password', 'password1', 'password123', 'passw0rd', 'p@ssword', 'p@ssw0rd', 'admin',
  'administrator', 'welcome', 'welcome1', 'letmein', 'monkey', 'dragon', 'qwerty', 'qwerty123',
  'qwertyuiop', 'abc123', 'iloveyou', 'sunshine', 'princess', 'football', 'baseball', 'master',
  'login', 'passw0rd1', 'trustno1', 'starwars', 'whatever', 'superman', 'batman', 'access',
  'shadow', 'michael', 'jennifer', 'jordan', 'harley', 'ranger', 'hunter', 'buster', 'soccer',
  'hockey', 'killer', 'george', 'sexy', 'andrew', 'charlie', 'thomas', 'robert', 'freedom',
  'ginger', 'summer', 'winter', 'spring', 'autumn', 'changeme', 'default', 'secret', 'test',
  'test123', 'temp', 'temp123', 'guest', 'root', 'toor', 'user', 'demo', 'company', 'internal',
];

const COMMON_PASSWORD_SET = new Set(COMMON_PASSWORDS);

/** Keyboard runs that add no real entropy despite looking mixed. */
const KEYBOARD_SEQUENCES: readonly string[] = [
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qazwsx', 'zaq12wsx', '1qaz2wsx',
];

/** Character classes present in a password, used to size the search space. */
function poolSize(password: string): number {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  // Printable ASCII punctuation, counted as one class.
  if (/[^A-Za-z0-9]/.test(password)) size += 33;
  return size;
}

/**
 * Detect a password that is one word plus decoration.
 *
 * "Summer2024!" has a nominal search space of 72^11 - about 68 bits - and is
 * guessed in seconds by any wordlist attack with a mangling rule. This is the
 * single most important correction the estimate makes, because it is the shape
 * corporate rotation policies actively produce.
 */
function looksLikeWordPlusDecoration(password: string): boolean {
  return /^[A-Z]?[a-z]{3,}[0-9]{0,4}[!@#$%^&*._-]{0,2}$/.test(password);
}

/** Runs of the same character, or simple ascending/descending sequences. */
function hasRepetitionOrSequence(password: string): boolean {
  if (/(.)\1{2,}/.test(password)) return true;

  const lower = password.toLowerCase();
  for (const sequence of KEYBOARD_SEQUENCES) {
    for (let i = 0; i + 4 <= sequence.length; i += 1) {
      if (lower.includes(sequence.slice(i, i + 4))) return true;
    }
  }

  // Ascending or descending runs of four: "abcd", "4321".
  let ascending = 1;
  let descending = 1;
  for (let i = 1; i < lower.length; i += 1) {
    const delta = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
    ascending = delta === 1 ? ascending + 1 : 1;
    descending = delta === -1 ? descending + 1 : 1;
    if (ascending >= 4 || descending >= 4) return true;
  }

  return false;
}

/**
 * Estimate the entropy of an observed password, in bits.
 *
 * Starts from `length * log2(poolSize)` and then subtracts for structure that a
 * real cracking rig exploits. The penalties are multiplicative caps rather than
 * fixed subtractions so that a long password built from a dictionary word is not
 * rescued by its length alone.
 */
export function observedEntropyBits(password: string): number {
  if (password.length === 0) return 0;

  const pool = poolSize(password);
  if (pool <= 1) return 0;

  let bits = password.length * Math.log2(pool);

  const normalized = password.toLowerCase().replace(/[^a-z0-9]/g, '');

  // On the common list: treat as public knowledge regardless of shape.
  if (COMMON_PASSWORD_SET.has(password.toLowerCase()) || COMMON_PASSWORD_SET.has(normalized)) {
    return Math.min(bits, 8);
  }

  // Contains a common password as its stem ("Password123!", "letmein2024").
  for (const common of COMMON_PASSWORDS) {
    if (common.length >= 5 && normalized.includes(common)) {
      bits = Math.min(bits, 22);
      break;
    }
  }

  if (looksLikeWordPlusDecoration(password)) bits = Math.min(bits, 30);
  if (hasRepetitionOrSequence(password)) bits *= 0.6;

  // Very few distinct characters means the effective pool is smaller than the
  // classes present suggest - "aaaaAAAA1111" looks mixed and is not.
  const distinct = new Set(password).size;
  if (distinct < password.length / 2) bits *= 0.7;

  return Math.max(0, Math.round(bits));
}

/** 0-4 strength score, the scale the UI renders as a meter. */
export function healthScoreForPassword(password: string): number {
  const bits = observedEntropyBits(password);
  if (bits < 28) return 0;
  if (bits < 45) return 1;
  if (bits < 60) return 2;
  if (bits < 90) return 3;
  return 4;
}

/** True when the password is on the bundled common list. */
export function isCommonPassword(password: string): boolean {
  return COMMON_PASSWORD_SET.has(password.toLowerCase());
}

// ---------------------------------------------------------------------------
// Item assessment
// ---------------------------------------------------------------------------

/** One item's inputs to the assessment. */
export interface AssessableItem {
  itemId: string;
  vaultId: string;
  sharedVaultId?: string | null;
  password: string;
  /** When the password was last changed. Falls back to the item's own timestamp. */
  passwordChangedAt?: string | null;
  updatedAt: string;
}

/** The assessment of one item, without anything that could recover the password. */
export interface AssessedItem {
  itemId: string;
  vaultId: string;
  sharedVaultId: string | null;
  severity: HealthSeverity;
  issues: HealthIssue[];
  strengthScore: number;
  entropyBits: number;
  passwordLength: number;
  ageDays: number | null;
  duplicateCount: number;
}

function daysBetween(from: Date, to: Date): number {
  return Math.max(0, Math.floor((to.getTime() - from.getTime()) / 86_400_000));
}

/**
 * Pick the single severity to display for a set of issues.
 *
 * A compromised credential outranks everything: it is not a quality problem, it
 * is a live one. Reuse comes next because it converts one breach into several.
 */
function severityFor(issues: readonly HealthIssue[], strengthScore: number): HealthSeverity {
  if (issues.includes(HEALTH_ISSUE.COMPROMISED)) return HEALTH_SEVERITY.CRITICAL;
  if (issues.includes(HEALTH_ISSUE.REUSED) && strengthScore <= 2) return HEALTH_SEVERITY.CRITICAL;
  if (issues.includes(HEALTH_ISSUE.WEAK)) return HEALTH_SEVERITY.HIGH;
  if (issues.includes(HEALTH_ISSUE.REUSED)) return HEALTH_SEVERITY.HIGH;
  if (issues.includes(HEALTH_ISSUE.SHORT)) return HEALTH_SEVERITY.MEDIUM;
  if (issues.includes(HEALTH_ISSUE.OLD)) return HEALTH_SEVERITY.MEDIUM;
  if (issues.includes(HEALTH_ISSUE.MISSING)) return HEALTH_SEVERITY.LOW;
  return HEALTH_SEVERITY.OK;
}

/**
 * Assess a whole vault.
 *
 * Duplicate detection groups on the plaintext password in a local `Map`, which
 * never leaves this function - only the resulting group *size* appears in the
 * output. That is the whole trick that lets an admin see "14 reused passwords in
 * the Finance group" without anyone learning what they are.
 *
 * @param isCompromised Optional breach oracle. The caller supplies it because
 *   whether a breach check is even possible depends on deployment: an air-gapped
 *   LAN has no route to a breach corpus, and this module must not assume one.
 *   When it is absent, `compromised` is simply never reported - the report says
 *   the check did not run rather than implying everything is clean.
 */
export async function assessVault(
  items: readonly AssessableItem[],
  options: {
    now?: Date;
    isCompromised?: (password: string) => Promise<boolean> | boolean;
  } = {},
): Promise<AssessedItem[]> {
  const now = options.now ?? new Date();

  // Group by plaintext to find reuse. Local only; never serialised.
  const occurrences = new Map<string, number>();
  for (const item of items) {
    if (!item.password) continue;
    occurrences.set(item.password, (occurrences.get(item.password) ?? 0) + 1);
  }

  // Breach lookups are deduplicated: the same password on five items is one call.
  const breachCache = new Map<string, boolean>();
  if (options.isCompromised) {
    for (const password of occurrences.keys()) {
      breachCache.set(password, await options.isCompromised(password));
    }
  }

  const assessed: AssessedItem[] = [];

  for (const item of items) {
    const issues: HealthIssue[] = [];
    const password = item.password ?? '';

    if (password.length === 0) {
      assessed.push({
        itemId: item.itemId,
        vaultId: item.vaultId,
        sharedVaultId: item.sharedVaultId ?? null,
        severity: HEALTH_SEVERITY.LOW,
        issues: [HEALTH_ISSUE.MISSING],
        strengthScore: 0,
        entropyBits: 0,
        passwordLength: 0,
        ageDays: null,
        duplicateCount: 0,
      });
      continue;
    }

    const entropyBits = observedEntropyBits(password);
    const strengthScore = healthScoreForPassword(password);
    const duplicateCount = occurrences.get(password) ?? 1;

    if (password.length < HEALTH_THRESHOLDS.minLength) issues.push(HEALTH_ISSUE.SHORT);
    if (entropyBits < HEALTH_THRESHOLDS.minEntropyBits) issues.push(HEALTH_ISSUE.WEAK);
    if (duplicateCount > 1) issues.push(HEALTH_ISSUE.REUSED);
    if (breachCache.get(password)) issues.push(HEALTH_ISSUE.COMPROMISED);

    const changedAt = item.passwordChangedAt ?? item.updatedAt;
    const parsed = new Date(changedAt);
    const ageDays = Number.isNaN(parsed.getTime()) ? null : daysBetween(parsed, now);

    if (ageDays !== null && ageDays > HEALTH_THRESHOLDS.maxAgeDays) issues.push(HEALTH_ISSUE.OLD);

    assessed.push({
      itemId: item.itemId,
      vaultId: item.vaultId,
      sharedVaultId: item.sharedVaultId ?? null,
      severity: severityFor(issues, strengthScore),
      issues,
      strengthScore,
      entropyBits,
      passwordLength: password.length,
      ageDays,
      duplicateCount,
    });
  }

  return assessed;
}

/**
 * Roll findings up into a 0-100 score.
 *
 * Weighted so that one compromised credential moves the number more than a dozen
 * merely-old ones. A score that treats every finding equally rewards clearing
 * the easy backlog while the dangerous item stays untouched.
 */
export function scoreFindings(findings: readonly AssessedItem[]): number {
  const assessable = findings.filter((finding) => finding.passwordLength > 0);
  if (assessable.length === 0) return 100;

  const WEIGHTS: Record<HealthIssue, number> = {
    [HEALTH_ISSUE.COMPROMISED]: 40,
    [HEALTH_ISSUE.REUSED]: 15,
    [HEALTH_ISSUE.WEAK]: 12,
    [HEALTH_ISSUE.SHORT]: 8,
    [HEALTH_ISSUE.OLD]: 4,
    [HEALTH_ISSUE.MISSING]: 0,
  };

  let penalty = 0;
  for (const finding of assessable) {
    // Per item, only the worst issue counts fully; the rest are half-weighted,
    // so a single item cannot drive the whole score to zero on its own.
    const weights = finding.issues.map((issue) => WEIGHTS[issue]).sort((a, b) => b - a);
    penalty += weights.reduce((sum, weight, index) => sum + (index === 0 ? weight : weight / 2), 0);
  }

  const average = penalty / assessable.length;
  return Math.max(0, Math.min(100, Math.round(100 - average)));
}

/** Count findings carrying a given issue. */
export function countIssue(findings: readonly AssessedItem[], issue: HealthIssue): number {
  return findings.filter((finding) => finding.issues.includes(issue)).length;
}

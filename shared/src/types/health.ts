/**
 * Password health.
 *
 * ## Why this looks unusual
 *
 * A conventional password manager runs this report on the server: it holds the
 * passwords, so it can score them, hash them to find duplicates and check them
 * against a breach corpus. This one cannot. The server has no key and no
 * plaintext, so every judgement about a password has to be made in the browser
 * that just decrypted it.
 *
 * So the client computes the report and uploads **findings, never passwords**:
 * a strength score, a length, an age, and flags. The heaviest thing that crosses
 * the wire is a vault item id the server already stores. Nothing uploaded here
 * can be run backwards into a password - not by an administrator reading the
 * report, and not by anyone who steals the database.
 *
 * The cost of that is real and worth stating plainly: the report is only as
 * fresh as the last time the user unlocked their vault in a client that ran it.
 * An account that has not been opened for a month reports month-old findings,
 * and the console shows the age so nobody mistakes stale data for a clean bill
 * of health.
 */

/** How serious a finding is. Drives sorting and colour in the console. */
export const HEALTH_SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  OK: 'ok',
} as const;

export type HealthSeverity = (typeof HEALTH_SEVERITY)[keyof typeof HEALTH_SEVERITY];

export const HEALTH_SEVERITY_RANK: Readonly<Record<HealthSeverity, number>> = {
  [HEALTH_SEVERITY.CRITICAL]: 4,
  [HEALTH_SEVERITY.HIGH]: 3,
  [HEALTH_SEVERITY.MEDIUM]: 2,
  [HEALTH_SEVERITY.LOW]: 1,
  [HEALTH_SEVERITY.OK]: 0,
};

/** What is wrong with a password. An item can carry several at once. */
export const HEALTH_ISSUE = {
  /** Low entropy for its length, or on the common-password list. */
  WEAK: 'weak',
  /** The same password appears on another item in this account. */
  REUSED: 'reused',
  /** Not changed within the org's rotation window. */
  OLD: 'old',
  /** Appears in a known breach corpus. */
  COMPROMISED: 'compromised',
  /** Below the org's minimum length. */
  SHORT: 'short',
  /** The item has no password at all where one is expected. */
  MISSING: 'missing',
} as const;

export type HealthIssue = (typeof HEALTH_ISSUE)[keyof typeof HEALTH_ISSUE];

export const HEALTH_ISSUE_LABEL: Readonly<Record<HealthIssue, string>> = {
  [HEALTH_ISSUE.WEAK]: 'Weak',
  [HEALTH_ISSUE.REUSED]: 'Reused',
  [HEALTH_ISSUE.OLD]: 'Old',
  [HEALTH_ISSUE.COMPROMISED]: 'Compromised',
  [HEALTH_ISSUE.SHORT]: 'Too short',
  [HEALTH_ISSUE.MISSING]: 'No password',
};

/**
 * Thresholds the report is judged against.
 *
 * Shared so the client that computes a finding and the console that renders it
 * cannot disagree about what "old" means.
 */
export const HEALTH_THRESHOLDS = {
  /** Below this, a password is reported as SHORT regardless of its entropy. */
  minLength: 12,
  /** Below this, WEAK. Roughly a 10-character mixed-case-and-digit password. */
  minEntropyBits: 60,
  /** Older than this, OLD. */
  maxAgeDays: 365,
  /** Older than this, OLD at HIGH rather than MEDIUM. */
  criticalAgeDays: 730,
} as const;

/**
 * One item's findings.
 *
 * Note what is absent: the password, any hash of it, the item's name, its URL
 * and its username. `itemId` is the only identifier, and it means nothing to
 * anyone who cannot already decrypt that item.
 */
export interface PasswordHealthFinding {
  itemId: string;
  /** The vault the item lives in, so a report can be scoped. */
  vaultId: string;
  /** Null for an item in a shared vault the reporter reached through a grant. */
  sharedVaultId: string | null;
  severity: HealthSeverity;
  issues: HealthIssue[];
  /** 0-4, matching the shared password strength scale. */
  strengthScore: number;
  /** Rounded to the nearest bit; not enough to reconstruct anything. */
  entropyBits: number;
  passwordLength: number;
  /** Days since the password was last changed, from item metadata. */
  ageDays: number | null;
  /**
   * How many items in this account share this password.
   *
   * 1 means unique. Computed client-side by grouping on a hash that is never
   * uploaded - only the resulting count is.
   */
  duplicateCount: number;
}

/** An uploaded report: one snapshot of one user's vault. */
export interface PasswordHealthReport {
  userId: string;
  email: string;
  fullName: string;
  totalItems: number;
  /** Items that carry a password and were therefore assessed. */
  assessedItems: number;
  weakCount: number;
  reusedCount: number;
  oldCount: number;
  compromisedCount: number;
  /** 0-100. Weighted so a compromised credential dominates the score. */
  healthScore: number;
  /** Whether the client was able to run a breach check at all. */
  breachCheckPerformed: boolean;
  generatedAt: string;
  createdAt: string;
}

/** Org-wide rollup for the admin console. */
export interface PasswordHealthSummary {
  /** Users who have ever uploaded a report. */
  reportedUsers: number;
  /** Users who have not - their vaults are unassessed, not healthy. */
  unreportedUsers: number;
  /** Reports older than the staleness window; shown as a caveat, not a finding. */
  staleReports: number;
  totalAssessedItems: number;
  weakCount: number;
  reusedCount: number;
  oldCount: number;
  compromisedCount: number;
  /** Mean health score across reporting users, 0-100. */
  averageHealthScore: number;
  /** Distribution for the chart: score bucket -> user count. */
  scoreDistribution: { bucket: string; users: number }[];
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

export interface SubmitHealthReportRequest {
  /** ISO-8601 instant the client finished the assessment. */
  generatedAt: string;
  totalItems: number;
  assessedItems: number;
  breachCheckPerformed: boolean;
  findings: PasswordHealthFinding[];
}

export interface HealthReportQuery {
  page?: number;
  pageSize?: number;
  sortBy?: 'healthScore' | 'weakCount' | 'reusedCount' | 'compromisedCount' | 'generatedAt';
  sortDir?: 'asc' | 'desc';
  search?: string;
  /** Only users whose score is at or below this. */
  maxScore?: number;
  /** Only users with at least one finding of this kind. */
  issue?: HealthIssue;
}

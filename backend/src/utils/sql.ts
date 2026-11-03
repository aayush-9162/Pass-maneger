/**
 * SQL helpers for the parts of a query that *cannot* be parameterised.
 *
 * Placeholders (`?`) cover values, but not identifiers: `ORDER BY ?` is invalid
 * SQL. Sort columns therefore arrive as untrusted strings and must be resolved
 * through an explicit allow-list before they touch a statement. That is the one
 * realistic SQL-injection vector left in a prepared-statement codebase, so it
 * is centralised here rather than reimplemented per repository.
 */

import { PAGINATION_DEFAULTS, type PaginationQuery } from '@passm/shared';

/** Maps a client-facing sort key to a physical `table.column` reference. */
export type SortColumnMap = Readonly<Record<string, string>>;

export interface ResolvedPagination {
  page: number;
  pageSize: number;
  limit: number;
  offset: number;
}

/**
 * Translate a client sort key into a safe SQL fragment.
 *
 * Anything not present in `allowed` falls back to `fallbackKey`, so a malicious
 * value is discarded rather than rejected - sorting is not worth a 4xx.
 */
export function resolveSortColumn(
  requested: string | undefined,
  allowed: SortColumnMap,
  fallbackKey: string,
): string {
  const key = requested !== undefined && requested in allowed ? requested : fallbackKey;
  const column = allowed[key];

  if (column === undefined) {
    // Programmer error: the fallback must exist in the map.
    throw new Error(`Sort fallback "${fallbackKey}" is missing from the allow-list.`);
  }
  return column;
}

/** Normalise sort direction; anything unrecognised becomes ASC. */
export function resolveSortDirection(requested: string | undefined): 'ASC' | 'DESC' {
  return String(requested).toLowerCase() === 'desc' ? 'DESC' : 'ASC';
}

/**
 * Clamp pagination input into a safe range.
 *
 * An unbounded `pageSize` is a denial-of-service vector (one request pulling a
 * million rows), so it is capped at `PAGINATION_DEFAULTS.maxPageSize`.
 */
export function resolvePagination(
  // Accepts the shared `PaginationQuery` as well as the looser repository filter
  // types; only `page` and `pageSize` are read, and both are re-validated below.
  query: Pick<PaginationQuery, 'page' | 'pageSize'> = {},
): ResolvedPagination {
  const rawPage = Number(query.page ?? PAGINATION_DEFAULTS.page);
  const rawPageSize = Number(query.pageSize ?? PAGINATION_DEFAULTS.pageSize);

  const page = Number.isFinite(rawPage) && rawPage >= 1 ? Math.floor(rawPage) : 1;
  const pageSize =
    Number.isFinite(rawPageSize) && rawPageSize >= 1
      ? Math.min(Math.floor(rawPageSize), PAGINATION_DEFAULTS.maxPageSize)
      : PAGINATION_DEFAULTS.pageSize;

  return { page, pageSize, limit: pageSize, offset: (page - 1) * pageSize };
}

/**
 * Render `LIMIT n OFFSET m` as literal SQL.
 *
 * ## Why this is not a bound parameter
 *
 * `LIMIT ?` looks like it should work, and over the text protocol it does. Over
 * the *binary* protocol - which is what `connection.execute()` uses, and what
 * gives us prepared statements - MySQL rejects it outright:
 *
 *     Error: Incorrect arguments to mysqld_stmt_execute
 *
 * The server will not accept a placeholder in the row-count position from a
 * client that has not declared it as an integer parameter, and mysql2 sends
 * every parameter as a string. So the choice is between dropping prepared
 * statements for every paginated query - losing server-side binding on the
 * *values*, which is where injection actually lives - or interpolating the two
 * numbers.
 *
 * ## Why interpolating here is safe
 *
 * Both arguments pass through `Number()` and `Math.trunc()` and are then clamped
 * to a fixed range. Nothing that is not a finite integer can survive: a string
 * becomes `NaN`, `NaN || 0` becomes `0`, and the clamp bounds the rest. There is
 * no input to this function that produces anything other than two decimal
 * integers in the output.
 *
 * This is the same category as `resolveSortColumn` above - the parts of a
 * statement that cannot be parameterised are resolved through code that can only
 * emit a known-safe token - and it is deliberately confined to these two
 * helpers so there is one place to review.
 */
export function limitOffsetClause(limit: number, offset: number): string {
  const safeLimit = Math.min(
    Math.max(Math.trunc(Number(limit)) || 0, 1),
    PAGINATION_DEFAULTS.maxPageSize,
  );
  const safeOffset = Math.max(Math.trunc(Number(offset)) || 0, 0);

  return `LIMIT ${safeLimit} OFFSET ${safeOffset}`;
}

/**
 * Render `LIMIT n` as literal SQL, clamped to `max`.
 *
 * Same reasoning as {@link limitOffsetClause}. `max` is supplied by the call
 * site because the sensible ceiling differs: a password-history lookup wants a
 * couple of dozen rows, a directory export a few hundred.
 */
export function limitClause(limit: number, max: number): string {
  const ceiling = Math.max(Math.trunc(Number(max)) || 1, 1);
  const safeLimit = Math.min(Math.max(Math.trunc(Number(limit)) || 0, 1), ceiling);

  return `LIMIT ${safeLimit}`;
}

/**
 * Build a `LIKE` pattern for a search term.
 *
 * Escapes the LIKE metacharacters `%`, `_` and `\` so a search for "100%" does
 * not turn into a full-table wildcard scan. The result is still passed as a
 * bound parameter.
 */
export function likePattern(term: string): string {
  const escaped = term.trim().replace(/[\\%_]/g, (match) => `\\${match}`);
  return `%${escaped}%`;
}

/**
 * `IN (?, ?, ?)` placeholder list.
 *
 * @throws when `count` is 0 - `IN ()` is a syntax error, so callers must
 *   short-circuit on empty input instead.
 */
export function placeholders(count: number): string {
  if (count <= 0) throw new Error('placeholders() requires at least one value.');
  return new Array(count).fill('?').join(', ');
}

/** MySQL driver error codes worth branching on. */
export const MYSQL_ERROR_CODES = {
  DUPLICATE_ENTRY: 'ER_DUP_ENTRY',
  NO_REFERENCED_ROW: 'ER_NO_REFERENCED_ROW_2',
  ROW_IS_REFERENCED: 'ER_ROW_IS_REFERENCED_2',
  LOCK_DEADLOCK: 'ER_LOCK_DEADLOCK',
  LOCK_WAIT_TIMEOUT: 'ER_LOCK_WAIT_TIMEOUT',
  CHECK_CONSTRAINT_VIOLATED: 'ER_CHECK_CONSTRAINT_VIOLATED',
} as const;

interface MysqlErrorLike {
  code?: string;
  errno?: number;
  sqlState?: string;
  sqlMessage?: string;
}

/** Structural check for a mysql2 driver error. */
export function isMysqlError(error: unknown): error is MysqlErrorLike & Error {
  return (
    error instanceof Error &&
    typeof (error as MysqlErrorLike).code === 'string' &&
    (error as MysqlErrorLike).code!.startsWith('ER_')
  );
}

/** True when the error is a unique-constraint violation. */
export function isDuplicateEntryError(error: unknown): boolean {
  return isMysqlError(error) && error.code === MYSQL_ERROR_CODES.DUPLICATE_ENTRY;
}

/**
 * Extract the violated index name from a duplicate-entry error.
 * mysql2 reports: `Duplicate entry 'x' for key 'users.uq_users_email'`.
 */
export function duplicateKeyName(error: unknown): string | null {
  if (!isMysqlError(error) || error.code !== MYSQL_ERROR_CODES.DUPLICATE_ENTRY) return null;
  const match = /for key '(?:[^.']+\.)?([^']+)'/.exec(error.sqlMessage ?? error.message);
  return match?.[1] ?? null;
}

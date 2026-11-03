/**
 * Date helpers.
 *
 * The database returns `Date` objects (the pool is configured with
 * `timezone: 'Z'`), while the API contract is ISO-8601 UTC strings. Conversion
 * happens in one place so no endpoint accidentally leaks a local-time string.
 */

/** Current instant. Wrapped so tests can stub a single function. */
export function now(): Date {
  return new Date();
}

/** `Date | string | null` -> ISO-8601 string, preserving null. */
export function toIso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

/** Same as {@link toIso} but for columns declared NOT NULL. */
export function toIsoRequired(value: Date | string): string {
  return toIso(value) ?? new Date(0).toISOString();
}

export function minutesFromNow(minutes: number): Date {
  return new Date(Date.now() + minutes * 60_000);
}

export function secondsFromNow(seconds: number): Date {
  return new Date(Date.now() + seconds * 1000);
}

/** True when `value` is a real date strictly in the future. */
export function isFuture(value: Date | string | null | undefined): boolean {
  if (value === null || value === undefined) return false;
  const date = value instanceof Date ? value : new Date(value);
  return !Number.isNaN(date.getTime()) && date.getTime() > Date.now();
}

/** Whole seconds from now until `value`; 0 when already past. */
export function secondsUntil(value: Date | string | null | undefined): number {
  if (value === null || value === undefined) return 0;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return 0;
  return Math.max(0, Math.ceil((date.getTime() - Date.now()) / 1000));
}

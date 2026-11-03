/**
 * Duration string parsing.
 *
 * Config uses human readable TTLs ("15m", "7d") because they are far easier to
 * review than raw second counts. Everything internal works in seconds.
 */

const UNIT_SECONDS: Record<string, number> = {
  ms: 0.001,
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
};

const DURATION_PATTERN = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)$/i;

/**
 * Convert a duration string to whole seconds.
 *
 * Accepts `"900"` (bare seconds) or `"<number><unit>"` where unit is one of
 * ms | s | m | h | d | w.
 *
 * @throws {Error} when the input cannot be parsed - config errors must fail
 *   loudly at boot, never silently default.
 */
export function parseDurationToSeconds(value: string): number {
  const raw = value.trim();

  if (/^\d+$/.test(raw)) {
    return Number.parseInt(raw, 10);
  }

  const match = DURATION_PATTERN.exec(raw);
  if (!match) {
    throw new Error(
      `Invalid duration "${value}". Use a bare number of seconds or <number><ms|s|m|h|d|w>, e.g. "15m".`,
    );
  }

  const amount = Number.parseFloat(match[1] as string);
  const unit = (match[2] as string).toLowerCase();
  const multiplier = UNIT_SECONDS[unit];

  if (multiplier === undefined) {
    throw new Error(`Unsupported duration unit "${unit}" in "${value}".`);
  }

  return Math.max(1, Math.floor(amount * multiplier));
}

/** Convert a duration string to milliseconds (cookie `maxAge`, timers). */
export function parseDurationToMs(value: string): number {
  return parseDurationToSeconds(value) * 1000;
}

/** `Date` that is `seconds` in the future - used for `expires_at` columns. */
export function secondsFromNow(seconds: number): Date {
  return new Date(Date.now() + seconds * 1000);
}

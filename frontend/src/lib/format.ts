/**
 * Display formatting.
 *
 * All timestamps arrive as ISO-8601 UTC and are rendered in the viewer's local
 * time zone. Security review is confusing enough without also asking people to
 * convert time zones in their head.
 */

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
});

const relativeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

/** Absolute local date and time, e.g. "12 Mar 2025, 14:05". */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '-' : dateTimeFormatter.format(date);
}

/** Relative time, e.g. "3 minutes ago". Falls back to absolute beyond 30 days. */
export function formatRelative(value: string | null | undefined): string {
  if (!value) return 'Never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';

  const deltaSeconds = (date.getTime() - Date.now()) / 1000;
  const absSeconds = Math.abs(deltaSeconds);

  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 3600],
    ['hour', 86_400],
    ['day', 2_592_000],
  ];

  let divisor = 1;
  for (const [unit, threshold] of units) {
    if (absSeconds < threshold) {
      return relativeFormatter.format(Math.round(deltaSeconds / divisor), unit);
    }
    divisor = threshold;
  }

  return dateTimeFormatter.format(date);
}

/** Initials for an avatar placeholder. */
export function initials(firstName: string, lastName: string): string {
  return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase() || '?';
}

/** Truncate a long identifier for display, keeping it recognisable. */
export function shortId(value: string, length = 8): string {
  return value.length <= length ? value : `${value.slice(0, length)}...`;
}

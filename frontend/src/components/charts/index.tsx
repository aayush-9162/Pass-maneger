/**
 * Charts, drawn as plain SVG.
 *
 * No charting library. The reasons are specific rather than dogmatic:
 *
 *  - The console ships as a **static export served by the API over a LAN**, so
 *    every byte is downloaded from that one origin. A general-purpose chart
 *    library is a large dependency for four chart shapes, none of which needs
 *    axes negotiation, zooming, or a plugin system.
 *  - The CSP forbids external script sources, so a CDN build is not an option
 *    anyway, and a bundled one would have to be audited like any other
 *    dependency in a password manager.
 *  - Colours come from the same CSS custom properties as everything else, so
 *    these follow the light/dark theme for free. Most chart libraries need a
 *    theme object rebuilt and re-passed on every switch.
 *
 * Every chart is responsive through `viewBox` plus `preserveAspectRatio`, so it
 * scales to its container without a resize observer, and every one degrades to
 * an accessible summary when it has no data.
 */

import * as React from 'react';

import { cn } from '@/lib/utils';

/** Series colours, in the order they are handed out. Theme-aware by design. */
const SERIES_COLORS = [
  'hsl(var(--primary))',
  'hsl(var(--success))',
  'hsl(var(--warning))',
  'hsl(var(--destructive))',
  'hsl(var(--muted-foreground))',
] as const;

export interface Point {
  date: string;
  value: number;
}

function EmptyState({ message }: { message: string }): React.ReactElement {
  return (
    <div className="flex h-full min-h-[8rem] items-center justify-center text-sm text-muted-foreground">
      {message}
    </div>
  );
}

/**
 * Convert a series into an SVG path.
 *
 * A plain polyline rather than a smoothed spline: a spline through daily counts
 * invents values that were never measured - it will dip below zero between two
 * small numbers and overshoot after a spike - and on a security dashboard that
 * is a chart that lies.
 */
function linePath(values: readonly number[], width: number, height: number, max: number): string {
  if (values.length === 0) return '';
  if (values.length === 1) return `M 0 ${height - (values[0]! / max) * height}`;

  const step = width / (values.length - 1);

  return values
    .map((value, index) => {
      const x = index * step;
      const y = height - (value / max) * height;
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(' ');
}

// ---------------------------------------------------------------------------
// Area chart
// ---------------------------------------------------------------------------

export interface AreaSeries {
  label: string;
  points: readonly Point[];
  color?: string;
}

/**
 * Multi-series area chart for daily activity.
 *
 * Scaled to the maximum across *all* series so the lines are comparable; two
 * independently-scaled series on one axis is a common way to make a small number
 * look like a large one.
 */
export function AreaChart({
  series,
  height = 180,
  className,
  emptyMessage = 'No activity in this period.',
}: {
  series: readonly AreaSeries[];
  height?: number;
  className?: string;
  emptyMessage?: string;
}): React.ReactElement {
  // Before any early return: hooks must run unconditionally on every render.
  const gradientId = React.useId();

  const width = 600;
  const length = series[0]?.points.length ?? 0;

  const max = Math.max(
    1,
    ...series.flatMap((entry) => entry.points.map((point) => point.value)),
  );

  const total = series.reduce(
    (sum, entry) => sum + entry.points.reduce((inner, point) => inner + point.value, 0),
    0,
  );

  if (length === 0 || total === 0) return <EmptyState message={emptyMessage} />;

  return (
    <figure className={cn('space-y-3', className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="w-full"
        style={{ height }}
        role="img"
        aria-label={series
          .map(
            (entry) =>
              `${entry.label}: ${entry.points.reduce((sum, point) => sum + point.value, 0)} over ${
                entry.points.length
              } days`,
          )
          .join('. ')}
      >
        <defs>
          {series.map((entry, index) => (
            <linearGradient
              key={entry.label}
              id={`${gradientId}-${index}`}
              x1="0"
              y1="0"
              x2="0"
              y2="1"
            >
              <stop
                offset="0%"
                stopColor={entry.color ?? SERIES_COLORS[index % SERIES_COLORS.length]}
                stopOpacity="0.25"
              />
              <stop
                offset="100%"
                stopColor={entry.color ?? SERIES_COLORS[index % SERIES_COLORS.length]}
                stopOpacity="0"
              />
            </linearGradient>
          ))}
        </defs>

        {/* Horizontal guides at quarter intervals. */}
        {[0.25, 0.5, 0.75].map((fraction) => (
          <line
            key={fraction}
            x1="0"
            x2={width}
            y1={height * fraction}
            y2={height * fraction}
            stroke="hsl(var(--border))"
            strokeWidth="1"
            vectorEffect="non-scaling-stroke"
          />
        ))}

        {series.map((entry, index) => {
          const values = entry.points.map((point) => point.value);
          const path = linePath(values, width, height, max);
          const color = entry.color ?? SERIES_COLORS[index % SERIES_COLORS.length];

          return (
            <g key={entry.label}>
              <path
                d={`${path} L ${width} ${height} L 0 ${height} Z`}
                fill={`url(#${gradientId}-${index})`}
              />
              <path
                d={path}
                fill="none"
                stroke={color}
                strokeWidth="2"
                strokeLinejoin="round"
                strokeLinecap="round"
                // Keeps the stroke 2px regardless of the non-uniform scaling
                // that `preserveAspectRatio="none"` applies.
                vectorEffect="non-scaling-stroke"
              />
            </g>
          );
        })}
      </svg>

      <figcaption className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
        {series.map((entry, index) => (
          <span key={entry.label} className="inline-flex items-center gap-1.5">
            <span
              className="size-2 rounded-full"
              style={{ background: entry.color ?? SERIES_COLORS[index % SERIES_COLORS.length] }}
              aria-hidden
            />
            {entry.label}
            <span className="tabular-nums text-foreground">
              {entry.points.reduce((sum, point) => sum + point.value, 0)}
            </span>
          </span>
        ))}
        <span className="ml-auto">
          {series[0]?.points[0]?.date} - {series[0]?.points.at(-1)?.date}
        </span>
      </figcaption>
    </figure>
  );
}

// ---------------------------------------------------------------------------
// Bar chart
// ---------------------------------------------------------------------------

export interface Bar {
  label: string;
  value: number;
  color?: string;
}

/**
 * Horizontal bar chart.
 *
 * Horizontal rather than vertical because every use here has a text label per
 * bar - item types, groups, score buckets - and horizontal bars give the
 * label a full line instead of a rotated stub.
 */
export function BarChart({
  bars,
  className,
  valueFormatter = (value: number) => value.toLocaleString(),
  emptyMessage = 'Nothing to show yet.',
}: {
  bars: readonly Bar[];
  className?: string;
  valueFormatter?: (value: number) => string;
  emptyMessage?: string;
}): React.ReactElement {
  const max = Math.max(1, ...bars.map((bar) => bar.value));
  const total = bars.reduce((sum, bar) => sum + bar.value, 0);

  // All-zero bars are shown as an empty state rather than a row of empty
  // tracks, which reads as "loading" rather than "nothing here".
  if (bars.length === 0 || total === 0) return <EmptyState message={emptyMessage} />;

  return (
    <ul className={cn('space-y-2.5', className)}>
      {bars.map((bar, index) => (
        <li key={bar.label} className="space-y-1">
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="truncate">{bar.label}</span>
            <span className="shrink-0 tabular-nums font-medium">{valueFormatter(bar.value)}</span>
          </div>
          <div
            className="h-2 overflow-hidden rounded-full bg-secondary"
            role="img"
            aria-label={`${bar.label}: ${valueFormatter(bar.value)}`}
          >
            <div
              className="h-full rounded-full transition-[width] duration-500"
              style={{
                width: `${Math.max(2, (bar.value / max) * 100)}%`,
                background: bar.color ?? SERIES_COLORS[index % SERIES_COLORS.length],
              }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------------------
// Donut chart
// ---------------------------------------------------------------------------

export interface Slice {
  label: string;
  value: number;
  color?: string;
}

/**
 * Donut chart for a small number of parts of a whole.
 *
 * Drawn with `stroke-dasharray` on concentric circles rather than arc paths: the
 * maths is one subtraction per slice instead of polar-to-cartesian conversion
 * with a large-arc flag, and there is no seam artefact where the arcs meet.
 */
export function DonutChart({
  slices,
  size = 160,
  thickness = 18,
  centerLabel,
  centerValue,
  className,
  emptyMessage = 'No data yet.',
}: {
  slices: readonly Slice[];
  size?: number;
  thickness?: number;
  centerLabel?: string;
  centerValue?: string | number;
  className?: string;
  emptyMessage?: string;
}): React.ReactElement {
  const total = slices.reduce((sum, slice) => sum + slice.value, 0);

  if (total === 0) return <EmptyState message={emptyMessage} />;

  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;

  let consumed = 0;

  return (
    <figure className={cn('flex flex-wrap items-center gap-6', className)}>
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg
          viewBox={`0 0 ${size} ${size}`}
          width={size}
          height={size}
          role="img"
          aria-label={slices
            .map((slice) => `${slice.label}: ${slice.value}`)
            .join(', ')}
          // Rotated so the first slice starts at 12 o'clock, which is where
          // people expect a donut to begin.
          style={{ transform: 'rotate(-90deg)' }}
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="hsl(var(--secondary))"
            strokeWidth={thickness}
          />

          {slices.map((slice, index) => {
            const fraction = slice.value / total;
            const dash = fraction * circumference;
            const offset = -consumed * circumference;
            consumed += fraction;

            return (
              <circle
                key={slice.label}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                stroke={slice.color ?? SERIES_COLORS[index % SERIES_COLORS.length]}
                strokeWidth={thickness}
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={offset}
                strokeLinecap="butt"
              />
            );
          })}
        </svg>

        {(centerValue !== undefined || centerLabel) && (
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            {centerValue !== undefined && (
              <span className="text-2xl font-semibold tabular-nums">{centerValue}</span>
            )}
            {centerLabel && (
              <span className="text-xs text-muted-foreground">{centerLabel}</span>
            )}
          </div>
        )}
      </div>

      <figcaption className="min-w-0 flex-1 space-y-1.5">
        {slices.map((slice, index) => (
          <div key={slice.label} className="flex items-center gap-2 text-sm">
            <span
              className="size-2.5 shrink-0 rounded-sm"
              style={{ background: slice.color ?? SERIES_COLORS[index % SERIES_COLORS.length] }}
              aria-hidden
            />
            <span className="min-w-0 flex-1 truncate text-muted-foreground">{slice.label}</span>
            <span className="tabular-nums font-medium">{slice.value.toLocaleString()}</span>
            <span className="w-10 text-right text-xs tabular-nums text-muted-foreground">
              {Math.round((slice.value / total) * 100)}%
            </span>
          </div>
        ))}
      </figcaption>
    </figure>
  );
}

// ---------------------------------------------------------------------------
// Sparkline
// ---------------------------------------------------------------------------

/** Inline trend line for a statistic card. */
export function Sparkline({
  points,
  color = 'hsl(var(--primary))',
  width = 120,
  height = 32,
  className,
}: {
  points: readonly Point[];
  color?: string;
  width?: number;
  height?: number;
  className?: string;
}): React.ReactElement | null {
  if (points.length < 2) return null;

  const values = points.map((point) => point.value);
  const max = Math.max(1, ...values);

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      width={width}
      height={height}
      className={className}
      aria-hidden
    >
      <path
        d={linePath(values, width, height, max)}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

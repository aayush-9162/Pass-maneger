import * as React from 'react';

import { cn } from '@/lib/utils';

/**
 * Styled native `<select>`.
 *
 * A native element rather than a custom listbox. The admin panel uses selects
 * for filters and short enumerations - role, status, group - where the
 * native control is better on every axis that matters: it is keyboard and screen
 * reader correct without any work, it renders as the platform picker on mobile,
 * and it costs no JavaScript.
 *
 * `appearance-none` plus a drawn chevron keeps it visually consistent with the
 * rest of the form controls in both themes.
 */
export const Select = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(({ className, children, ...props }, ref) => (
  <div className="relative">
    <select
      ref={ref}
      className={cn(
        'flex h-10 w-full appearance-none rounded-md border border-input bg-background px-3 py-2 pr-9 text-sm',
        'ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2',
        'disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      {...props}
    >
      {children}
    </select>

    <svg
      className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <path d="m4 6 4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  </div>
));
Select.displayName = 'Select';

/** Compact variant for table cells and toolbars. */
export const SelectCompact = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(({ className, ...props }, ref) => (
  <Select ref={ref} className={cn('h-8 py-1 text-xs', className)} {...props} />
));
SelectCompact.displayName = 'SelectCompact';

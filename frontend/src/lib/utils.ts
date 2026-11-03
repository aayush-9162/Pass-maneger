import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Merge conditional class names, resolving Tailwind conflicts.
 *
 * `clsx` handles conditionals; `twMerge` ensures a later utility wins over an
 * earlier conflicting one, so `cn('p-2', 'p-4')` yields `p-4` rather than both.
 * Without it, component variants and caller overrides fight unpredictably.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

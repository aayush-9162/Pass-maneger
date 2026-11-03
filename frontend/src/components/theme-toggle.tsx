import { Monitor, Moon, Sun } from 'lucide-react';
import * as React from 'react';

import { useTheme, type Theme } from '@/lib/theme';
import { cn } from '@/lib/utils';

const OPTIONS: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
];

/**
 * Three-way theme switch.
 *
 * A segmented control rather than a two-state toggle, because "follow the
 * system" is a real preference and a toggle cannot express it - a user who has
 * their OS on a sunset schedule would otherwise have to flip this by hand twice
 * a day.
 */
export function ThemeToggle(): React.ReactElement {
  const { theme, setTheme } = useTheme();

  return (
    <div
      className="inline-flex items-center rounded-lg border bg-background p-0.5"
      role="radiogroup"
      aria-label="Colour theme"
    >
      {OPTIONS.map((option) => {
        const active = theme === option.value;

        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={active}
            title={option.label}
            onClick={() => setTheme(option.value)}
            className={cn(
              'flex size-7 items-center justify-center rounded-md transition-colors',
              active
                ? 'bg-secondary text-secondary-foreground'
                : 'text-muted-foreground hover:text-foreground',
            )}
          >
            <option.icon className="size-4" aria-hidden />
            <span className="sr-only">{option.label}</span>
          </button>
        );
      })}
    </div>
  );
}

/**
 * Theme (light / dark / system).
 *
 * Tailwind is configured with `darkMode: ['class']`, so the whole theme is one
 * class on `<html>` and every component follows without a conditional.
 *
 * Two details that are easy to get wrong and unpleasant to live with:
 *
 *  - **The flash.** A provider that applies the theme in `useEffect` renders one
 *    frame of light mode first, which on a dark-themed screen is a flash of
 *    white on every page load. The fix is a tiny script in `<head>` that runs
 *    before first paint - see `public/theme-init.js`.
 *  - **"System" is a live setting, not a one-time read.** Following the OS means
 *    subscribing to `prefers-color-scheme`, so a machine that switches at sunset
 *    switches the console with it.
 */

import * as React from 'react';

export type Theme = 'light' | 'dark' | 'system';

/** Resolved appearance after `system` has been consulted. */
export type ResolvedTheme = 'light' | 'dark';

/** Also read by `public/theme-init.js`, which cannot import it. Change both together. */
const STORAGE_KEY = 'passm.theme';

interface ThemeContextValue {
  theme: Theme;
  resolvedTheme: ResolvedTheme;
  setTheme: (theme: Theme) => void;
}

const ThemeContext = React.createContext<ThemeContextValue | null>(null);

function readStoredTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'light';
  } catch {
    return 'light';
  }
}

function systemPrefersDark(): boolean {
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function apply(resolved: ResolvedTheme): void {
  const root = document.documentElement;
  root.classList.toggle('dark', resolved === 'dark');
  // Tells the browser to render native controls (scrollbars, date pickers,
  // form fields) in the matching scheme. Without it a dark page keeps white
  // scrollbars, which looks broken rather than themed.
  root.style.colorScheme = resolved;
}

export function ThemeProvider({ children }: { children: React.ReactNode }): React.ReactElement {
  // The pre-paint script has already put the right class on <html>; this reads
  // the same preference so React's copy of the state agrees from the first render.
  const [theme, setThemeState] = React.useState<Theme>(readStoredTheme);
  const [resolvedTheme, setResolvedTheme] = React.useState<ResolvedTheme>(() => {
    const stored = readStoredTheme();
    return stored === 'system' ? (systemPrefersDark() ? 'dark' : 'light') : stored;
  });

  // Follow the OS while the preference is `system`.
  React.useEffect(() => {
    if (theme !== 'system') return undefined;

    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (): void => {
      const resolved = media.matches ? 'dark' : 'light';
      setResolvedTheme(resolved);
      apply(resolved);
    };

    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [theme]);

  const setTheme = React.useCallback((next: Theme) => {
    setThemeState(next);

    const resolved = next === 'system' ? (systemPrefersDark() ? 'dark' : 'light') : next;
    setResolvedTheme(resolved);
    apply(resolved);

    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Preference is not persisted in private browsing; the session still works.
    }
  }, []);

  const value = React.useMemo(
    () => ({ theme, resolvedTheme, setTheme }),
    [theme, resolvedTheme, setTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = React.useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used inside a ThemeProvider.');
  return context;
}

/*
 * Pre-paint theme application. Loaded synchronously from index.html.
 *
 * Kept deliberately tiny, and it reads only its own storage key. The key must
 * match `STORAGE_KEY` in src/lib/theme.tsx - this file runs before any bundle
 * has loaded, so it cannot import it.
 */
(function () {
  try {
    var stored = localStorage.getItem('passm.theme');
    var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    // Light unless the user chose otherwise. The OS preference only applies
    // when they explicitly picked "system" - a console that silently follows
    // Windows into dark mode looks broken to anyone who never asked for it.
    var dark = stored === 'dark' || (stored === 'system' && prefersDark);
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
  } catch (error) {
    // Private browsing can make localStorage throw. Light mode is a fine
    // fallback, and a theme preference is never worth breaking a page load.
  }
})();

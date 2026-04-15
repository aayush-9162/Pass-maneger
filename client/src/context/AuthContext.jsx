/**
 * AuthContext — single source of truth for authentication + encryption state.
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  THREE LAYERS OF STATE                                                  ║
 * ║                                                                          ║
 * ║  Layer 1 — JWT + salt  (sessionStorage)                                 ║
 * ║    Survives page reloads within the same tab.                           ║
 * ║    Cleared when the tab is closed (sessionStorage lifecycle).           ║
 * ║    Token authenticates API requests; salt feeds PBKDF2 on unlock.      ║
 * ║                                                                          ║
 * ║  Layer 2 — Encryption key  (React state ONLY — NEVER persisted)        ║
 * ║    A non-extractable CryptoKey object. Cannot be serialized, cannot    ║
 * ║    be written to localStorage, cannot be sent via postMessage.          ║
 * ║    Lost on page reload (by design — forces master password re-entry).  ║
 * ║    Auto-wiped on: 5 min inactivity, tab hidden, window close.          ║
 * ║                                                                          ║
 * ║  Layer 3 — Key verifier  (sessionStorage)                              ║
 * ║    An encrypted sentinel created on first unlock. On subsequent        ║
 * ║    unlocks we decrypt it to confirm the derived key matches.           ║
 * ║    Opaque ciphertext — completely useless without the Layer 2 key.     ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
} from 'react';
import {
  deriveKey,
  createKeyVerifier,
  verifyKey,
  KeyDerivationError,
} from '../utils/crypto';

const AuthContext = createContext(null);

/** Inactivity timeout: wipe key after 5 minutes of no user interaction. */
const INACTIVITY_MS = 5 * 60 * 1000;

export function AuthProvider({ children }) {
  // ── Layer 1: session credentials (sessionStorage-backed) ─────────────
  const [token, setToken] = useState(() => sessionStorage.getItem('token'));
  const [salt, setSalt]   = useState(() => sessionStorage.getItem('salt'));

  // ── Layer 2: encryption key (memory-only) ────────────────────────────
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [isUnlocked, setIsUnlocked] = useState(false);

  const timerRef = useRef(null);

  // ── Key wipe helper ──────────────────────────────────────────────────
  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const wipeKey = useCallback(() => {
    setEncryptionKey(null);
    setIsUnlocked(false);
    clearTimer();
  }, [clearTimer]);

  // ── Inactivity timer reset ───────────────────────────────────────────
  const resetTimer = useCallback(() => {
    clearTimer();
    if (!encryptionKey) return;
    timerRef.current = setTimeout(wipeKey, INACTIVITY_MS);
  }, [encryptionKey, clearTimer, wipeKey]);

  // ── Auto-lock lifecycle ──────────────────────────────────────────────
  useEffect(() => {
    if (!isUnlocked) return;

    // User-activity events that reset the inactivity timer
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'mousemove'];
    const onActivity = () => resetTimer();
    events.forEach((e) => window.addEventListener(e, onActivity, { passive: true }));

    // Wipe key when the user switches away from the tab
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') wipeKey();
    };
    document.addEventListener('visibilitychange', onVisibility);

    // Wipe key when the tab/window is closed
    const onUnload = () => wipeKey();
    window.addEventListener('beforeunload', onUnload);

    // Start the initial timer
    resetTimer();

    return () => {
      events.forEach((e) => window.removeEventListener(e, onActivity));
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('beforeunload', onUnload);
      clearTimer();
    };
  }, [isUnlocked, resetTimer, wipeKey, clearTimer]);

  // ── handleLogin: store JWT + salt after successful auth ──────────────
  const handleLogin = useCallback((jwtToken, userSalt) => {
    sessionStorage.setItem('token', jwtToken);
    sessionStorage.setItem('salt', userSalt);
    setToken(jwtToken);
    setSalt(userSalt);
  }, []);

  // ── unlock: derive key from master password, verify if possible ──────
  /**
   * @param {string} masterPassword — entered by the user, used transiently
   * @returns {Promise<{ isValid: boolean }>}
   * @throws {KeyDerivationError}
   */
  const unlock = useCallback(async (masterPassword) => {
    if (!salt) {
      throw new KeyDerivationError('No salt available — please log in first');
    }

    // Derive the AES-256-GCM key (300k PBKDF2 iterations, ~200-800ms)
    const key = await deriveKey(masterPassword, salt);

    // If we have a stored verifier from a previous unlock, test the key
    const stored = sessionStorage.getItem('keyVerifier');
    if (stored) {
      const { encryptedData, iv } = JSON.parse(stored);
      const correct = await verifyKey(encryptedData, iv, key);
      if (!correct) {
        return { isValid: false };
      }
    } else {
      // First-time unlock — create a verifier for future sessions.
      // Stored as opaque ciphertext; useless without the in-memory key.
      const verifier = await createKeyVerifier(key);
      sessionStorage.setItem('keyVerifier', JSON.stringify(verifier));
    }

    setEncryptionKey(key);
    setIsUnlocked(true);
    return { isValid: true };
  }, [salt]);

  // ── lock: clear key, keep session ────────────────────────────────────
  const lock = useCallback(() => {
    wipeKey();
  }, [wipeKey]);

  // ── logout: clear everything ─────────────────────────────────────────
  const logout = useCallback(() => {
    wipeKey();
    setToken(null);
    setSalt(null);
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('salt');
    sessionStorage.removeItem('keyVerifier');
  }, [wipeKey]);

  return (
    <AuthContext.Provider
      value={{
        token,
        salt,
        encryptionKey,
        isUnlocked,
        isAuthenticated: !!token,
        handleLogin,
        unlock,
        lock,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

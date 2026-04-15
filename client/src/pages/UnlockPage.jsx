/**
 * UnlockPage — Master Password Entry
 *
 * This page is the security boundary between authentication (JWT) and
 * vault access (encryption key). The master password entered here is:
 *
 *  1. NEVER transmitted to the server
 *  2. NEVER written to storage (localStorage, sessionStorage, cookies)
 *  3. Used ONLY to derive the AES-256-GCM key via PBKDF2 (300k iterations)
 *  4. Cleared from React state immediately after derivation completes
 *
 * If a key verifier exists from a previous unlock, the derived key is
 * tested against it. This detects wrong-password errors BEFORE attempting
 * to decrypt the entire vault.
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { KeyDerivationError } from '../utils/crypto';

export default function UnlockPage() {
  const [masterPassword, setMasterPassword] = useState('');
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);
  const { unlock, isAuthenticated, isUnlocked } = useAuth();
  const navigate = useNavigate();

  // Redirect: not logged in → login, already unlocked → vault
  useEffect(() => {
    if (!isAuthenticated) navigate('/login', { replace: true });
    else if (isUnlocked) navigate('/vault', { replace: true });
  }, [isAuthenticated, isUnlocked, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await unlock(masterPassword);

      // Immediately clear the master password from component state.
      // After this line, it exists nowhere except the JS engine's
      // garbage-collectible heap (which we cannot control).
      setMasterPassword('');

      if (!result.isValid) {
        setError(
          'Incorrect master password — the derived key does not match ' +
          'your previous unlock. Please try again.'
        );
        setLoading(false);
        return;
      }

      navigate('/vault', { replace: true });
    } catch (err) {
      setMasterPassword('');
      if (err instanceof KeyDerivationError) {
        setError(`Key derivation error: ${err.message}`);
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  if (!isAuthenticated) return null;

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>Unlock Vault</h1>
        <p className="hint">
          Enter your master password to derive your encryption key.
          This password never leaves your browser.
        </p>

        {error && <div className="error-msg">{error}</div>}

        <form onSubmit={handleSubmit}>
          <label htmlFor="master-pw">Master Password</label>
          <input
            id="master-pw"
            type="password"
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            required
            autoComplete="off"
            autoFocus
            placeholder="Your master encryption password"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !masterPassword}
            className="btn-primary"
          >
            {loading ? 'Deriving key (this takes a moment)...' : 'Unlock'}
          </button>
        </form>

        {loading && (
          <p className="hint" style={{ marginTop: '1rem' }}>
            Running 300,000 PBKDF2 iterations to derive your encryption key.
            This deliberate slowness protects you against brute-force attacks.
          </p>
        )}
      </div>
    </div>
  );
}

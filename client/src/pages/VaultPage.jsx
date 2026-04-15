/**
 * VaultPage — Main Dashboard
 *
 * E2E encryption data flow:
 *
 *  ADD:    user input → encryptData(entry, key) → POST /api/vault (ciphertext)
 *  FETCH:  GET /api/vault → [{ encrypted_data, iv }] → decryptData(each) → plaintext
 *  DELETE: DELETE /api/vault/:id → removed from server + local state
 *
 * The server NEVER sees plaintext. It stores and returns opaque ciphertext.
 * All encryption/decryption happens exclusively in this component via crypto.js.
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  getVaultEntries,
  saveVaultEntry,
  deleteVaultEntry,
} from '../utils/api';
import {
  encryptData,
  decryptData,
  DecryptionError,
  CryptoError,
} from '../utils/crypto';
import AddEntryForm from '../components/AddEntryForm';
import VaultEntry from '../components/VaultEntry';

export default function VaultPage() {
  const { encryptionKey, isUnlocked, isAuthenticated, lock, logout } = useAuth();
  const [entries, setEntries]     = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState('');
  const [showForm, setShowForm]   = useState(false);
  const [failCount, setFailCount] = useState(0);
  const navigate = useNavigate();

  // Guard routes
  useEffect(() => {
    if (!isAuthenticated) navigate('/login', { replace: true });
    else if (!isUnlocked) navigate('/unlock', { replace: true });
  }, [isAuthenticated, isUnlocked, navigate]);

  // ── Fetch + decrypt ──────────────────────────────────────────────────
  const fetchEntries = useCallback(async () => {
    if (!encryptionKey) return;
    setLoading(true);
    setError('');
    setFailCount(0);

    try {
      const { data: rawEntries } = await getVaultEntries();

      let failures = 0;

      const decrypted = await Promise.all(
        rawEntries.map(async (entry) => {
          try {
            // Decrypt each entry client-side using the in-memory key.
            // Server returns { id, encrypted_data, iv, created_at }.
            const plaintext = await decryptData(
              entry.encrypted_data,
              entry.iv,
              encryptionKey
            );
            return {
              id: entry.id,
              created_at: entry.created_at,
              decryptionFailed: false,
              ...plaintext,
            };
          } catch (err) {
            failures++;
            return {
              id: entry.id,
              created_at: entry.created_at,
              decryptionFailed: true,
              site: '[Decryption Failed]',
              username: '',
              password: '',
              error: err instanceof DecryptionError
                ? err.message
                : 'Unknown decryption error',
            };
          }
        })
      );

      setFailCount(failures);
      setEntries(decrypted);

      if (failures > 0 && failures === rawEntries.length && rawEntries.length > 0) {
        setError(
          `All ${failures} entries failed to decrypt. ` +
          'This usually means the wrong master password was used. ' +
          'Lock the vault and try again.'
        );
      } else if (failures > 0) {
        setError(
          `${failures} of ${rawEntries.length} entries could not be decrypted.`
        );
      }
    } catch {
      setError('Failed to fetch vault entries from the server.');
    } finally {
      setLoading(false);
    }
  }, [encryptionKey]);

  useEffect(() => { fetchEntries(); }, [fetchEntries]);

  // ── Add entry: encrypt client-side, send ciphertext to server ────────
  const handleAdd = async (entry) => {
    if (!encryptionKey) {
      setError('Vault is locked — please unlock first.');
      return;
    }
    try {
      const { encryptedData, iv } = await encryptData(entry, encryptionKey);
      await saveVaultEntry(encryptedData, iv);
      setShowForm(false);
      await fetchEntries();
    } catch (err) {
      if (err instanceof CryptoError) {
        setError(`Encryption error: ${err.message}`);
      } else {
        setError('Failed to save entry.');
      }
    }
  };

  // ── Delete entry ─────────────────────────────────────────────────────
  const handleDelete = async (id) => {
    try {
      await deleteVaultEntry(id);
      setEntries((prev) => prev.filter((e) => e.id !== id));
    } catch {
      setError('Failed to delete entry.');
    }
  };

  const handleLock = () => { lock(); navigate('/unlock', { replace: true }); };
  const handleLogout = () => { logout(); navigate('/login', { replace: true }); };

  if (!isUnlocked) return null;

  return (
    <div className="vault-page">
      <header className="vault-header">
        <h1>PassVault</h1>
        <div className="vault-actions">
          <button onClick={() => setShowForm(!showForm)} className="btn-primary">
            {showForm ? 'Cancel' : '+ Add Password'}
          </button>
          <button onClick={handleLock} className="btn-secondary">Lock</button>
          <button onClick={handleLogout} className="btn-danger">Logout</button>
        </div>
      </header>

      {error && <div className="error-msg">{error}</div>}

      {failCount > 0 && (
        <div className="error-msg" style={{ cursor: 'pointer' }} onClick={handleLock}>
          Wrong master password? Click here to lock and re-enter it.
        </div>
      )}

      {showForm && <AddEntryForm onAdd={handleAdd} />}

      <div className="vault-list">
        {loading ? (
          <p className="vault-empty">Decrypting your vault...</p>
        ) : entries.length === 0 ? (
          <p className="vault-empty">
            Your vault is empty. Click &quot;+ Add Password&quot; to get started.
          </p>
        ) : (
          entries.map((entry) => (
            <VaultEntry key={entry.id} entry={entry} onDelete={handleDelete} />
          ))
        )}
      </div>
    </div>
  );
}

import { useState } from 'react';

/**
 * Renders a single vault entry card.
 *
 * The entry object is ALREADY DECRYPTED by VaultPage before reaching
 * this component. Plaintext exists only in React state (memory) and
 * is rendered to the DOM only when the user clicks "Show".
 *
 * Entries that failed decryption are rendered with a distinct error state.
 */
export default function VaultEntry({ entry, onDelete }) {
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState('');

  const copyToClipboard = async (text, field) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(field);
      setTimeout(() => setCopied(''), 2000);
    } catch {
      // Clipboard API requires HTTPS or localhost — fails silently otherwise
    }
  };

  // ── Failed decryption card ───────────────────────────────────────────
  if (entry.decryptionFailed) {
    return (
      <div className="vault-entry vault-entry--failed">
        <div className="vault-entry-header">
          <h4 style={{ color: 'var(--danger)' }}>[Decryption Failed]</h4>
          <button
            onClick={() => onDelete(entry.id)}
            className="btn-danger btn-sm"
          >
            Delete
          </button>
        </div>
        <p className="vault-entry-error">
          {entry.error || 'Could not decrypt with the current key.'}
        </p>
      </div>
    );
  }

  // ── Normal decrypted card ────────────────────────────────────────────
  return (
    <div className="vault-entry">
      <div className="vault-entry-header">
        <h4>{entry.site}</h4>
        <button
          onClick={() => onDelete(entry.id)}
          className="btn-danger btn-sm"
          title="Delete entry"
        >
          Delete
        </button>
      </div>

      <div className="vault-entry-field">
        <span className="field-label">Username:</span>
        <span className="field-value">{entry.username}</span>
        <button
          onClick={() => copyToClipboard(entry.username, 'username')}
          className="btn-copy"
        >
          {copied === 'username' ? 'Copied!' : 'Copy'}
        </button>
      </div>

      <div className="vault-entry-field">
        <span className="field-label">Password:</span>
        <span className="field-value">
          {showPassword ? entry.password : '\u2022'.repeat(12)}
        </span>
        <button
          onClick={() => setShowPassword((prev) => !prev)}
          className="btn-copy"
        >
          {showPassword ? 'Hide' : 'Show'}
        </button>
        <button
          onClick={() => copyToClipboard(entry.password, 'password')}
          className="btn-copy"
        >
          {copied === 'password' ? 'Copied!' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

import { useState } from 'react';
import { generatePassword } from '../utils/passwordGenerator';

/**
 * Form for adding a new vault entry.
 *
 * The { site, username, password } object produced here is passed to
 * the parent's onAdd callback, which encrypts it client-side before
 * sending the ciphertext to the server. Plaintext never leaves the browser.
 */
export default function AddEntryForm({ onAdd }) {
  const [site, setSite]         = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading]   = useState(false);

  const handleGenerate = () => {
    setPassword(generatePassword(20));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await onAdd({ site, username, password });
      setSite('');
      setUsername('');
      setPassword('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="add-entry-form">
      <h3>Add New Entry</h3>
      <form onSubmit={handleSubmit}>
        <label htmlFor="entry-site">Site / Service</label>
        <input
          id="entry-site"
          type="text"
          value={site}
          onChange={(e) => setSite(e.target.value)}
          required
          placeholder="e.g. github.com"
        />
        <label htmlFor="entry-user">Username / Email</label>
        <input
          id="entry-user"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
          placeholder="e.g. user@example.com"
        />
        <label htmlFor="entry-pass">Password</label>
        <div className="password-input-row">
          <input
            id="entry-pass"
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            placeholder="Enter or generate a password"
          />
          <button type="button" onClick={handleGenerate} className="btn-generate">
            Generate
          </button>
        </div>
        <button type="submit" disabled={loading} className="btn-primary">
          {loading ? 'Encrypting...' : 'Save Entry'}
        </button>
      </form>
    </div>
  );
}

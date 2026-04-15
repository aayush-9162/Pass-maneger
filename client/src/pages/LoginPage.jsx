import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { login } from '../utils/api';

export default function LoginPage() {
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const { handleLogin } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const { data } = await login(email, password);
      // Server returns JWT + PBKDF2 salt for client-side key derivation
      handleLogin(data.token, data.salt);
      navigate('/unlock', { replace: true });
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>PassVault</h1>
        <h2>Sign In</h2>
        {error && <div className="error-msg">{error}</div>}
        <form onSubmit={handleSubmit}>
          <label htmlFor="login-email">Email</label>
          <input
            id="login-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
          />
          <label htmlFor="login-pass">Login Password</label>
          <input
            id="login-pass"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            autoComplete="current-password"
          />
          <button type="submit" disabled={loading} className="btn-primary">
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        <p className="auth-link">
          Don&apos;t have an account? <Link to="/register">Register</Link>
        </p>
      </div>
    </div>
  );
}

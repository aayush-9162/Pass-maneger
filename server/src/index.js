/**
 * PassVault Express Server
 *
 * This server is a BLIND STORAGE backend. It authenticates users with
 * bcrypt + JWT and stores AES-256-GCM ciphertext blobs from the client.
 * It NEVER decrypts, inspects, or processes the plaintext vault data.
 *
 * Security middleware:
 *  - Helmet     → HTTP security headers (X-Frame-Options, CSP hints, etc.)
 *  - CORS       → Restrict origins (dev: localhost:5173, prod: env var)
 *  - Rate limit → 20 attempts per 15 min on auth endpoints
 *  - JSON limit → 1 MB body size cap
 */

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

import authRoutes from './routes/auth.js';
import vaultRoutes from './routes/vault.js';
import pool from './config/db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// ── Security headers ───────────────────────────────────────────────────────
app.use(helmet());

// ── CORS ───────────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? process.env.FRONTEND_URL
    : [
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:5175',
      ],
  credentials: true,
}));

// ── Body parsing ───────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));

// ── Rate limiting on auth endpoints ────────────────────────────────────────
// Prevents brute-force attacks on login/register
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15-minute window
  max: 20,                     // 20 requests per window per IP
  message: { error: 'Too many requests — try again in 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Routes ─────────────────────────────────────────────────────────────────
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/vault', vaultRoutes);

// ── Health check ───────────────────────────────────────────────────────────
app.get('/api/health', async (_req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch {
    res.status(503).json({ status: 'error', database: 'disconnected' });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`PassVault server listening on port ${PORT}`);
});

export default app;

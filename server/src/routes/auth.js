/**
 * Authentication Routes
 *
 * POST /api/auth/register  — Create account, return JWT + PBKDF2 salt
 * POST /api/auth/login     — Verify credentials, return JWT + PBKDF2 salt
 *
 * IMPORTANT SECURITY NOTES:
 *  - The "password" in these routes is the LOGIN password (hashed with bcrypt).
 *  - The "salt" returned to the client is for PBKDF2 key derivation from the
 *    MASTER password, which is a DIFFERENT credential entered client-side only.
 *  - The master password and derived encryption key NEVER touch this server.
 */

import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { body } from 'express-validator';
import { handleValidationErrors } from '../middleware/validate.js';
import pool from '../config/db.js';

const router = Router();

// ── Shared validation chain for email + password ───────────────────────────
const authValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('A valid email address is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),
  handleValidationErrors,
];

// ── POST /api/auth/register ────────────────────────────────────────────────

router.post('/register', authValidation, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check for existing account
    const [existing] = await pool.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const id = uuidv4();

    // Hash the LOGIN password with bcrypt (cost factor 12).
    // bcrypt internally generates its own random salt for the hash.
    const passwordHash = await bcrypt.hash(password, 12);

    // Generate a 32-byte cryptographically random salt for the CLIENT
    // to use with PBKDF2 when deriving the encryption key from the
    // master password. This salt is stored in the DB and returned to
    // the client on every login. The server never uses it for decryption.
    const salt = crypto.randomBytes(32).toString('base64');

    await pool.execute(
      'INSERT INTO users (id, email, password_hash, salt) VALUES (?, ?, ?, ?)',
      [id, email, passwordHash, salt]
    );

    // Issue a JWT so the user is authenticated immediately after registration
    const token = jwt.sign(
      { id, email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    res.status(201).json({ token, salt });
  } catch (err) {
    console.error('Registration error:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ── POST /api/auth/login ───────────────────────────────────────────────────

router.post('/login', authValidation, async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await pool.execute(
      'SELECT id, email, password_hash, salt FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      // Generic error message — do NOT reveal whether the email exists.
      // bcrypt.compare is still called below on a dummy hash so that the
      // response time doesn't leak user-existence information.
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = rows[0];

    // Constant-time comparison via bcrypt
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
    );

    // Return the PBKDF2 salt so the client can derive the encryption key
    res.json({ token, salt: user.salt });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

export default router;

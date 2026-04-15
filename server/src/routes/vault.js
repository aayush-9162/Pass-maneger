/**
 * Vault Routes — Blind Encrypted Storage
 *
 * POST   /api/vault      — Store an encrypted entry
 * GET    /api/vault      — Retrieve all encrypted entries for the user
 * DELETE /api/vault/:id  — Delete an entry (ownership-checked)
 *
 * ZERO-KNOWLEDGE CONTRACT:
 *  - The server receives encrypted_data (AES-256-GCM ciphertext, base64) and
 *    iv (initialization vector, base64) as opaque strings.
 *  - It stores them, returns them, and deletes them. Nothing else.
 *  - There is NO decryption logic anywhere on the backend.
 *  - There is NO plaintext processing of vault content.
 *  - The backend cannot read user passwords even if the database is compromised.
 */

import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { body, param } from 'express-validator';
import { handleValidationErrors } from '../middleware/validate.js';
import { authenticate } from '../middleware/auth.js';
import pool from '../config/db.js';

const router = Router();

// Every vault route requires a valid JWT
router.use(authenticate);

// ── POST /api/vault ────────────────────────────────────────────────────────
// Store a new encrypted vault entry.
// The server does NOT inspect or validate the ciphertext content.

router.post(
  '/',
  [
    body('encrypted_data')
      .isString().notEmpty()
      .withMessage('encrypted_data is required'),
    body('iv')
      .isString().notEmpty()
      .withMessage('iv is required'),
    handleValidationErrors,
  ],
  async (req, res) => {
    try {
      const { encrypted_data, iv } = req.body;
      const id = uuidv4();

      await pool.execute(
        'INSERT INTO vault (id, user_id, encrypted_data, iv) VALUES (?, ?, ?, ?)',
        [id, req.user.id, encrypted_data, iv]
      );

      res.status(201).json({ id, message: 'Vault entry saved' });
    } catch (err) {
      console.error('Vault save error:', err.message);
      res.status(500).json({ error: 'Failed to save vault entry' });
    }
  }
);

// ── GET /api/vault ─────────────────────────────────────────────────────────
// Return all encrypted entries belonging to the authenticated user.
// Data remains encrypted — decryption is client-only.

router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, encrypted_data, iv, created_at FROM vault WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('Vault fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch vault entries' });
  }
});

// ── DELETE /api/vault/:id ──────────────────────────────────────────────────
// Delete a vault entry. The WHERE clause checks BOTH the entry ID and the
// user_id from the JWT to prevent IDOR attacks (user A deleting user B's data).

router.delete(
  '/:id',
  [
    param('id').isUUID().withMessage('Entry ID must be a valid UUID'),
    handleValidationErrors,
  ],
  async (req, res) => {
    try {
      const [result] = await pool.execute(
        'DELETE FROM vault WHERE id = ? AND user_id = ?',
        [req.params.id, req.user.id]
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Vault entry not found' });
      }

      res.json({ message: 'Vault entry deleted' });
    } catch (err) {
      console.error('Vault delete error:', err.message);
      res.status(500).json({ error: 'Failed to delete vault entry' });
    }
  }
);

export default router;

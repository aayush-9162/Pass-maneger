/**
 * JWT authentication middleware.
 *
 * Validates the Bearer token from the Authorization header and attaches
 * the decoded payload { id, email } to req.user for downstream handlers.
 *
 * Rejection cases:
 *  - Missing Authorization header        → 401
 *  - Malformed header (not "Bearer …")   → 401
 *  - Expired or invalid signature         → 401
 */

import jwt from 'jsonwebtoken';

export function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = header.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // Attach only the fields downstream handlers need
    req.user = { id: decoded.id, email: decoded.email };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

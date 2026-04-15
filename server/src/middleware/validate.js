/**
 * Centralized validation error handler for express-validator.
 *
 * Place this after your validation chains:
 *   router.post('/foo', [body('x').isString(), handleValidationErrors], handler);
 *
 * Returns 400 with the array of validation errors if any exist,
 * otherwise passes control to the next handler.
 */

import { validationResult } from 'express-validator';

export function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

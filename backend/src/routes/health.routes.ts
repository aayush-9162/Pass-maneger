/**
 * Health routes. Unauthenticated by necessity - probes cannot sign in - and
 * therefore free of any internal detail.
 */

import { Router } from 'express';

import { healthController } from '../controllers/health.controller';
import { asyncHandler } from '../utils/async-handler';

export const healthRoutes = Router();

/** Liveness: no dependency checks, so a database blip cannot cause a restart storm. */
healthRoutes.get('/', healthController.live);

/** Readiness: checks MySQL (hard) and the cache (soft). */
healthRoutes.get('/ready', asyncHandler(healthController.ready));

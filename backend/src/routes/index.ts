/**
 * Route registration.
 *
 * The auth router is mounted twice on purpose:
 *
 *  - `/api/v1/auth/*` - the canonical, namespaced form used by the frontend and
 *    the extension.
 *  - `/api/v1/*`      - the flat form named in the API specification
 *                       (`POST /google`, `POST /logout`, `POST /refresh`,
 *                       `GET /profile`).
 *
 * Both resolve to the same handlers, so there is one implementation and no risk
 * of the two forms drifting apart in their middleware chains.
 */

import { API_PREFIX, API_VERSION } from '@passm/shared';
import { Router } from 'express';

import { env } from '../config/env';
import { adminRoutes } from './admin.routes';
import { authRoutes } from './auth.routes';
import { healthRoutes } from './health.routes';
import { iconRoutes } from './icons.routes';
import { securityRoutes } from './security.routes';
import { sharedRoutes } from './shared.routes';
import { vaultRoutes } from './vault.routes';

export const apiRouter = Router();

apiRouter.use('/health', healthRoutes);
apiRouter.use('/icons', iconRoutes);
apiRouter.use('/auth', authRoutes);
apiRouter.use('/admin', adminRoutes);
apiRouter.use('/vault', vaultRoutes);
apiRouter.use('/shared', sharedRoutes);
apiRouter.use('/security', securityRoutes);

/** Spec-compatible flat aliases: /api/v1/login, /logout, /refresh, /profile. */
apiRouter.use('/', authRoutes);

/**
 * Service descriptor at the API root.
 *
 * Lists only what an authorised client needs to discover the surface. No
 * versions of dependencies, no environment details - a public endpoint should not
 * help someone fingerprint the stack.
 */
apiRouter.get('/', (_req, res) => {
  res.json({
    success: true,
    data: {
      service: env.appName,
      apiVersion: API_VERSION,
      endpoints: {
        login: `POST ${API_PREFIX}/auth/google`,
        logout: `POST ${API_PREFIX}/auth/logout`,
        refresh: `POST ${API_PREFIX}/auth/refresh`,
        profile: `GET ${API_PREFIX}/auth/profile`,
        register: `POST ${API_PREFIX}/auth/register (admin only)`,
        sessions: `GET ${API_PREFIX}/auth/sessions`,
        devices: `GET ${API_PREFIX}/auth/devices`,
        admin: `${API_PREFIX}/admin/users`,
        health: `GET ${API_PREFIX}/health`,
      },
    },
    requestId: res.locals.requestId,
    timestamp: new Date().toISOString(),
  });
});

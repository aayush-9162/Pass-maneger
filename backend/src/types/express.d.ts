/**
 * Express type augmentation.
 *
 * Middleware attaches request-scoped state; declaring it here means controllers
 * read `req.auth.userId` with full type safety instead of casting to `any`.
 */

import type { DeviceIdentity } from '@passm/shared';
import type { Logger } from 'winston';

import type { AuthContext, RequestContext } from './auth.types';

declare global {
  namespace Express {
    interface Request {
      /** Correlation id, set by `requestContext` and echoed as `x-request-id`. */
      requestId: string;
      /** Child logger pre-bound to the request id, method and path. */
      log: Logger;
      /** High-resolution start time, used to compute request duration. */
      startedAt: bigint;
      /** Normalised client IP, user agent and request id (for services/audit). */
      context: RequestContext;
      /**
       * Present only after `authenticate` has run.
       * Routes behind `authenticate` may use `req.auth!`; public routes must not.
       */
      auth?: AuthContext;
      /** Device metadata parsed from headers/body, when the client supplied it. */
      deviceIdentity?: DeviceIdentity | null;
    }

    interface Locals {
      requestId: string;
    }
  }
}

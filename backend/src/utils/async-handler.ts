/**
 * Async route wrapper.
 *
 * Express 4 does not catch rejected promises from handlers: an unhandled
 * rejection would leave the request hanging until the client times out. Wrapping
 * every async handler funnels rejections into `next()` and therefore into the
 * central error middleware.
 */

import type { NextFunction, Request, RequestHandler, Response } from 'express';

type AsyncHandler<Req> = (req: Req, res: Response, next: NextFunction) => Promise<unknown>;

/**
 * ```ts
 * router.post('/login', validate({ body: loginSchema }), asyncHandler(authController.login));
 * ```
 *
 * The handler may declare a narrowed request type (see `TypedRequest`), which is
 * why the incoming `Request` is re-typed here. That assertion is sound only
 * because the matching `validate(...)` middleware runs first and replaces
 * `body`/`query`/`params` with parsed data - so the two always appear together on
 * a route, and a handler with a `TypedRequest` signature must never be mounted
 * without its schema.
 */
export function asyncHandler<Req = Request>(handler: AsyncHandler<Req>): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(handler(req as unknown as Req, res, next)).catch(next);
  };
}

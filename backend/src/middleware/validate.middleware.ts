/**
 * Request validation.
 *
 * Every route that accepts input declares a zod schema. The parsed, normalised
 * result *replaces* the raw input, so handlers downstream can only ever see
 * validated data - there is no path by which an unvalidated field reaches a
 * service. Combined with `.strict()` on the DTO schemas, unknown keys are
 * rejected rather than passed along, which blocks mass-assignment.
 */

import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { ZodError, type ZodTypeAny } from 'zod';

import type { ApiFieldError } from '@passm/shared';

import { ValidationError } from '../utils/errors';

export interface ValidationSchemas {
  body?: ZodTypeAny;
  query?: ZodTypeAny;
  params?: ZodTypeAny;
}

/**
 * Convert a `ZodError` into the API's field-error list.
 *
 * The `field` path is prefixed with its source (`body.email`, `query.page`) so a
 * client can tell a bad query string from a bad body without guessing.
 */
function toFieldErrors(error: ZodError, source: string): ApiFieldError[] {
  return error.issues.map((issue) => ({
    field: issue.path.length > 0 ? `${source}.${issue.path.join('.')}` : source,
    message: issue.message,
  }));
}

/**
 * Replace a request property with its validated value.
 *
 * `req.query` is an accessor on the Express prototype, so a plain assignment
 * throws in strict mode. `defineProperty` installs an own property that shadows
 * it, which works uniformly for body, query and params.
 */
function assignValidated(req: Request, key: 'body' | 'query' | 'params', value: unknown): void {
  Object.defineProperty(req, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Validate one or more parts of the request.
 *
 * ```ts
 * router.post('/login', validate({ body: loginSchema }), asyncHandler(login));
 * ```
 *
 * All sources are validated before anything is reported, so the client receives
 * every problem in a single 422 instead of discovering them one at a time.
 */
export function validate(schemas: ValidationSchemas): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    const errors: ApiFieldError[] = [];
    const parsed: Partial<Record<'body' | 'query' | 'params', unknown>> = {};

    for (const source of ['params', 'query', 'body'] as const) {
      const schema = schemas[source];
      if (!schema) continue;

      const result = schema.safeParse(req[source] ?? {});
      if (result.success) {
        parsed[source] = result.data;
      } else {
        errors.push(...toFieldErrors(result.error, source));
      }
    }

    if (errors.length > 0) {
      next(new ValidationError(errors));
      return;
    }

    for (const [source, value] of Object.entries(parsed) as [
      'body' | 'query' | 'params',
      unknown,
    ][]) {
      assignValidated(req, source, value);
    }

    next();
  };
}

/**
 * Typed request alias for controllers.
 *
 * Because `validate` guarantees the shape, a controller can declare what it
 * expects and read `req.body` with full type safety and no cast:
 *
 * ```ts
 * async function login(req: TypedRequest<LoginDto>, res: Response) { ... }
 * ```
 */
export type TypedRequest<
  TBody = unknown,
  TParams = Request['params'],
  TQuery = Request['query'],
> = Omit<Request, 'body' | 'params' | 'query'> & {
  body: TBody;
  params: TParams;
  query: TQuery;
};

/**
 * Convenience alias for handlers whose validated input is the query string, and
 * optionally the path parameters.
 *
 * The parameter order differs from {@link TypedRequest} on purpose: these
 * handlers lead with the query, so it reads as `TypedQueryRequest<Query>` in the
 * common case and `TypedQueryRequest<Query, Params>` when a nested route also
 * validates its ids.
 */
export type TypedQueryRequest<TQuery, TParams = Request['params']> = TypedRequest<
  unknown,
  TParams,
  TQuery
>;

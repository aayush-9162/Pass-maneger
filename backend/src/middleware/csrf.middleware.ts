/**
 * CSRF protection.
 *
 * ## Why the existing defences are not enough
 *
 * Phases 1-5 relied on two things: `SameSite=Lax` cookies, and a hard
 * requirement that bodies be `application/json`. Both are real, and both have
 * gaps that matter on the deployment this system actually targets - a LAN, by
 * IP address, over plain HTTP.
 *
 *  - **SameSite is same-*site*, not same-origin.** Sites are computed from the
 *    registrable domain, and a bare IP address has none. Worse, `http://10.0.0.5`
 *    and `http://10.0.0.9` are different *origins* but browsers treat IP hosts
 *    inconsistently across versions. Any other service on the same host - a
 *    router admin page, a colleague's dev server on another port - is same-site
 *    with this one, because ports are not part of a site either.
 *  - **Lax still permits top-level GET navigation.** Harmless while every
 *    mutation is a POST, which is true here, but it is one careless route away
 *    from not being true.
 *  - **The JSON content-type requirement is genuinely strong** - a cross-origin
 *    HTML form cannot set it, and `fetch` with a custom content type triggers a
 *    preflight that CORS refuses. It is defeated only by a browser bug or a
 *    misconfigured CORS origin. Defence in depth means not betting everything on
 *    one control.
 *
 * ## The mechanism
 *
 * Signed double-submit. The server issues a random token in a readable cookie;
 * the client echoes it in a header. An attacker's page can *cause* the cookie to
 * be sent but cannot *read* it, so it cannot produce the header.
 *
 * The token is HMAC-signed with the session id bound in. Plain double-submit has
 * a known weakness: an attacker who can set a cookie on a sibling origin - and
 * on a bare-IP LAN, sibling origins are everyone - can plant a value they know
 * and echo it in the header. Both halves then match and the check passes.
 * Binding the session id and signing means a token minted for one session is
 * rejected on another, and a token the attacker made up has no valid signature.
 *
 * ## Why not `httpOnly`
 *
 * The cookie must be readable by same-origin script; that is the whole
 * mechanism. It is not a credential: possessing it grants nothing without the
 * session cookie, which remains `httpOnly`.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import type { NextFunction, Request, RequestHandler, Response } from 'express';

import { COOKIES, HEADERS, AUDIT_ACTIONS } from '@passm/shared';

import { env } from '../config/env';
import { logger } from '../config/logger';
import { auditService } from '../services/audit.service';
import { securitySettingsService } from '../services/security-settings.service';
import { CsrfError } from '../utils/errors';
import { getClientIp } from '../utils/request-context';

/** Random half of the token, before signing. */
const TOKEN_BYTES = 32;

/**
 * Methods that cannot change state and therefore need no token.
 *
 * `HEAD` and `OPTIONS` are included because a preflight must succeed for the
 * real request to be sent at all - rejecting it would break every cross-origin
 * client, including the browser extension.
 */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Paths exempt from the check.
 *
 * Each is here for a specific reason, not for convenience:
 *
 *  - **login**: there is no session yet, so there is nothing to bind a token to.
 *    A forged login is not an attack on the victim - it signs them into the
 *    *attacker's* account, which is a real if minor concern (login CSRF), and is
 *    mitigated instead by the JSON content-type requirement and CORS.
 *  - **refresh**: the refresh token is itself an unguessable credential in an
 *    httpOnly cookie, and a client whose access token has expired may not have a
 *    current CSRF token either. Chicken and egg.
 *  - **csrf-token**: the endpoint that issues the token cannot require it.
 *  - **health**: monitoring has no cookies.
 */
const EXEMPT_PATHS: readonly RegExp[] = [
  /\/auth\/login$/,
  /\/auth\/refresh$/,
  /\/auth\/register$/,
  /\/security\/csrf-token$/,
  /\/health(\/ready)?$/,
];

function isExempt(path: string): boolean {
  return EXEMPT_PATHS.some((pattern) => pattern.test(path));
}

/**
 * Sign `value`, binding it to a session.
 *
 * The session id makes a token non-transferable: one minted for session A does
 * not verify under session B, which is what closes the sibling-origin
 * cookie-planting hole that plain double-submit leaves open.
 */
function sign(value: string, sessionBinding: string): string {
  return createHmac('sha256', env.jwt.accessSecret)
    .update(`csrf:${value}:${sessionBinding}`)
    .digest('base64url');
}

/**
 * Session identity a token is bound to.
 *
 * The session id when there is one. Before sign-in there is no session, so the
 * token is bound to nothing and is only good for the exempt endpoints - which is
 * exactly right: an unauthenticated request has no state to protect.
 */
function bindingFor(req: Request): string {
  return req.auth?.sessionId ?? 'anonymous';
}

/** Mint a token and set the cookie. Returns the value for the response body. */
export function issueCsrfToken(req: Request, res: Response): string {
  const random = randomBytes(TOKEN_BYTES).toString('base64url');
  const token = `${random}.${sign(random, bindingFor(req))}`;

  res.cookie(COOKIES.CSRF_TOKEN, token, {
    // Readable by script, by design - see the header comment.
    httpOnly: false,
    /**
     * `Secure` would stop the cookie being sent over plain HTTP entirely, which
     * on a LAN deployment means CSRF protection that silently never works. It
     * follows the same rule as the session cookie so the two are consistent.
     */
    secure: env.cookies.secure,
    sameSite: env.cookies.sameSite,
    ...(env.cookies.domain ? { domain: env.cookies.domain } : {}),
    path: '/',
    // Session cookie: it should not outlive the browser session, and a fresh one
    // is issued on every sign-in anyway.
  });

  return token;
}

/** Constant-time comparison that tolerates different lengths. */
function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  // `timingSafeEqual` throws on a length mismatch, which would itself leak the
  // length through the exception path. Compare lengths first, non-secretly.
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Verify a token against its cookie and signature.
 *
 * Three things must hold: the header matches the cookie (classic double
 * submit), the signature verifies (the token was minted by this server), and the
 * binding matches the current session (the token belongs to *this* caller).
 */
function verify(req: Request): boolean {
  const cookies = req.cookies as Record<string, string | undefined> | undefined;
  const cookieToken = cookies?.[COOKIES.CSRF_TOKEN];

  const headerValue = req.get(HEADERS.CSRF_TOKEN);
  const headerToken = typeof headerValue === 'string' ? headerValue : undefined;

  if (!cookieToken || !headerToken) return false;
  if (!safeEqual(cookieToken, headerToken)) return false;

  const separatorAt = cookieToken.lastIndexOf('.');
  if (separatorAt <= 0) return false;

  const random = cookieToken.slice(0, separatorAt);
  const signature = cookieToken.slice(separatorAt + 1);

  return safeEqual(signature, sign(random, bindingFor(req)));
}

/**
 * The middleware.
 *
 * Mounted after authentication so `req.auth.sessionId` is available for the
 * binding check, and after the body parser so the exemption paths are known.
 * Reads the live policy, so an administrator can switch it off to diagnose a
 * client that cannot read the cookie - and the settings page says that is the
 * only good reason to.
 */
/**
 * Does this request authenticate by cookie?
 *
 * CSRF is only possible when the browser attaches credentials *automatically*.
 * A caller that presents a bearer token and sends no session cookie cannot be
 * forged by a cross-origin page: that page would have to read the token, and
 * the same-origin policy stops it.
 *
 * The browser extension is exactly that caller - it sets `credentials: 'omit'`
 * and carries its token explicitly. Demanding a CSRF token from it would break
 * every write it makes while adding no security, because there is no
 * ambient authority to abuse.
 *
 * The check is on the *absence of the refresh cookie*, not on a client-type
 * header alone. A header is caller-controlled; the cookie's absence is a fact
 * about the request. If a cookie is present, the request is treated as
 * cookie-authenticated and must carry a token, whatever it claims to be.
 */
function isBearerOnlyRequest(req: Request): boolean {
  const cookies = req.cookies as Record<string, string | undefined> | undefined;
  const hasSessionCookie = Boolean(cookies?.[COOKIES.REFRESH_TOKEN]);
  if (hasSessionCookie) return false;

  const authorization = req.get('authorization');
  return typeof authorization === 'string' && authorization.startsWith('Bearer ');
}

export function csrfProtection(): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (SAFE_METHODS.has(req.method) || isExempt(req.path)) {
      next();
      return;
    }

    if (isBearerOnlyRequest(req)) {
      next();
      return;
    }

    void securitySettingsService
      .get('csrfEnabled')
      .then((enabled) => {
        if (!enabled) {
          next();
          return;
        }

        if (verify(req)) {
          next();
          return;
        }

        const ip = getClientIp(req);
        logger.warn('CSRF check failed', {
          requestId: req.requestId,
          ip,
          path: req.originalUrl.split('?')[0],
          method: req.method,
          hasCookie: Boolean((req.cookies as Record<string, unknown> | undefined)?.[COOKIES.CSRF_TOKEN]),
          hasHeader: Boolean(req.get(HEADERS.CSRF_TOKEN)),
        });

        // Audited: a burst of these is either an attack or a broken client, and
        // both are worth seeing in the security dashboard. Fire-and-forget so a
        // logging failure cannot turn a rejected request into a 500.
        void auditService
          .recordFailure({
            action: AUDIT_ACTIONS.CSRF_REJECTED,
            actorUserId: req.auth?.userId ?? null,
            sessionId: req.auth?.sessionId ?? null,
            context: req.context,
            isSharedResource: true,
            metadata: {
              path: req.originalUrl.split('?')[0],
              method: req.method,
            },
          })
          .catch(() => undefined);

        next(new CsrfError());
      })
      .catch((error: unknown) => {
        // Policy unreadable. Fail closed: this middleware exists to refuse
        // requests, and defaulting to "allow" on error would make the database
        // being slow into a way to switch the protection off.
        logger.error('Could not read CSRF policy; refusing the request', { error });
        next(new CsrfError());
      });
  };
}

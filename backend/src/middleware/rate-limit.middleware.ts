/**
 * Rate limiting.
 *
 * ## Why several limiters instead of one
 *
 * A single per-IP limiter on `/login` is easy to work around and easy to abuse:
 *
 *  - Keyed by IP alone, an attacker rotates source addresses and slips through.
 *  - Keyed by *email* alone, an attacker can exhaust a colleague's login budget
 *    and lock them out on purpose - the limiter becomes the attack.
 *
 * So `/login` gets two limiters, applied together:
 *
 *  1. {@link loginAccountLimiter} - keyed by (IP, email). Stops password
 *     guessing against one account from one place.
 *  2. {@link loginIpLimiter} - keyed by IP, with a higher budget. Catches
 *     credential *spraying*: one password tried across many accounts, which
 *     limiter 1 never sees because each pair stays under its own threshold.
 *
 * Neither can lock a user out on its own, because the key always includes the
 * caller's IP. Per-account brute force is handled separately by the lockout
 * counter in `auth.service`.
 *
 * ## Storage
 *
 * With Redis enabled, counters are shared across PM2 workers and hosts. With the
 * in-memory fallback each worker counts independently, so the effective limit is
 * roughly `max x workers`. That is stated at boot by `config/cache.ts` and is the
 * main operational reason to run Redis.
 */

import type { RequestHandler } from 'express';
import { rateLimit, type Options, type RateLimitRequestHandler } from 'express-rate-limit';
import RedisStore, { type RedisReply } from 'rate-limit-redis';

import type { SecuritySettings } from '@passm/shared';

import { env } from '../config/env';
import { getRedisClient } from '../config/cache';
import { logger } from '../config/logger';
import { TooManyRequestsError } from '../utils/errors';
import { getClientIp } from '../utils/request-context';
import { sha256Hex } from '../services/crypto.service';
import { securitySettingsService } from '../services/security-settings.service';

/**
 * Redis-backed store, or `undefined` to use the library's memory store.
 *
 * A separate `passm:rl:` prefix keeps limiter keys out of the way of the
 * application cache, so flushing one never disturbs the other.
 */
function buildStore(): Options['store'] | undefined {
  const client = getRedisClient();
  if (!client) return undefined;

  return new RedisStore({
    prefix: 'rl:',
    // rate-limit-redis issues raw Redis commands; ioredis exposes `call` for
    // that. The command name is split from its arguments because ioredis types
    // `call` as (command, ...args) rather than a single spread.
    sendCommand: (command: string, ...args: string[]) =>
      client.call(command, ...args) as Promise<RedisReply>,
  });
}

/** Shared options. */
function baseOptions(windowMs: number, limit: number): Partial<Options> {
  return {
    windowMs,
    limit,
    // `draft-7` sends the standard `RateLimit` / `RateLimit-Policy` headers.
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store: buildStore(),

    /**
     * Route the rejection through the normal error pipeline so the client gets
     * the same envelope as every other error, with a `Retry-After` header.
     */
    handler: (req, res, next, options) => {
      const retryAfterSeconds = Math.ceil(options.windowMs / 1000);

      logger.warn('Rate limit exceeded', {
        requestId: req.requestId,
        ip: getClientIp(req),
        path: req.originalUrl.split('?')[0],
        limit: options.limit,
      });

      next(new TooManyRequestsError(retryAfterSeconds));
    },

    /**
     * Health checks must stay reachable even while a limiter is saturated,
     * otherwise an orchestrator kills a pod that is merely under attack.
     *
     * Matched with `endsWith` because the global limiter is mounted at the app
     * root, where `req.path` is the full `/api/v1/health` rather than the
     * router-relative `/health`.
     */
    skip: (req) => req.path.endsWith('/health') || req.path.endsWith('/health/ready'),
  };
}

/** Normalised IP key. Reused so every limiter derives keys identically. */
function ipKey(req: Parameters<NonNullable<Options['keyGenerator']>>[0]): string {
  return getClientIp(req);
}

// ---------------------------------------------------------------------------
// Runtime-configurable limiters
// ---------------------------------------------------------------------------

/**
 * A limiter whose window and budget come from the live security policy.
 *
 * `express-rate-limit` fixes `windowMs` when the handler is built, so a
 * genuinely configurable window means rebuilding the handler when the setting
 * changes. This wrapper does that: it keeps the current handler, and swaps it
 * when the policy it was built from no longer matches.
 *
 * Without this, the rate-limit controls on the settings page would be
 * decorative - saved, displayed, and ignored until someone restarted the
 * process. A switch that does nothing is worse than no switch.
 *
 * The rebuild discards in-flight counters for that limiter, which is acceptable:
 * changing a rate limit is a deliberate administrative act, and the alternative
 * (never applying it) is worse.
 */
function policyLimiter(
  resolve: (settings: SecuritySettings) => { windowMs: number; limit: number },
  keyGenerator: NonNullable<Options['keyGenerator']>,
  extra: Partial<Options> = {},
): RequestHandler {
  let current: RateLimitRequestHandler | null = null;
  let signature = '';

  const build = (windowMs: number, limit: number): RateLimitRequestHandler =>
    rateLimit({ ...baseOptions(windowMs, limit), keyGenerator, ...extra });

  return (req, res, next) => {
    void securitySettingsService
      .getSettings()
      .then((settings) => {
        const { windowMs, limit } = resolve(settings);
        const nextSignature = `${windowMs}:${limit}`;

        if (!current || signature !== nextSignature) {
          current = build(windowMs, limit);
          signature = nextSignature;
        }

        current(req, res, next);
      })
      .catch((error: unknown) => {
        // Policy unreadable: fall back to the environment-configured limiter
        // rather than letting every request through unmetered.
        logger.warn('Could not read the rate-limit policy; using the boot values', { error });
        if (!current) {
          current = build(env.rateLimit.global.windowMs, env.rateLimit.global.max);
          signature = 'fallback';
        }
        current(req, res, next);
      });
  };
}

// ---------------------------------------------------------------------------
// Limiters
// ---------------------------------------------------------------------------

/** Blanket limiter for the whole API, governed by live policy. */
export const globalLimiter: RequestHandler = policyLimiter(
  (settings) => ({
    windowMs: settings.rateLimitWindowMinutes * 60_000,
    limit: settings.rateLimitGlobalMax,
  }),
  ipKey,
);

/**
 * Per (IP, email) login limiter.
 *
 * The email is hashed before it becomes a cache key: keys land in Redis and in
 * log lines on error paths, and a corporate address is personal data.
 * `skipSuccessfulRequests` means a user who signs in correctly never burns
 * budget - only failures count.
 */
export const loginAccountLimiter: RequestHandler = policyLimiter(
  (settings) => ({
    windowMs: settings.rateLimitWindowMinutes * 60_000,
    limit: settings.rateLimitLoginMax,
  }),
  (req) => {
    const body = req.body as { email?: unknown } | undefined;
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : 'anonymous';
    return `login:${ipKey(req)}:${sha256Hex(email).slice(0, 32)}`;
  },
  // Only failures count, so a user who signs in correctly never burns budget.
  { skipSuccessfulRequests: true },
);

/**
 * Per-IP login limiter with a wider budget, to catch credential spraying across
 * many accounts from one source.
 */
export const loginIpLimiter: RequestHandler = policyLimiter(
  (settings) => ({
    windowMs: settings.rateLimitWindowMinutes * 60_000,
    // Three times the per-account budget: this catches spraying across many
    // accounts, which the per-account limiter never sees.
    limit: settings.rateLimitLoginMax * 3,
  }),
  (req) => `login-ip:${ipKey(req)}`,
  { skipSuccessfulRequests: true },
);

/**
 * Refresh limiter.
 *
 * Deliberately generous: a legitimate client refreshes once per access-token
 * lifetime per tab, and several open tabs multiply that. Too tight a limit here
 * signs real users out.
 */
export const refreshLimiter: RateLimitRequestHandler = rateLimit({
  ...baseOptions(env.rateLimit.refresh.windowMs, env.rateLimit.refresh.max),
  keyGenerator: (req) => `refresh:${ipKey(req)}`,
});

/**
 * Tight limiter for privileged and expensive operations: provisioning, password
 * change, admin password reset. Argon2id/bcrypt make these CPU-heavy, so this is
 * as much a resource guard as an abuse guard.
 */
export const sensitiveOperationLimiter: RateLimitRequestHandler = rateLimit({
  ...baseOptions(env.rateLimit.sensitive.windowMs, env.rateLimit.sensitive.max),
  keyGenerator: (req) => `sensitive:${ipKey(req)}:${req.auth?.userId ?? 'anonymous'}`,
});

/**
 * Configuration changes: security settings and IP rules.
 *
 * Deliberately separate from {@link sensitiveOperationLimiter}, and more
 * generous. These are privileged but cheap - no password hashing - and an
 * administrator working through a settings page with sixty switches will
 * legitimately make dozens of writes in a few minutes. Sharing a 20-request
 * budget with password resets meant configuring the product exhausted the
 * limiter that protects credentials, which is exactly backwards.
 */
export const configurationLimiter: RateLimitRequestHandler = rateLimit({
  ...baseOptions(15 * 60_000, 120),
  keyGenerator: (req) => `config:${ipKey(req)}:${req.auth?.userId ?? 'anonymous'}`,
});

/**
 * Step-up verification.
 *
 * Its own budget because the per-challenge attempt cap already stops guessing
 * against one nonce; this stops an attacker cycling through fresh challenges to
 * get unlimited attempts overall. Generous enough that a user who mistypes their
 * master password a few times across a session is not locked out of confirming
 * anything for fifteen minutes.
 */
export const stepUpLimiter: RateLimitRequestHandler = rateLimit({
  ...baseOptions(15 * 60_000, 40),
  keyGenerator: (req) => `stepup:${ipKey(req)}:${req.auth?.userId ?? 'anonymous'}`,
});

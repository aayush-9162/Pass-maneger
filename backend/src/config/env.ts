/**
 * Environment configuration.
 *
 * Everything the app reads from `process.env` is validated exactly once, here,
 * at import time. A misconfigured deployment fails at boot with a readable
 * report instead of throwing a confusing runtime error under load.
 *
 * Rule: no other module may touch `process.env` directly.
 */

import fs from 'node:fs';
import path from 'node:path';

import dotenv from 'dotenv';
import { z } from 'zod';

import { parseDurationToSeconds } from '../utils/duration';

// ---------------------------------------------------------------------------
// Load .env (never overrides variables already present in the real environment,
// so container/secret-manager values always win over the file).
// ---------------------------------------------------------------------------
dotenv.config({ path: path.resolve(process.cwd(), '.env'), override: false });

// ---------------------------------------------------------------------------
// Coercion helpers
// ---------------------------------------------------------------------------

/** `"true" | "1" | "yes"` -> true. Anything else (including empty) -> false. */
const zBool = (defaultValue: boolean) =>
  z
    .string()
    .optional()
    .transform((value) => {
      if (value === undefined || value.trim() === '') return defaultValue;
      return ['true', '1', 'yes', 'on'].includes(value.trim().toLowerCase());
    });

const zInt = (defaultValue: number, min: number, max: number) =>
  z
    .string()
    .optional()
    .transform((value, ctx) => {
      if (value === undefined || value.trim() === '') return defaultValue;
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `must be an integer between ${min} and ${max}`,
        });
        return z.NEVER;
      }
      return parsed;
    });

/** Duration string, validated eagerly so a typo cannot reach production. */
const zDuration = (defaultValue: string) =>
  z
    .string()
    .optional()
    .transform((value, ctx) => {
      const candidate = value === undefined || value.trim() === '' ? defaultValue : value.trim();
      try {
        parseDurationToSeconds(candidate);
        return candidate;
      } catch (error) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: error instanceof Error ? error.message : 'invalid duration',
        });
        return z.NEVER;
      }
    });

/** Non-empty string with a default. */
const zStr = (defaultValue: string) =>
  z
    .string()
    .optional()
    .transform((value) => (value === undefined || value.trim() === '' ? defaultValue : value.trim()));

/** Optional string that normalises empty-string to `undefined`. */
const zOptionalStr = z
  .string()
  .optional()
  .transform((value) => {
    const trimmed = value?.trim();
    return trimmed === undefined || trimmed === '' ? undefined : trimmed;
  });

/**
 * True when an origin is safe to trust without TLS.
 *
 * A LAN deployment reached by IP cannot get a public CA certificate, so plain
 * HTTP has to remain *possible* - but only to a private address. Allowing
 * `http://` to a routable public host would mean credentials crossing the open
 * internet in cleartext, which is never acceptable for this application.
 *
 * Covers loopback, RFC 1918, link-local, CGNAT and the conventional internal
 * suffixes.
 */
function isPrivateOrigin(origin: string): boolean {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }

  // TLS is acceptable regardless of where the host lives.
  if (url.protocol === 'https:') return true;

  const host = url.hostname.toLowerCase();

  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]') {
    return true;
  }
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.lan')) {
    return true;
  }

  // `192.168.4.103.nip.io` (or sslip.io, dotted or dashed): wildcard DNS that
  // answers with the address written in the name, so it is exactly as private
  // as that address.
  const embedded = /^(?:.*[.-])?(\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3})\.(?:nip|sslip)\.io$/.exec(host);
  const address = embedded?.[1] ? embedded[1].replace(/-/g, '.') : host;

  const octets = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (!octets) return false;

  const first = Number(octets[1]);
  const second = Number(octets[2]);

  if (first === 10) return true; // 10.0.0.0/8
  if (first === 127) return true; // loopback
  if (first === 192 && second === 168) return true; // 192.168.0.0/16
  if (first === 172 && second >= 16 && second <= 31) return true; // 172.16.0.0/12
  if (first === 169 && second === 254) return true; // link-local
  if (first === 100 && second >= 64 && second <= 127) return true; // CGNAT

  return false;
}

/** Comma separated list -> deduplicated array of trimmed, non-empty entries. */
const zCsv = z
  .string()
  .optional()
  .transform((value) =>
    Array.from(
      new Set(
        (value ?? '')
          .split(',')
          .map((entry) => entry.trim())
          .filter((entry) => entry.length > 0),
      ),
    ),
  );

/** 32-byte key, base64 encoded. Enforced strictly - AES-256 needs exactly 256 bits. */
const zBase64Key32 = z
  .string()
  .optional()
  .transform((value, ctx) => {
    const raw = value?.trim();
    if (raw === undefined || raw === '') return undefined;
    let decoded: Buffer;
    try {
      decoded = Buffer.from(raw, 'base64');
    } catch {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'must be valid base64' });
      return z.NEVER;
    }
    if (decoded.length !== 32) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `must decode to exactly 32 bytes (got ${decoded.length}); generate one with \`npm run generate:secrets\``,
      });
      return z.NEVER;
    }
    return raw;
  });

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const MIN_SECRET_LENGTH = 32;

const secretSchema = z
  .string({ required_error: 'is required' })
  .min(MIN_SECRET_LENGTH, `must be at least ${MIN_SECRET_LENGTH} characters`);

const envSchema = z
  .object({
    // --- Application -------------------------------------------------------
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    APP_NAME: zStr('PassM'),
    PORT: zInt(4000, 1, 65535),
    HOST: zStr('0.0.0.0'),
    TRUST_PROXY_HOPS: zInt(0, 0, 10),

    // --- Logging -----------------------------------------------------------
    LOG_LEVEL: z.enum(['error', 'warn', 'info', 'http', 'debug']).default('info'),
    LOG_TO_FILE: zBool(false),
    LOG_DIR: zStr('logs'),

    // --- MySQL -------------------------------------------------------------
    DB_HOST: zStr('127.0.0.1'),
    DB_PORT: zInt(3306, 1, 65535),
    DB_USER: z.string({ required_error: 'is required' }).min(1, 'is required'),
    DB_PASSWORD: z.string().default(''),
    DB_NAME: z.string({ required_error: 'is required' }).min(1, 'is required'),
    DB_CONNECTION_LIMIT: zInt(10, 1, 200),
    DB_QUEUE_LIMIT: zInt(0, 0, 10000),
    DB_CONNECT_TIMEOUT_MS: zInt(10_000, 1000, 60_000),
    DB_SSL: zBool(false),
    DB_SSL_CA: zOptionalStr,
    DB_SSL_REJECT_UNAUTHORIZED: zBool(true),

    // --- Redis -------------------------------------------------------------
    REDIS_ENABLED: zBool(false),
    REDIS_URL: zStr('redis://127.0.0.1:6379/0'),
    REDIS_PASSWORD: zOptionalStr,
    REDIS_TLS: zBool(false),
    REDIS_KEY_PREFIX: zStr('passm:'),

    // --- JWT ---------------------------------------------------------------
    JWT_ACCESS_SECRET: secretSchema,
    JWT_REFRESH_SECRET: secretSchema,
    JWT_DEVICE_TRUST_SECRET: secretSchema,
    JWT_ISSUER: zStr('passm.internal'),
    JWT_AUDIENCE: zStr('passm.clients'),
    // The access token stays short: it is a bearer credential sent on every
    // request, and the refresh alarm renews it silently, so a long one buys
    // nothing. How long a *sign-in* lasts is REFRESH_TOKEN_TTL below.
    ACCESS_TOKEN_TTL: zDuration('15m'),
    // Six months. Deliberate: PassM is a LAN tool where re-authenticating
    // means retyping the password that derives the vault key, so a short
    // refresh window is felt on every device rather than just at the console.
    // Expiry slides on each rotation, so an active device never hits it.
    REFRESH_TOKEN_TTL: zDuration('90d'),
    DEVICE_TRUST_TTL: zDuration('180d'),

    // --- Encryption at rest ------------------------------------------------
    ENCRYPTION_KEY: zBase64Key32,
    ENCRYPTION_KEY_ID: zStr('k1'),
    ENCRYPTION_KEY_PREVIOUS: zBase64Key32,
    ENCRYPTION_KEY_PREVIOUS_ID: zStr('k0'),

    // --- Session & lockout policy -----------------------------------------
    // Default matches REFRESH_TOKEN_TTL (180 days) so one knob, not two, decides
    // how long a sign-in lasts. The ceiling is a year: past that the value is
    // indistinguishable from "never expires", which should be an explicit
    // decision rather than something reached by typing a large number.
    SESSION_IDLE_TIMEOUT_MINUTES: zInt(259_200, 5, 525_600),
    MAX_ACTIVE_SESSIONS_PER_USER: zInt(10, 1, 100),
    MAX_DEVICES_PER_USER: zInt(10, 1, 100),

    // --- Google sign-in -----------------------------------------------------
    GOOGLE_CLIENT_ID: zOptionalStr,
    GOOGLE_ALLOWED_DOMAINS: zCsv,

    // --- CORS / cookies ----------------------------------------------------
    CORS_ORIGINS: zCsv,
    CORS_ALLOW_EXTENSION_ORIGINS: zCsv,
    COOKIE_DOMAIN: zOptionalStr,
    COOKIE_SECURE: zBool(false),
    COOKIE_SAMESITE: z.enum(['lax', 'strict', 'none']).default('lax'),

    // --- Rate limiting -----------------------------------------------------
    RATE_LIMIT_WINDOW_MINUTES: zInt(15, 1, 1440),
    RATE_LIMIT_MAX: zInt(300, 10, 100_000),
    LOGIN_RATE_LIMIT_WINDOW_MINUTES: zInt(15, 1, 1440),
    LOGIN_RATE_LIMIT_MAX: zInt(10, 3, 1000),
    REFRESH_RATE_LIMIT_WINDOW_MINUTES: zInt(15, 1, 1440),
    REFRESH_RATE_LIMIT_MAX: zInt(60, 5, 10_000),
    /*
     * Privileged, CPU-heavy operations: provisioning, admin password reset.
     * Was a hard-coded 20 - right for production, but it makes a test suite that
     * provisions several users unable to run twice. Configurable now, with that
     * same default.
     */
    SENSITIVE_RATE_LIMIT_MAX: zInt(20, 1, 10_000),

    // --- HTTP / HTTPS ------------------------------------------------------
    /**
     * Encrypted vault payloads are the largest bodies this API accepts - a
     * secure note plus base64 expansion can legitimately reach a few hundred
     * kilobytes. Per-field caps in the vault DTOs do the precise limiting; this
     * is the coarse ceiling that stops an unbounded body reaching the parser.
     */
    BODY_LIMIT: zStr('512kb'),
    HTTPS_ENABLED: zBool(false),
    TLS_KEY_PATH: zOptionalStr,
    TLS_CERT_PATH: zOptionalStr,
    TLS_CA_PATH: zOptionalStr,
    HSTS_MAX_AGE: zInt(63_072_000, 0, 63_072_000),
    SHUTDOWN_TIMEOUT_MS: zInt(15_000, 1000, 120_000),

    /**
     * Permit plain HTTP in production, for a private LAN deployment.
     *
     * Only honoured when every configured origin is a private address. It also
     * disables Secure cookies and the HTTPS redirect, because both would
     * otherwise make sign-in impossible over HTTP.
     */
    ALLOW_INSECURE_HTTP: zBool(false),

    /**
     * Directory of the exported web console, served by this process.
     *
     * Set it and the console and API share one origin and one port: no CORS, no
     * second server, and cookies work without SameSite gymnastics. Leave it
     * empty to run the console separately (e.g. `next dev`).
     */
    WEB_ROOT: zOptionalStr,
    /**
     * URL path the console is served under, e.g. `/passmadmin` for
     * `http://host:port/passmadmin/`. Must match the path the console was built
     * for (`VITE_BASE_PATH`, same default). `/` serves it at the root.
     */
    WEB_BASE_PATH: z
      .string()
      .default('/passmadmin')
      .transform((value) => `/${value.trim().replace(/^\/+|\/+$/g, '')}`)
      .refine((value) => value === '/' || /^\/[A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*$/.test(value), {
        message: 'must be a plain URL path such as /passmadmin',
      })
      .refine((value) => !value.startsWith('/api'), {
        message: 'must not overlap the API under /api',
      }),
  })
  // -------------------------------------------------------------------------
  // Cross-field rules. These are the checks that actually catch dangerous
  // production misconfigurations.
  // -------------------------------------------------------------------------
  .superRefine((cfg, ctx) => {
    const fail = (path: string, message: string) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: [path], message });

    const isProduction = cfg.NODE_ENV === 'production';

    // Distinct signing keys: reusing one secret across token types would let a
    // refresh token be replayed as an access token.
    const secrets = {
      JWT_ACCESS_SECRET: cfg.JWT_ACCESS_SECRET,
      JWT_REFRESH_SECRET: cfg.JWT_REFRESH_SECRET,
      JWT_DEVICE_TRUST_SECRET: cfg.JWT_DEVICE_TRUST_SECRET,
    };
    const seen = new Map<string, string>();
    for (const [name, value] of Object.entries(secrets)) {
      const previous = seen.get(value);
      if (previous) {
        fail(name, `must differ from ${previous} - each token type needs its own key`);
      }
      seen.set(value, name);
    }

    // AES key is mandatory: MFA secrets and device trust material are encrypted.
    if (!cfg.ENCRYPTION_KEY) {
      fail('ENCRYPTION_KEY', 'is required (32 random bytes, base64) - run `npm run generate:secrets`');
    }
    if (cfg.ENCRYPTION_KEY_PREVIOUS && cfg.ENCRYPTION_KEY_PREVIOUS === cfg.ENCRYPTION_KEY) {
      fail('ENCRYPTION_KEY_PREVIOUS', 'must differ from ENCRYPTION_KEY');
    }
    if (cfg.ENCRYPTION_KEY_ID === cfg.ENCRYPTION_KEY_PREVIOUS_ID) {
      fail('ENCRYPTION_KEY_PREVIOUS_ID', 'must differ from ENCRYPTION_KEY_ID');
    }

    // SameSite=None is only meaningful on a Secure cookie: browsers reject the
    // combination outright, so the user would simply never stay signed in.
    if (cfg.COOKIE_SAMESITE === 'none' && !cfg.COOKIE_SECURE) {
      fail(
        'COOKIE_SAMESITE',
        '"none" requires COOKIE_SECURE=true (browsers discard SameSite=None cookies sent without Secure). ' +
          'If the console and API share one origin, use "lax" instead.',
      );
    }

    // A configured web root must actually exist, or the console 404s at runtime.
    if (cfg.WEB_ROOT && !fs.existsSync(cfg.WEB_ROOT)) {
      fail(
        'WEB_ROOT',
        `directory not found: ${cfg.WEB_ROOT}. Build the console first: npm run build --workspace @passm/frontend`,
      );
    }

    // TLS material must be complete and readable if in-process HTTPS is on.
    if (cfg.HTTPS_ENABLED) {
      for (const key of ['TLS_KEY_PATH', 'TLS_CERT_PATH'] as const) {
        const filePath = cfg[key];
        if (!filePath) {
          fail(key, 'is required when HTTPS_ENABLED=true');
          continue;
        }
        if (!fs.existsSync(filePath)) {
          fail(key, `file not found: ${filePath}`);
        }
      }
    }

    if (cfg.DB_SSL && cfg.DB_SSL_CA && !fs.existsSync(cfg.DB_SSL_CA)) {
      fail('DB_SSL_CA', `file not found: ${cfg.DB_SSL_CA}`);
    }

    // --- Production-only hardening ------------------------------------------
    if (!isProduction) return;

    for (const [name, value] of Object.entries(secrets)) {
      if (/replace_with|change_me|example|insecure|password/i.test(value)) {
        fail(name, 'still contains a placeholder value - generate a real secret');
      }
    }

    if (cfg.DB_PASSWORD.length === 0) {
      fail('DB_PASSWORD', 'is required in production');
    }

    // Google is the only way in. Without a client id nobody can sign in at all,
    // and without a domain list any Google account on earth would be given one.
    if (!cfg.GOOGLE_CLIENT_ID) {
      fail('GOOGLE_CLIENT_ID', 'is required in production - it is the only sign-in method');
    }
    if (cfg.GOOGLE_ALLOWED_DOMAINS.length === 0) {
      fail('GOOGLE_ALLOWED_DOMAINS', 'is required in production, e.g. GOOGLE_ALLOWED_DOMAINS=123cfc.com');
    }

    // A same-origin deployment (WEB_ROOT set) legitimately needs no CORS
    // origins at all, because the console is served from this process.
    const needsCorsOrigins =
      !cfg.WEB_ROOT &&
      cfg.CORS_ORIGINS.length === 0 &&
      cfg.CORS_ALLOW_EXTENSION_ORIGINS.length === 0;

    if (needsCorsOrigins) {
      fail(
        'CORS_ORIGINS',
        'must list at least one allowed origin in production, or set WEB_ROOT to serve the console from this process',
      );
    }
    if (cfg.CORS_ORIGINS.some((origin) => origin === '*')) {
      fail('CORS_ORIGINS', 'wildcard "*" is not allowed with credentialed requests');
    }

    // --- Plaintext HTTP -----------------------------------------------------
    // Permitted on a private network, and only when explicitly acknowledged.
    const publicPlaintextOrigins = cfg.CORS_ORIGINS.filter(
      (origin) => origin.startsWith('http://') && !isPrivateOrigin(origin),
    );
    if (publicPlaintextOrigins.length > 0) {
      fail(
        'CORS_ORIGINS',
        `plaintext http:// is only allowed to private LAN addresses; refusing: ${publicPlaintextOrigins.join(', ')}`,
      );
    }

    const privatePlaintextOrigins = cfg.CORS_ORIGINS.filter((origin) =>
      origin.startsWith('http://'),
    );
    if (privatePlaintextOrigins.length > 0 && !cfg.ALLOW_INSECURE_HTTP) {
      fail(
        'ALLOW_INSECURE_HTTP',
        'must be true to serve a plaintext http:// origin in production. ' +
          'Anyone on the same network can then read passwords and tokens in transit - ' +
          'prefer HTTPS (see scripts/generate-lan-cert.sh).',
      );
    }

    // Secure cookies over plain HTTP are never sent by the browser, so the two
    // settings must agree or sign-in silently fails.
    if (cfg.ALLOW_INSECURE_HTTP && cfg.COOKIE_SECURE && !cfg.HTTPS_ENABLED) {
      fail(
        'COOKIE_SECURE',
        'must be false when ALLOW_INSECURE_HTTP=true and TLS is off - a Secure cookie is never sent over http://',
      );
    }

    if (cfg.LOG_LEVEL === 'debug') {
      fail('LOG_LEVEL', 'debug logging is not permitted in production (risk of secret leakage)');
    }
  });

// ---------------------------------------------------------------------------
// Parse & report
// ---------------------------------------------------------------------------

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const report = parsed.error.issues
    .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
    .join('\n');

  // Bypass the logger: it depends on this module, and a config failure must be
  // visible even if logging cannot be constructed.
  process.stderr.write(
    `\n[FATAL] Invalid environment configuration:\n${report}\n\n` +
      `Copy backend/.env.example to backend/.env and populate it.\n\n`,
  );
  process.exit(1);
}

const raw = parsed.data;

/** Cookie `sameSite` values accepted by Express. */
export type SameSiteOption = 'lax' | 'strict' | 'none';

/**
 * Frozen, fully typed configuration object.
 *
 * Derived values (TTLs in seconds, resolved TLS buffers) are computed once here
 * so hot paths never re-parse strings.
 */
export const env = Object.freeze({
  // --- Application ---------------------------------------------------------
  nodeEnv: raw.NODE_ENV,
  isProduction: raw.NODE_ENV === 'production',
  isDevelopment: raw.NODE_ENV === 'development',
  isTest: raw.NODE_ENV === 'test',
  appName: raw.APP_NAME,
  port: raw.PORT,
  host: raw.HOST,
  trustProxyHops: raw.TRUST_PROXY_HOPS,
  shutdownTimeoutMs: raw.SHUTDOWN_TIMEOUT_MS,

  // --- Logging -------------------------------------------------------------
  log: {
    level: raw.LOG_LEVEL,
    toFile: raw.LOG_TO_FILE,
    dir: raw.LOG_DIR,
  },

  // --- MySQL ---------------------------------------------------------------
  db: {
    host: raw.DB_HOST,
    port: raw.DB_PORT,
    user: raw.DB_USER,
    password: raw.DB_PASSWORD,
    database: raw.DB_NAME,
    connectionLimit: raw.DB_CONNECTION_LIMIT,
    queueLimit: raw.DB_QUEUE_LIMIT,
    connectTimeoutMs: raw.DB_CONNECT_TIMEOUT_MS,
    ssl: raw.DB_SSL,
    sslCaPath: raw.DB_SSL_CA,
    sslRejectUnauthorized: raw.DB_SSL_REJECT_UNAUTHORIZED,
  },

  // --- Redis ---------------------------------------------------------------
  redis: {
    enabled: raw.REDIS_ENABLED,
    url: raw.REDIS_URL,
    password: raw.REDIS_PASSWORD,
    tls: raw.REDIS_TLS,
    keyPrefix: raw.REDIS_KEY_PREFIX,
  },

  // --- JWT -----------------------------------------------------------------
  jwt: {
    accessSecret: raw.JWT_ACCESS_SECRET,
    refreshSecret: raw.JWT_REFRESH_SECRET,
    deviceTrustSecret: raw.JWT_DEVICE_TRUST_SECRET,
    issuer: raw.JWT_ISSUER,
    audience: raw.JWT_AUDIENCE,
    accessTtl: raw.ACCESS_TOKEN_TTL,
    refreshTtl: raw.REFRESH_TOKEN_TTL,
    deviceTrustTtl: raw.DEVICE_TRUST_TTL,
    accessTtlSeconds: parseDurationToSeconds(raw.ACCESS_TOKEN_TTL),
    refreshTtlSeconds: parseDurationToSeconds(raw.REFRESH_TOKEN_TTL),
    deviceTrustTtlSeconds: parseDurationToSeconds(raw.DEVICE_TRUST_TTL),
  },

  // --- Crypto --------------------------------------------------------------
  crypto: {
    // Non-null: `superRefine` above rejects a missing ENCRYPTION_KEY.
    encryptionKey: raw.ENCRYPTION_KEY as string,
    encryptionKeyId: raw.ENCRYPTION_KEY_ID,
    previousEncryptionKey: raw.ENCRYPTION_KEY_PREVIOUS,
    previousEncryptionKeyId: raw.ENCRYPTION_KEY_PREVIOUS_ID,
  },

  // --- Security policy -----------------------------------------------------
  security: {
    sessionIdleTimeoutMinutes: raw.SESSION_IDLE_TIMEOUT_MINUTES,
    maxActiveSessionsPerUser: raw.MAX_ACTIVE_SESSIONS_PER_USER,
    maxDevicesPerUser: raw.MAX_DEVICES_PER_USER,
    hstsMaxAge: raw.HSTS_MAX_AGE,
    bodyLimit: raw.BODY_LIMIT,
  },

  // --- Google sign-in ------------------------------------------------------
  google: {
    /** OAuth 2.0 web client id; the `aud` every ID token must carry. */
    clientId: raw.GOOGLE_CLIENT_ID,
    /**
     * Google Workspace domains whose accounts may sign in, lowercased. Empty
     * means any verified Google account - refused at boot in production.
     */
    allowedDomains: raw.GOOGLE_ALLOWED_DOMAINS.map((domain) => domain.toLowerCase()),
  },

  // --- CORS / cookies ------------------------------------------------------
  cors: {
    origins: raw.CORS_ORIGINS,
    extensionOrigins: raw.CORS_ALLOW_EXTENSION_ORIGINS,
  },
  cookies: {
    domain: raw.COOKIE_DOMAIN,
    /**
     * Secure cookies in production, unless plaintext HTTP was explicitly
     * enabled for a private LAN - a Secure cookie is simply never sent over
     * `http://`, so forcing it there would break sign-in rather than harden it.
     */
    secure:
      raw.NODE_ENV === 'production' && !(raw.ALLOW_INSECURE_HTTP && !raw.HTTPS_ENABLED)
        ? true
        : raw.COOKIE_SECURE,
    sameSite: raw.COOKIE_SAMESITE as SameSiteOption,
  },

  /** Plaintext HTTP is permitted (private LAN deployments only). */
  allowInsecureHttp: raw.ALLOW_INSECURE_HTTP,

  /** Absolute path to the exported web console, or undefined to not serve it. */
  webRoot: raw.WEB_ROOT ? path.resolve(raw.WEB_ROOT) : undefined,

  /** Path the console is served under: `/passmadmin`, or `/` for the root. */
  webBasePath: raw.WEB_BASE_PATH,

  // --- Rate limiting -------------------------------------------------------
  rateLimit: {
    global: {
      windowMs: raw.RATE_LIMIT_WINDOW_MINUTES * 60_000,
      max: raw.RATE_LIMIT_MAX,
    },
    login: {
      windowMs: raw.LOGIN_RATE_LIMIT_WINDOW_MINUTES * 60_000,
      max: raw.LOGIN_RATE_LIMIT_MAX,
    },
    refresh: {
      windowMs: raw.REFRESH_RATE_LIMIT_WINDOW_MINUTES * 60_000,
      max: raw.REFRESH_RATE_LIMIT_MAX,
    },
    sensitive: {
      windowMs: 15 * 60_000,
      max: raw.SENSITIVE_RATE_LIMIT_MAX,
    },
  },

  // --- TLS -----------------------------------------------------------------
  tls: {
    enabled: raw.HTTPS_ENABLED,
    keyPath: raw.TLS_KEY_PATH,
    certPath: raw.TLS_CERT_PATH,
    caPath: raw.TLS_CA_PATH,
  },
});

export type Env = typeof env;

/**
 * Structured logging (winston).
 *
 * Two hard rules:
 *  1. Secrets never reach a log sink. The `redact` format strips known
 *     sensitive keys at any depth, so an accidental `logger.info('x', req.body)`
 *     cannot leak a password or token.
 *  2. Production output is single-line JSON, ready for shipping to
 *     CloudWatch/ELK/Loki. Human-friendly colour output is development only.
 */

import fs from 'node:fs';
import path from 'node:path';

import winston from 'winston';

import { env } from './env';

/** Keys whose values are replaced with `[REDACTED]`, matched case-insensitively. */
const SENSITIVE_KEYS = new Set(
  [
    'password',
    'currentpassword',
    'newpassword',
    'confirmpassword',
    'masterpassword',
    'passwordhash',
    'password_hash',
    'token',
    'accesstoken',
    'access_token',
    'refreshtoken',
    'refresh_token',
    'refreshtokenhash',
    'refresh_token_hash',
    'trusttokenhash',
    'trust_token_hash',
    'devicetrusttoken',
    'authorization',
    'cookie',
    'set-cookie',
    'secret',
    'apikey',
    'api_key',
    'privatekey',
    'private_key',
    'encryptionkey',
    'masterkeyverifier',
    'master_key_verifier',
    'masterkeysalt',
    'master_key_salt',
    'mfasecret',
    'mfa_secret',
    'mfa_secret_encrypted',
    'ciphertext',
    'jwt',
  ].map((key) => key.toLowerCase()),
);

const REDACTED = '[REDACTED]';
const MAX_REDACT_DEPTH = 6;

/**
 * Deep-clone `value`, masking sensitive keys.
 *
 * Depth-limited and cycle-safe so a logged Express request (which contains
 * circular socket references) cannot hang or blow the stack.
 */
function redactValue(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (depth > MAX_REDACT_DEPTH) return '[TRUNCATED]';
  if (value === null || typeof value !== 'object') return value;

  if (seen.has(value as object)) return '[CIRCULAR]';
  seen.add(value as object);

  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item) => redactValue(item, depth + 1, seen));
  }

  if (value instanceof Error) {
    return { name: value.name, message: value.message, stack: value.stack };
  }

  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return `[Buffer ${value.length}B]`;

  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    output[key] = SENSITIVE_KEYS.has(key.toLowerCase())
      ? REDACTED
      : redactValue(item, depth + 1, seen);
  }
  return output;
}

/** winston format that applies {@link redactValue} to every log entry's metadata. */
const redact = winston.format((info) => {
  for (const key of Object.keys(info)) {
    if (key === 'level' || key === 'message' || key === 'timestamp' || key === 'stack') continue;
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      (info as Record<string, unknown>)[key] = REDACTED;
      continue;
    }
    (info as Record<string, unknown>)[key] = redactValue(
      (info as Record<string, unknown>)[key],
    );
  }
  return info;
});

/** Compact, aligned output for local development. */
const developmentFormat = winston.format.combine(
  redact(),
  winston.format.timestamp({ format: 'HH:mm:ss.SSS' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ level: true }),
  winston.format.printf((info) => {
    const { timestamp, level, message, stack, requestId, ...meta } = info as Record<
      string,
      unknown
    >;

    const tag = requestId ? ` [${String(requestId).slice(0, 8)}]` : '';
    const extras = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
    const trace = stack ? `\n${String(stack)}` : '';

    return `${String(timestamp)} ${level}${tag}: ${String(message)}${extras}${trace}`;
  }),
);

/** Machine readable output for production log pipelines. */
const productionFormat = winston.format.combine(
  redact(),
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json(),
);

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

const transports: winston.transport[] = [
  new winston.transports.Console({
    // Never let a logging failure crash the process.
    handleExceptions: false,
    handleRejections: false,
  }),
];

if (env.log.toFile) {
  const logDir = path.resolve(process.cwd(), env.log.dir);
  fs.mkdirSync(logDir, { recursive: true });

  // Rotation is delegated to pm2-logrotate / logrotate rather than duplicated here.
  transports.push(
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      maxsize: 20 * 1024 * 1024,
      maxFiles: 10,
      tailable: true,
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      maxsize: 20 * 1024 * 1024,
      maxFiles: 10,
      tailable: true,
    }),
  );
}

/**
 * Application logger.
 *
 * Prefer `req.log` inside request handlers - it carries the request id, user id
 * and route, which makes production incidents traceable.
 */
export const logger = winston.createLogger({
  level: env.log.level,
  levels: winston.config.npm.levels,
  format: env.isProduction ? productionFormat : developmentFormat,
  defaultMeta: {
    service: env.appName,
    env: env.nodeEnv,
    pid: process.pid,
  },
  transports,
  exitOnError: false,
  silent: env.isTest,
});

/** Child logger bound to a fixed set of fields (request id, user id, ...). */
export function createChildLogger(meta: Record<string, unknown>): winston.Logger {
  return logger.child(meta);
}

export type Logger = winston.Logger;

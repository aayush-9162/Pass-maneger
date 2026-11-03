/**
 * MySQL connectivity (mysql2/promise - no ORM).
 *
 * SQL injection defence, by construction:
 *  - `multipleStatements` is disabled at the driver level, so even a successful
 *    injection cannot chain a second statement.
 *  - Every query goes through {@link query}/{@link execute}, which use *prepared
 *    statements* (`connection.execute`). Values are bound by the server, never
 *    interpolated into SQL text.
 *  - Identifiers (table/column names) can't be parameterised, so repositories
 *    must map untrusted sort/filter input through an allow-list. See
 *    `utils/sql.ts#resolveSortColumn`.
 */

import fs from 'node:fs';

import mysql, {
  type Pool,
  type PoolConnection,
  type PoolOptions,
  type ResultSetHeader,
  type RowDataPacket,
} from 'mysql2/promise';

import { env } from './env';
import { logger } from './logger';

/**
 * A value that may be bound to a `?` placeholder.
 *
 * Typing parameters explicitly (rather than `unknown[]`) is a small safety net:
 * accidentally passing an object or a function - which mysql2 would serialise in
 * a way nobody intends - fails to compile.
 */
export type SqlParam = string | number | bigint | boolean | Date | Buffer | null;

/**
 * Anything capable of running a statement: the pool, or a single connection
 * enlisted in a transaction. Repositories accept this so the same method works
 * both inside and outside a transaction.
 *
 * Structurally satisfied by both `Pool` and `PoolConnection`. The result is
 * `unknown` here and narrowed by the helpers below, which keeps this interface
 * free of mysql2's deep internal type paths.
 */
export interface SqlExecutor {
  execute(sql: string, values?: SqlParam[]): Promise<[unknown, unknown]>;
}

function buildPoolOptions(): PoolOptions {
  const options: PoolOptions = {
    host: env.db.host,
    port: env.db.port,
    user: env.db.user,
    password: env.db.password,
    database: env.db.database,

    // --- Pooling -----------------------------------------------------------
    waitForConnections: true,
    connectionLimit: env.db.connectionLimit,
    queueLimit: env.db.queueLimit,
    connectTimeout: env.db.connectTimeoutMs,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10_000,
    maxIdle: env.db.connectionLimit,
    idleTimeout: 60_000,

    // --- Safety ------------------------------------------------------------
    /** Hard block on statement chaining - the single most valuable SQLi guard. */
    multipleStatements: false,
    /** Positional `?` binding only; keeps every call site uniform. */
    namedPlaceholders: false,

    // --- Types -------------------------------------------------------------
    /** Return DATETIME as JS Date; the app normalises to ISO-8601 UTC on output. */
    dateStrings: false,
    timezone: 'Z',
    supportBigNumbers: true,
    bigNumberStrings: false,
    decimalNumbers: true,
    charset: 'utf8mb4_unicode_ci',
  };

  // Prepared-statement cache size (mysql2 option, per connection).
  (options as Record<string, unknown>).maxPreparedStatements = 200;

  if (env.db.ssl) {
    options.ssl = {
      rejectUnauthorized: env.db.sslRejectUnauthorized,
      ...(env.db.sslCaPath ? { ca: fs.readFileSync(env.db.sslCaPath, 'utf8') } : {}),
    };
  }

  return options;
}

let pool: Pool | null = null;

/** Lazily created singleton connection pool. */
export function getPool(): Pool {
  if (pool) return pool;

  pool = mysql.createPool(buildPoolOptions());

  /**
   * Pin every connection's session time zone to UTC.
   *
   * This is load-bearing, not tidiness. The driver is configured with
   * `timezone: 'Z'`, so it encodes JS `Date` values as UTC on the way in and
   * decodes DATETIME columns as UTC on the way out. MySQL's `NOW(3)`, however,
   * returns the *server's* local time - and the schema compares the two
   * constantly (`expires_at > NOW(3)`, `verified_until > CURRENT_TIMESTAMP(3)`).
   *
   * On a server running anything other than UTC those comparisons are wrong by
   * the offset. With the host on IST (+05:30) a five-minute step-up window
   * evaluates as expired the instant it is written, and sessions expire five and
   * a half hours early. Long TTLs hide it; short ones do not.
   *
   * Setting the session zone to UTC makes `NOW(3)`, `CURRENT_TIMESTAMP(3)` and
   * every `DEFAULT CURRENT_TIMESTAMP` column agree with what the driver reads
   * and writes, whatever the host is configured for.
   */
  pool.on('connection', (connection) => {
    /**
     * The `connection` event hands back the *callback-style* connection, even on
     * the promise pool - so this uses the callback form deliberately. Calling
     * `.catch()` on it throws "not a promise" at runtime while typechecking
     * fine, which is exactly the sort of mistake that only shows up at boot.
     */
    const raw = connection as unknown as {
      query(sql: string, callback: (error: unknown) => void): void;
    };

    raw.query("SET time_zone = '+00:00'", (error: unknown) => {
      if (error) {
        logger.error('Could not pin the MySQL session to UTC; time comparisons may be skewed', {
          error,
        });
      }
    });
  });

  logger.info('MySQL pool created', {
    host: env.db.host,
    port: env.db.port,
    database: env.db.database,
    connectionLimit: env.db.connectionLimit,
    ssl: env.db.ssl,
  });

  return pool;
}

/**
 * Run a SELECT and return typed rows.
 *
 * @param sql    Statement with `?` placeholders only.
 * @param params Values bound by the server.
 */
export async function query<T extends RowDataPacket>(
  sql: string,
  params: SqlParam[] = [],
  executor: SqlExecutor = getPool(),
): Promise<T[]> {
  const started = process.hrtime.bigint();
  try {
    const [rows] = await executor.execute(sql, params);
    // The driver returns a union of every possible result shape. Narrowing it
    // here - in the one function that talks to mysql2 - keeps the assertion in a
    // single reviewable place instead of spread across every repository.
    return rows as T[];
  } finally {
    logSlowQuery(sql, started);
  }
}

/** Run a SELECT expected to match at most one row. */
export async function queryOne<T extends RowDataPacket>(
  sql: string,
  params: SqlParam[] = [],
  executor: SqlExecutor = getPool(),
): Promise<T | null> {
  const rows = await query<T>(sql, params, executor);
  return rows[0] ?? null;
}

/** Run an INSERT/UPDATE/DELETE and return the driver result header. */
export async function execute(
  sql: string,
  params: SqlParam[] = [],
  executor: SqlExecutor = getPool(),
): Promise<ResultSetHeader> {
  const started = process.hrtime.bigint();
  try {
    const [result] = await executor.execute(sql, params);
    return result as ResultSetHeader;
  } finally {
    logSlowQuery(sql, started);
  }
}

const SLOW_QUERY_MS = 200;

function logSlowQuery(sql: string, startedAt: bigint): void {
  const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
  if (durationMs < SLOW_QUERY_MS) return;

  // Log the statement shape only - bound values may contain sensitive data.
  logger.warn('Slow SQL query', {
    durationMs: Math.round(durationMs),
    sql: sql.replace(/\s+/g, ' ').trim().slice(0, 300),
  });
}

/**
 * Execute `work` inside a transaction, committing on success and rolling back on
 * any thrown error. The connection is always released.
 *
 * ```ts
 * await withTransaction(async (tx) => {
 *   await userRepository.create(dto, tx);
 *   await auditRepository.insert(entry, tx);
 * });
 * ```
 */
export async function withTransaction<T>(
  work: (connection: PoolConnection) => Promise<T>,
): Promise<T> {
  const connection = await getPool().getConnection();
  try {
    await connection.beginTransaction();
    const result = await work(connection);
    await connection.commit();
    return result;
  } catch (error) {
    try {
      await connection.rollback();
    } catch (rollbackError) {
      logger.error('Transaction rollback failed', { error: rollbackError });
    }
    throw error;
  } finally {
    connection.release();
  }
}

/** Cheap liveness probe used by `/health/ready` and by the boot sequence. */
export async function checkDatabaseHealth(): Promise<{ ok: boolean; latencyMs: number }> {
  const started = Date.now();
  try {
    await getPool().query('SELECT 1');
    return { ok: true, latencyMs: Date.now() - started };
  } catch (error) {
    logger.error('MySQL health check failed', { error });
    return { ok: false, latencyMs: Date.now() - started };
  }
}

/**
 * Verify connectivity at boot. Fails fast so an orchestrator restarts the
 * container instead of serving 500s.
 */
export async function assertDatabaseConnection(): Promise<void> {
  const connection = await getPool().getConnection();
  try {
    const [rows] = await connection.query<RowDataPacket[]>(
      'SELECT VERSION() AS version, DATABASE() AS db',
    );
    const info = rows[0];
    logger.info('MySQL connection verified', {
      version: info?.version,
      database: info?.db,
    });
  } finally {
    connection.release();
  }
}

/** Close the pool during graceful shutdown. Idempotent. */
export async function closePool(): Promise<void> {
  if (!pool) return;
  const closing = pool;
  pool = null;
  await closing.end();
  logger.info('MySQL pool closed');
}

export type { Pool, PoolConnection, ResultSetHeader, RowDataPacket };

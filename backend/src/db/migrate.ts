/**
 * Migration runner.  `npm run db:migrate`
 *
 * Applies every `db/migrations/*.sql` file in filename order exactly once and
 * records it in `schema_migrations` together with a SHA-256 checksum, so an
 * already-applied file that gets edited is reported instead of silently skipped.
 *
 * Privileges: the application account intentionally has no DDL rights. Set
 * MIGRATION_DB_USER / MIGRATION_DB_PASSWORD to run migrations under a separate
 * account that does. (Reading those two directly from `process.env` is the one
 * sanctioned exception to the "config lives in env.ts" rule - this is a CLI
 * tool, not part of the served application.)
 *
 * MySQL performs an implicit commit on DDL, so migrations are not wrapped in a
 * transaction. Keep each file independently re-runnable where practical.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

import mysql, { type RowDataPacket } from 'mysql2/promise';

import { env } from '../config/env';
import { logger } from '../config/logger';

const MIGRATIONS_DIR = path.resolve(process.cwd(), 'db', 'migrations');

interface AppliedMigrationRow extends RowDataPacket {
  id: string;
  checksum: string;
}

/** Bootstrap table that tracks which migrations have run. */
const CREATE_TRACKING_TABLE = `
  CREATE TABLE IF NOT EXISTS schema_migrations (
    id          VARCHAR(255) NOT NULL,
    checksum    CHAR(64) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    applied_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    duration_ms INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id)
  ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci
`;

function sha256(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

async function main(): Promise<void> {
  const files = (await fs.readdir(MIGRATIONS_DIR))
    .filter((name) => name.endsWith('.sql'))
    .sort((a, b) => a.localeCompare(b, 'en'));

  if (files.length === 0) {
    logger.warn('No migration files found', { dir: MIGRATIONS_DIR });
    return;
  }

  const connection = await mysql.createConnection({
    host: env.db.host,
    port: env.db.port,
    user: process.env.MIGRATION_DB_USER || env.db.user,
    password: process.env.MIGRATION_DB_PASSWORD ?? env.db.password,
    database: env.db.database,
    // Required to execute a multi-statement .sql file. Safe here: the input is
    // a developer-authored file on disk, never request data. The application
    // pool keeps this disabled (see config/database.ts).
    multipleStatements: true,
    connectTimeout: env.db.connectTimeoutMs,
  });

  try {
    await connection.query(CREATE_TRACKING_TABLE);

    const [appliedRows] = await connection.query<AppliedMigrationRow[]>(
      'SELECT id, checksum FROM schema_migrations',
    );
    const applied = new Map(appliedRows.map((row) => [row.id, row.checksum]));

    let executed = 0;

    for (const file of files) {
      const sql = await fs.readFile(path.join(MIGRATIONS_DIR, file), 'utf8');
      const checksum = sha256(sql);
      const previousChecksum = applied.get(file);

      if (previousChecksum !== undefined) {
        if (previousChecksum !== checksum) {
          throw new Error(
            `Migration "${file}" was modified after it was applied ` +
              `(stored ${previousChecksum.slice(0, 12)}..., current ${checksum.slice(0, 12)}...). ` +
              'Add a new migration instead of editing an applied one.',
          );
        }
        logger.debug('Migration already applied, skipping', { file });
        continue;
      }

      logger.info('Applying migration', { file });
      const startedAt = Date.now();
      await connection.query(sql);
      const durationMs = Date.now() - startedAt;

      await connection.execute(
        'INSERT INTO schema_migrations (id, checksum, duration_ms) VALUES (?, ?, ?)',
        [file, checksum, durationMs],
      );

      executed += 1;
      logger.info('Migration applied', { file, durationMs });
    }

    logger.info('Migrations complete', {
      applied: executed,
      alreadyApplied: files.length - executed,
      total: files.length,
    });
  } finally {
    await connection.end();
  }
}

main()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    logger.error('Migration failed', { error });
    process.exit(1);
  });

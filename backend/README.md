# PassM API

Express + TypeScript + MySQL (`mysql2`, no ORM).

See the [root README](../README.md) for setup, the endpoint table and the
security rationale. This file covers the parts specific to working *in* the
backend.

---

## Layout

```
src/
  config/        env validation, logger, MySQL pool, cache — the only modules that read process.env
  types/         Express augmentation, AuthContext
  models/        row shapes + mappers to domain records
  dto/           zod request schemas (validation happens here, once)
  repositories/  the only code that writes SQL
  services/      business rules and security policy
  middleware/    correlation, security headers, rate limits, validation, auth, errors
  controllers/   HTTP translation only
  routes/        middleware chains and permission declarations
  db/            migration runner and seeder
  scripts/       operational CLI tools
  app.ts         Express assembly
  server.ts      dependency checks, listener, graceful shutdown
db/migrations/   .sql files, applied in filename order
```

Dependencies point one way: `routes -> controllers -> services -> repositories`.
A service never imports a controller, and only repositories contain SQL.

---

## Conventions

**Configuration.** Only `config/env.ts` reads `process.env`. It validates
everything at import time and exits with a readable report on failure, so a
misconfigured deployment dies at boot instead of mid-request. The two exceptions
are CLI scripts (`db/migrate.ts`, `db/seed.ts`), which read their own operational
variables directly and say so in a comment.

**SQL.** Values are always bound with `?`. Identifiers cannot be parameterised,
so sort columns go through `resolveSortColumn` and an explicit allow-list.
`multipleStatements` is off at the driver level.

**Errors.** Throw an `AppError` subclass; the central handler turns it into the
response envelope. Anything else is treated as a bug: logged in full, reported as
a generic 500.

**Async handlers.** Wrap every async route in `asyncHandler`, otherwise Express 4
leaves the rejection unhandled and the request hangs.

**Validation.** Every route with input declares a zod schema in `dto/` and mounts
`validate(...)`. The parsed result replaces the raw input, so a service can never
receive an unvalidated field. Schemas are `.strict()`, so unknown keys are
rejected rather than ignored — which is what blocks mass assignment.

**Logging.** Use `req.log` inside handlers; it carries the request id, user id and
route. Sensitive keys are redacted at any depth by the logger's format, but do not
rely on that — avoid logging request bodies at all.

---

## Adding an endpoint

1. `dto/` — a zod schema for the input.
2. `repositories/` — SQL, if new queries are needed.
3. `services/` — the rule. This is where authorization guardrails belong.
4. `controllers/` — translate HTTP to the service call.
5. `routes/` — mount with `validate(...)` and `requirePermission(...)`.
6. `shared/` — add the permission to the matrix if it is a new capability.

---

## Migrations

```bash
npm run db:migrate
```

Files are applied in filename order and recorded in `schema_migrations` with a
SHA-256 checksum. Editing an applied migration is reported as an error rather
than silently skipped — add a new file instead.

MySQL commits DDL implicitly, so migrations are not transactional. Keep each file
independently re-runnable where practical.

Run under an account with DDL rights:

```bash
MIGRATION_DB_USER=passm_migrator MIGRATION_DB_PASSWORD=… npm run db:migrate
```

---

## Operational scripts

| Command | Purpose |
| --- | --- |
| `npm run generate:secrets` | Print fresh JWT secrets and an AES key for `.env` |
| `npm run db:migrate` | Apply pending migrations |
| `npm run db:seed` | Create the bootstrap administrator (idempotent) |

---

## Background maintenance

`services/maintenance.service.ts` runs every 15 minutes: it expires stale
sessions and device-trust grants and prunes `login_attempts` and terminated
sessions.

None of it is load-bearing for security — expiry is enforced at request time by
comparing timestamps, not by these status updates. Every statement is idempotent
and `LIMIT`-bounded, so the duplicate passes a PM2 cluster produces are harmless.

---

## Graceful shutdown

On `SIGTERM` the server stops accepting connections, drains in-flight requests,
then closes the MySQL pool and cache, with a hard timeout backstop
(`SHUTDOWN_TIMEOUT_MS`). PM2's `kill_timeout` must stay above it.

`process.send('ready')` pairs with `wait_ready: true` in `ecosystem.config.js`,
so `pm2 reload` only routes traffic to a worker that has verified its
dependencies.

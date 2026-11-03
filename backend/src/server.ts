/**
 * Process entry point: dependency checks, listener, graceful shutdown.
 *
 * ## Boot order
 *
 * MySQL connectivity is verified *before* the port opens. Failing fast means an
 * orchestrator replaces a broken instance, instead of a half-working process
 * answering health checks and serving 500s to real users.
 *
 * ## Graceful shutdown
 *
 * On SIGTERM the server stops accepting connections, lets in-flight requests
 * finish, then closes the MySQL pool and the cache. This matters here in
 * particular: a login interrupted mid-transaction could otherwise leave a session
 * row without its audit entry. A hard timeout guarantees the process exits even
 * if a connection refuses to drain.
 *
 * ## PM2
 *
 * `process.send('ready')` pairs with `wait_ready: true` in ecosystem.config.js,
 * so `pm2 reload` only routes traffic to a worker that has actually verified its
 * dependencies - which is what makes a zero-downtime reload real rather than
 * nominal.
 */

import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';

import { getCache, closeCache } from './config/cache';
import { assertDatabaseConnection, closePool } from './config/database';
import { env } from './config/env';
import { logger } from './config/logger';
import { createApp } from './app';
import { installProcessErrorHandlers } from './middleware/error.middleware';
import { roleRepository } from './repositories/role.repository';
import { maintenanceService } from './services/maintenance.service';

/** Build an HTTPS server when TLS material is configured, otherwise plain HTTP. */
function createServer(app: ReturnType<typeof createApp>): http.Server | https.Server {
  if (!env.tls.enabled) {
    return http.createServer(app);
  }

  // Paths were validated at config load; a read failure here is fatal by design.
  const options: https.ServerOptions = {
    key: fs.readFileSync(env.tls.keyPath as string),
    cert: fs.readFileSync(env.tls.certPath as string),
    ...(env.tls.caPath ? { ca: fs.readFileSync(env.tls.caPath) } : {}),
    // TLS 1.2 is the floor: everything below has known weaknesses and no modern
    // client needs it.
    minVersion: 'TLSv1.2',
    honorCipherOrder: true,
  };

  logger.info('TLS enabled: terminating HTTPS in-process');
  return https.createServer(options, app);
}

let shuttingDown = false;

/**
 * State the effective transport security at boot, in one unmissable place.
 *
 * A deployment that is accidentally serving credentials in cleartext should not
 * be something an operator has to infer from a config file - especially on a LAN,
 * where "it works" and "it is safe" look identical from the browser.
 */
function reportSecurityPosture(): void {
  const tlsInProcess = env.tls.enabled;
  const tlsAtProxy = !tlsInProcess && env.trustProxyHops > 0 && !env.allowInsecureHttp;

  if (tlsInProcess || tlsAtProxy) {
    logger.info('Transport security: HTTPS', {
      terminatedBy: tlsInProcess ? 'this process' : 'reverse proxy',
      secureCookies: env.cookies.secure,
      sameSite: env.cookies.sameSite,
    });
    return;
  }

  if (env.allowInsecureHttp) {
    logger.warn(
      'Transport security: PLAINTEXT HTTP (ALLOW_INSECURE_HTTP=true). ' +
        'Passwords, access tokens and refresh tokens cross the network unencrypted - ' +
        'anyone able to observe this LAN segment can capture them. ' +
        'Acceptable only on a trusted private network; enable TLS with scripts/generate-lan-cert.sh.',
      { secureCookies: env.cookies.secure, sameSite: env.cookies.sameSite },
    );
    return;
  }

  logger.info('Transport security: plaintext HTTP (development)', {
    secureCookies: env.cookies.secure,
  });
}

async function main(): Promise<void> {
  logger.info('Starting API', {
    service: env.appName,
    env: env.nodeEnv,
    node: process.version,
    pid: process.pid,
  });

  reportSecurityPosture();

  // --- Dependency verification, before the port opens ----------------------
  await assertDatabaseConnection();

  // Fails loudly if migration 002 never ran, rather than at the first login.
  await roleRepository.requireIdByName('admin');

  // Constructs the cache and logs which backend is in use.
  getCache();

  const app = createApp();
  const server = createServer(app);

  // Slightly above a typical 60s load-balancer idle timeout, so the balancer
  // closes idle connections first and clients never see a mid-request reset.
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  server.requestTimeout = 30_000;

  /**
   * Drain and exit.
   *
   * Idempotent: a second signal during shutdown is ignored rather than
   * interrupting the drain that is already under way.
   */
  const shutdown = (exitCode: number, signal?: string): void => {
    if (shuttingDown) {
      logger.warn('Shutdown already in progress; ignoring repeat signal', { signal });
      return;
    }
    shuttingDown = true;

    logger.info('Shutting down', { signal, exitCode });

    // Backstop: exit even if a socket refuses to close.
    const forceExit = setTimeout(() => {
      logger.error('Graceful shutdown timed out; forcing exit', {
        timeoutMs: env.shutdownTimeoutMs,
      });
      process.exit(exitCode === 0 ? 1 : exitCode);
    }, env.shutdownTimeoutMs);
    forceExit.unref();

    maintenanceService.stop();

    // Stops accepting new connections; the callback fires once in-flight
    // requests have completed.
    server.close(() => {
      void (async () => {
        try {
          await closePool();
          await closeCache();
          logger.info('Shutdown complete');
        } catch (error) {
          logger.error('Error during shutdown', { error });
          process.exit(1);
        } finally {
          clearTimeout(forceExit);
          process.exit(exitCode);
        }
      })();
    });
  };

  installProcessErrorHandlers((code) => shutdown(code, 'fatal-error'));
  process.on('SIGTERM', () => shutdown(0, 'SIGTERM'));
  process.on('SIGINT', () => shutdown(0, 'SIGINT'));

  server.listen(env.port, env.host, () => {
    const scheme = env.tls.enabled ? 'https' : 'http';
    logger.info(`API listening on ${scheme}://${env.host}:${env.port}`, {
      port: env.port,
      trustProxyHops: env.trustProxyHops,
      corsOrigins: env.cors.origins,
    });

    maintenanceService.start();

    // Tell PM2 the worker is genuinely ready (pairs with `wait_ready: true`).
    process.send?.('ready');
  });

  server.on('error', (error: NodeJS.ErrnoException) => {
    if (error.code === 'EADDRINUSE') {
      logger.error(`Port ${env.port} is already in use`, { port: env.port });
    } else {
      logger.error('HTTP server error', { error });
    }
    process.exit(1);
  });
}

main().catch((error: unknown) => {
  logger.error('Fatal error during startup', { error });
  process.exit(1);
});

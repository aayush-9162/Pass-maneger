/**
 * PM2 process definition.
 *
 *   Production:  pm2 start ecosystem.config.js --env production
 *   Reload (0s downtime): pm2 reload passm-api
 *   Logs:        pm2 logs passm-api
 *
 * Notes
 *  - `cluster` mode forks one process per CPU. Because sessions live in MySQL
 *    (and optionally Redis) rather than in process memory, workers are
 *    interchangeable - but you MUST enable Redis for shared rate limiting,
 *    otherwise each worker enforces its own independent counters.
 *  - `kill_timeout` must exceed SHUTDOWN_TIMEOUT_MS so the app can drain
 *    in-flight requests and close the MySQL pool before SIGKILL.
 */
module.exports = {
  apps: [
    {
      name: 'passm-api',
      script: 'dist/server.js',
      cwd: __dirname,

      // --- Clustering --------------------------------------------------------
      // One process unless told otherwise: without Redis each worker keeps its
      // own rate-limit counters and session cache. With REDIS_ENABLED=true, set
      // PM2_INSTANCES=max to use every CPU.
      exec_mode: 'cluster',
      instances: process.env.PM2_INSTANCES || 1,

      // --- Restart policy ----------------------------------------------------
      autorestart: true,
      max_restarts: 10,
      min_uptime: '30s',
      restart_delay: 2000,
      exp_backoff_restart_delay: 250,
      max_memory_restart: '512M',

      // --- Graceful lifecycle ------------------------------------------------
      wait_ready: true, // waits for process.send('ready') from server.ts
      listen_timeout: 15000,
      kill_timeout: 20000, // > SHUTDOWN_TIMEOUT_MS
      shutdown_with_message: false,

      // --- Logging (PM2 handles rotation via pm2-logrotate) ------------------
      time: true,
      merge_logs: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      out_file: 'logs/pm2-out.log',
      error_file: 'logs/pm2-error.log',

      // --- Environments ------------------------------------------------------
      env: {
        NODE_ENV: 'development',
      },
      env_production: {
        NODE_ENV: 'production',
        // Real secrets come from the deployment environment / secret manager,
        // never from this file.
      },

      // Do not watch files in production.
      watch: false,
    },
  ],
};

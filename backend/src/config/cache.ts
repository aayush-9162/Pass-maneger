/**
 * Cache / session-state layer.
 *
 * Redis is optional (per the spec). The app therefore programs against the
 * {@link CacheStore} interface and picks a backend at boot:
 *
 *  - `REDIS_ENABLED=true`  -> Redis (shared across PM2 workers and hosts)
 *  - otherwise             -> in-process Map with TTL sweeping
 *
 * The in-memory store is functionally correct but *per process*. In a PM2
 * cluster that means each worker keeps its own copy, so rate-limit counters are
 * effectively multiplied by the worker count. That trade-off is logged at boot;
 * enable Redis for any multi-instance deployment.
 *
 * The cache is never authoritative: MySQL holds the truth for sessions and
 * devices. A cold or unavailable cache costs latency, never correctness.
 */

import Redis, { type RedisOptions } from 'ioredis';

import { env } from './env';
import { logger } from './logger';

export interface CacheStore {
  /** Backend kind, surfaced on the health endpoint. */
  readonly kind: 'redis' | 'memory';
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttlSeconds: number): Promise<void>;
  del(...keys: string[]): Promise<void>;
  /** Delete every key starting with `prefix` (e.g. all sessions of one user). */
  delByPrefix(prefix: string): Promise<void>;
  /** Atomic counter with expiry-on-create. Returns the new value. */
  incr(key: string, ttlSeconds: number): Promise<number>;
  /** True when the key exists and has not expired. */
  has(key: string): Promise<boolean>;
  close(): Promise<void>;
}

/** Namespaced cache key builders - keeps key formats in one place. */
export const CACHE_KEYS = {
  session: (sessionId: string) => `session:${sessionId}`,
  sessionActivity: (sessionId: string) => `session:activity:${sessionId}`,
  userSessions: (userId: string) => `user:${userId}:sessions:`,
  userSession: (userId: string, sessionId: string) => `user:${userId}:sessions:${sessionId}`,
  revokedSession: (sessionId: string) => `revoked:session:${sessionId}`,
  user: (userId: string) => `user:${userId}`,
  loginAttempts: (email: string) => `login:attempts:${email}`,
} as const;

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

interface MemoryEntry {
  value: unknown;
  expiresAtMs: number;
}

class MemoryCacheStore implements CacheStore {
  readonly kind = 'memory' as const;

  private readonly store = new Map<string, MemoryEntry>();
  private readonly sweeper: NodeJS.Timeout;

  constructor() {
    // Periodic sweep bounds memory growth from keys that are never read again.
    this.sweeper = setInterval(() => this.sweep(), 60_000);
    this.sweeper.unref();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (entry.expiresAtMs <= now) this.store.delete(key);
    }
  }

  private read(key: string): MemoryEntry | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (entry.expiresAtMs <= Date.now()) {
      this.store.delete(key);
      return undefined;
    }
    return entry;
  }

  async get<T>(key: string): Promise<T | null> {
    return (this.read(key)?.value as T) ?? null;
  }

  async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    this.store.set(key, { value, expiresAtMs: Date.now() + ttlSeconds * 1000 });
  }

  async del(...keys: string[]): Promise<void> {
    for (const key of keys) this.store.delete(key);
  }

  async delByPrefix(prefix: string): Promise<void> {
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) this.store.delete(key);
    }
  }

  async incr(key: string, ttlSeconds: number): Promise<number> {
    const existing = this.read(key);
    const next = (typeof existing?.value === 'number' ? existing.value : 0) + 1;
    this.store.set(key, {
      value: next,
      // Preserve the original window: do not extend TTL on every hit.
      expiresAtMs: existing?.expiresAtMs ?? Date.now() + ttlSeconds * 1000,
    });
    return next;
  }

  async has(key: string): Promise<boolean> {
    return this.read(key) !== undefined;
  }

  async close(): Promise<void> {
    clearInterval(this.sweeper);
    this.store.clear();
  }
}

// ---------------------------------------------------------------------------
// Redis backend
// ---------------------------------------------------------------------------

class RedisCacheStore implements CacheStore {
  readonly kind = 'redis' as const;

  constructor(private readonly client: Redis) {}

  async get<T>(key: string): Promise<T | null> {
    const raw = await this.client.get(key);
    if (raw === null) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      // Corrupt entry: drop it rather than propagating a parse error.
      await this.client.del(key);
      return null;
    }
  }

  async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    await this.client.set(key, JSON.stringify(value), 'EX', Math.max(1, Math.floor(ttlSeconds)));
  }

  async del(...keys: string[]): Promise<void> {
    if (keys.length === 0) return;
    await this.client.del(...keys);
  }

  async delByPrefix(prefix: string): Promise<void> {
    // SCAN, not KEYS: KEYS blocks the Redis event loop on large keyspaces.
    // `keyPrefix` is applied client-side, so the pattern must include it while
    // the returned keys must have it stripped before deletion.
    const fullPrefix = `${env.redis.keyPrefix}${prefix}`;
    let cursor = '0';

    do {
      const [nextCursor, keys] = await this.client.scan(
        cursor,
        'MATCH',
        `${fullPrefix}*`,
        'COUNT',
        200,
      );
      cursor = nextCursor;
      if (keys.length > 0) {
        const unprefixed = keys.map((key) =>
          key.startsWith(env.redis.keyPrefix) ? key.slice(env.redis.keyPrefix.length) : key,
        );
        await this.client.del(...unprefixed);
      }
    } while (cursor !== '0');
  }

  async incr(key: string, ttlSeconds: number): Promise<number> {
    // INCR then conditional EXPIRE: the NX flag only sets a TTL on first hit,
    // keeping the window fixed rather than sliding.
    const results = await this.client
      .multi()
      .incr(key)
      .expire(key, Math.max(1, Math.floor(ttlSeconds)), 'NX')
      .exec();

    const value = results?.[0]?.[1];
    return typeof value === 'number' ? value : Number(value ?? 0);
  }

  async has(key: string): Promise<boolean> {
    return (await this.client.exists(key)) === 1;
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

let redisClient: Redis | null = null;
let cacheStore: CacheStore | null = null;

function createRedisClient(): Redis {
  const options: RedisOptions = {
    keyPrefix: env.redis.keyPrefix,
    lazyConnect: false,
    // Fail fast instead of queueing forever when Redis is down; callers treat a
    // cache error as a miss.
    maxRetriesPerRequest: 2,
    enableOfflineQueue: false,
    connectTimeout: 5000,
    retryStrategy: (attempt) => Math.min(attempt * 500, 5000),
    ...(env.redis.password ? { password: env.redis.password } : {}),
    ...(env.redis.tls ? { tls: {} } : {}),
  };

  const client = new Redis(env.redis.url, options);

  client.on('connect', () => logger.info('Redis connected'));
  client.on('ready', () => logger.debug('Redis ready'));
  client.on('error', (error: Error) => logger.error('Redis error', { error: error.message }));
  client.on('close', () => logger.warn('Redis connection closed'));
  client.on('reconnecting', () => logger.warn('Redis reconnecting'));

  return client;
}

/** Process-wide cache singleton. */
export function getCache(): CacheStore {
  if (cacheStore) return cacheStore;

  if (env.redis.enabled) {
    redisClient = createRedisClient();
    cacheStore = new RedisCacheStore(redisClient);
    logger.info('Cache backend: Redis', { url: redactRedisUrl(env.redis.url) });
  } else {
    cacheStore = new MemoryCacheStore();
    logger.warn(
      'Cache backend: in-process memory. Enable Redis (REDIS_ENABLED=true) for ' +
        'multi-instance deployments - rate limits and session caches are not shared between workers.',
    );
  }

  return cacheStore;
}

/**
 * Raw Redis client, or `null` when Redis is disabled.
 * Only `rate-limit-redis` needs this; everything else uses {@link CacheStore}.
 */
export function getRedisClient(): Redis | null {
  if (!env.redis.enabled) return null;
  if (!redisClient) getCache();
  return redisClient;
}

/** Strip credentials from a Redis URL before logging it. */
function redactRedisUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.password) parsed.password = '***';
    if (parsed.username) parsed.username = '***';
    return parsed.toString();
  } catch {
    return 'redis://<unparseable>';
  }
}

/** Liveness probe for `/health/ready`. */
export async function checkCacheHealth(): Promise<{ ok: boolean; kind: string; latencyMs: number }> {
  const cache = getCache();
  const started = Date.now();

  if (cache.kind === 'memory') {
    return { ok: true, kind: cache.kind, latencyMs: 0 };
  }

  try {
    await redisClient?.ping();
    return { ok: true, kind: cache.kind, latencyMs: Date.now() - started };
  } catch (error) {
    logger.error('Redis health check failed', { error });
    return { ok: false, kind: cache.kind, latencyMs: Date.now() - started };
  }
}

/** Release cache resources during graceful shutdown. Idempotent. */
export async function closeCache(): Promise<void> {
  const store = cacheStore;
  cacheStore = null;
  redisClient = null;
  if (!store) return;
  try {
    await store.close();
    logger.info('Cache closed', { kind: store.kind });
  } catch (error) {
    logger.warn('Error while closing cache', { error });
  }
}

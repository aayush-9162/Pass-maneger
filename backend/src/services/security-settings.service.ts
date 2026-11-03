/**
 * Runtime security policy.
 *
 * ## The caching problem
 *
 * Policy is consulted on essentially every authenticated request - the idle
 * timeout check, the emergency lock check, the CSRF toggle. A database round
 * trip per request per check would be absurd, so the merged settings object is
 * held in memory.
 *
 * That creates the usual staleness question, made sharper by PM2 running several
 * workers: an administrator saves in worker 1, and workers 2-4 keep enforcing
 * the old policy until their own cache expires.
 *
 * Two mechanisms, belt and braces:
 *
 *  1. A short TTL ({@link CACHE_TTL_MS}). Bounded staleness with no
 *     infrastructure, so a single-process deployment with no Redis still
 *     converges within seconds.
 *  2. A Redis pub/sub broadcast when Redis is configured, so the other workers
 *     drop their cache immediately rather than waiting out the TTL.
 *
 * Neither is a correctness guarantee for the few seconds after a change, and it
 * does not need to be: no setting here is a authorisation boundary. The ones
 * that gate access - the emergency lock especially - are re-read through
 * {@link getSettings} which honours the TTL, and a five-second window on
 * *tightening* a policy is not a vulnerability. Loosening is immediate for the
 * worker that made the change and near-immediate elsewhere.
 *
 * ## Environment overrides
 *
 * `SECURITY_SETTINGS_LOCK` pins keys to their environment value. An operator who
 * sets it keeps a floor that a compromised administrator account cannot lower -
 * the API refuses writes to a locked key, and the admin panel shows it read-only
 * with the reason.
 */

import {
  SECURITY_SETTING_DEFAULTS,
  SECURITY_SETTING_DEFINITIONS,
  isSecuritySettingKey,
  validateSettingValue,
  validateSettingsCoherence,
  type SecuritySettings,
  type SecuritySettingEntry,
  type SettingValidationError,
} from '@passm/shared';

import { getRedisClient } from '../config/cache';
import { env } from '../config/env';
import { logger } from '../config/logger';
import {
  mergeSettings,
  securitySettingsRepository,
  type StoredSetting,
} from '../repositories/security-settings.repository';
import { BadRequestError, ValidationError } from '../utils/errors';

/**
 * How long a worker trusts its cached copy.
 *
 * Five seconds: long enough that a burst of requests costs one query, short
 * enough that an administrator watching the effect of a change sees it before
 * they conclude it did not save.
 */
const CACHE_TTL_MS = 5_000;

/** Redis channel other workers listen on for invalidation. */
const INVALIDATION_CHANNEL = 'passm:settings:changed';

interface CacheEntry {
  settings: SecuritySettings;
  stored: StoredSetting[];
  loadedAt: number;
}

let cache: CacheEntry | null = null;
/** In-flight load, so a burst of concurrent misses issues one query, not N. */
let inFlight: Promise<CacheEntry> | null = null;
let subscribed = false;

/**
 * Keys the environment pins.
 *
 * Parsed once. An unknown key is a configuration mistake worth shouting about
 * at boot rather than silently ignoring - the operator believes something is
 * locked that is not.
 */
const lockedKeys: ReadonlySet<keyof SecuritySettings> = (() => {
  const raw = process.env.SECURITY_SETTINGS_LOCK ?? '';
  const keys = new Set<keyof SecuritySettings>();

  for (const candidate of raw.split(',').map((part) => part.trim()).filter(Boolean)) {
    if (isSecuritySettingKey(candidate)) {
      keys.add(candidate);
    } else {
      logger.error('SECURITY_SETTINGS_LOCK names an unknown setting; ignoring it', {
        key: candidate,
      });
    }
  }

  return keys;
})();

/**
 * Defaults with environment fallbacks folded in.
 *
 * Phases 1-5 configured these through environment variables and existing
 * deployments still set them. Honouring them as the *default* - beneath any
 * stored value - means upgrading does not silently reset a policy someone
 * deliberately configured, while the admin panel still takes precedence going
 * forward.
 */
const baseDefaults: SecuritySettings = {
  ...SECURITY_SETTING_DEFAULTS,
  sessionIdleTimeoutMinutes: env.security.sessionIdleTimeoutMinutes,
  maxActiveSessionsPerUser: env.security.maxActiveSessionsPerUser,
  maxDevicesPerUser: env.security.maxDevicesPerUser,
  rateLimitGlobalMax: env.rateLimit.global.max,
  rateLimitLoginMax: env.rateLimit.login.max,
  rateLimitWindowMinutes: Math.round(env.rateLimit.global.windowMs / 60_000),
};

/** Subscribe once to cross-worker invalidation, if Redis is configured. */
function ensureSubscribed(): void {
  if (subscribed) return;
  subscribed = true;

  const client = getRedisClient();
  if (!client) return;

  // A dedicated connection: a subscribed ioredis client refuses ordinary
  // commands, so sharing the main one would break every other cache user.
  const subscriber = client.duplicate();

  subscriber.subscribe(INVALIDATION_CHANNEL).catch((error: unknown) => {
    logger.warn('Could not subscribe to settings invalidation; relying on the TTL', { error });
  });

  subscriber.on('message', (channel: string) => {
    if (channel !== INVALIDATION_CHANNEL) return;
    cache = null;
    logger.debug('Security settings cache invalidated by another worker');
  });
}

async function load(): Promise<CacheEntry> {
  const stored = await securitySettingsRepository.findAll();
  const merged = mergeSettings(stored);

  // Fold the environment fallbacks in beneath the stored values: any key with
  // no row keeps its environment value rather than the shipped constant.
  const settings: SecuritySettings = { ...baseDefaults };
  const storedKeys = new Set(stored.map((entry) => entry.key));
  for (const key of Object.keys(settings) as (keyof SecuritySettings)[]) {
    if (storedKeys.has(key)) {
      Object.assign(settings, { [key]: merged[key] });
    }
  }

  // A pinned key always wins, whatever the database says.
  for (const key of lockedKeys) {
    Object.assign(settings, { [key]: baseDefaults[key] });
  }

  return { settings, stored, loadedAt: Date.now() };
}

async function getEntry(): Promise<CacheEntry> {
  ensureSubscribed();

  if (cache && Date.now() - cache.loadedAt < CACHE_TTL_MS) return cache;
  if (inFlight) return inFlight;

  inFlight = load()
    .then((entry) => {
      cache = entry;
      return entry;
    })
    .catch((error: unknown) => {
      // The database is unreachable. Serving a stale policy is better than
      // failing every request; serving the defaults is better than crashing.
      logger.error('Could not load security settings; using the last known policy', { error });
      const fallback: CacheEntry = cache ?? {
        settings: baseDefaults,
        stored: [],
        loadedAt: Date.now(),
      };
      return fallback;
    })
    .finally(() => {
      inFlight = null;
    });

  return inFlight;
}

/** Tell every worker, including this one, to reload. */
async function invalidate(): Promise<void> {
  cache = null;

  const client = getRedisClient();
  if (!client) return;

  try {
    await client.publish(INVALIDATION_CHANNEL, '1');
  } catch (error) {
    logger.warn('Could not broadcast settings invalidation; other workers will use the TTL', {
      error,
    });
  }
}

export const securitySettingsService = {
  /** The live policy. Cheap: usually an in-memory read. */
  async getSettings(): Promise<SecuritySettings> {
    const entry = await getEntry();
    return entry.settings;
  },

  /**
   * One setting, typed.
   *
   * Sugar over {@link getSettings}, but it reads far better at the call site:
   * `await setting('emergencyLockActive')` says what it wants.
   */
  async get<K extends keyof SecuritySettings>(key: K): Promise<SecuritySettings[K]> {
    const settings = await this.getSettings();
    return settings[key];
  },

  /** Settings plus provenance, for the admin panel. */
  async getWithProvenance(): Promise<{
    settings: SecuritySettings;
    entries: SecuritySettingEntry[];
    lockedKeys: (keyof SecuritySettings)[];
  }> {
    const entry = await getEntry();
    const byKey = new Map(entry.stored.map((stored) => [stored.key, stored]));

    const entries: SecuritySettingEntry[] = (
      Object.keys(SECURITY_SETTING_DEFINITIONS) as (keyof SecuritySettings)[]
    ).map((key) => {
      const stored = byKey.get(key);
      return {
        key,
        value: entry.settings[key],
        isDefault: stored === undefined,
        updatedAt: stored?.updatedAt?.toISOString() ?? null,
        updatedByName: stored?.updatedByName ?? null,
      };
    });

    return { settings: entry.settings, entries, lockedKeys: [...lockedKeys] };
  },

  /**
   * Apply a partial update.
   *
   * Validates each value against its definition, then validates the *resulting*
   * settings object as a whole - a change can be individually fine and jointly
   * nonsensical, like an idle timeout longer than the absolute one.
   *
   * Returns the keys that actually changed, so the audit entry records a diff
   * rather than "someone pressed save".
   */
  async update(
    patch: Partial<SecuritySettings>,
    updatedByUserId: string | null,
  ): Promise<{
    settings: SecuritySettings;
    changed: { key: keyof SecuritySettings; from: unknown; to: unknown }[];
  }> {
    const current = await this.getSettings();
    const fieldErrors: SettingValidationError[] = [];
    const normalized = new Map<keyof SecuritySettings, SecuritySettings[keyof SecuritySettings]>();

    for (const [rawKey, rawValue] of Object.entries(patch)) {
      if (!isSecuritySettingKey(rawKey)) {
        fieldErrors.push({ key: rawKey, message: 'Not a recognised setting.' });
        continue;
      }

      if (lockedKeys.has(rawKey)) {
        fieldErrors.push({
          key: rawKey,
          message: 'Pinned by the server environment and cannot be changed here.',
        });
        continue;
      }

      const result = validateSettingValue(rawKey, rawValue);
      if (!result.ok) {
        fieldErrors.push({ key: rawKey, message: result.error });
        continue;
      }

      normalized.set(rawKey, result.value);
    }

    if (fieldErrors.length > 0) {
      throw new ValidationError(
        fieldErrors.map((error) => ({ field: error.key, message: error.message })),
        'Some settings could not be saved.',
      );
    }

    const candidate: SecuritySettings = { ...current };
    for (const [key, value] of normalized) {
      Object.assign(candidate, { [key]: value });
    }

    const coherenceErrors = validateSettingsCoherence(candidate);
    if (coherenceErrors.length > 0) {
      throw new ValidationError(
        coherenceErrors.map((error) => ({ field: error.key, message: error.message })),
        'These settings contradict each other.',
      );
    }

    const changed: { key: keyof SecuritySettings; from: unknown; to: unknown }[] = [];

    for (const [key, value] of normalized) {
      if (current[key] === value) continue;
      await securitySettingsRepository.upsert(key, value, updatedByUserId);
      changed.push({ key, from: current[key], to: value });
    }

    await invalidate();

    return { settings: candidate, changed };
  },

  /**
   * Return every setting to its default.
   *
   * Pinned keys are unaffected - they were never stored in the first place.
   */
  async resetToDefaults(): Promise<number> {
    const removed = await securitySettingsRepository.removeAll();
    await invalidate();
    return removed;
  },

  /** Return one setting to its default. */
  async resetKey(key: keyof SecuritySettings): Promise<void> {
    if (lockedKeys.has(key)) {
      throw new BadRequestError('That setting is pinned by the server environment.');
    }
    await securitySettingsRepository.remove(key);
    await invalidate();
  },

  /** True when the environment pins this key. */
  isLocked(key: keyof SecuritySettings): boolean {
    return lockedKeys.has(key);
  },

  /**
   * Drop the cache.
   *
   * For tests, and for the maintenance job after a bulk change. Not exported to
   * the API: an administrator has no reason to reach for this, and a "clear
   * cache" button invites cargo-cult use.
   */
  invalidateCache(): void {
    cache = null;
  },
};

/**
 * Security settings repository.
 *
 * One row per policy key. Absent rows mean the shipped default applies, so this
 * repository never writes defaults - a table with 60 rows identical to the code
 * defaults would make "what has actually been customised?" unanswerable.
 */

import {
  SECURITY_SETTING_DEFAULTS,
  isSecuritySettingKey,
  type SecuritySettings,
} from '@passm/shared';

import { execute, query, type RowDataPacket, type SqlExecutor } from '../config/database';
import { logger } from '../config/logger';

interface SettingRow extends RowDataPacket {
  setting_key: string;
  /**
   * mysql2 parses a JSON column into a JS value already, so this is a boolean,
   * number or string rather than the text of one. Older drivers hand back a
   * string, which is why {@link parseStoredValue} tolerates both.
   */
  setting_value: unknown;
  updated_at: Date | null;
  updated_by_user_id: string | null;
  updated_by_first_name: string | null;
  updated_by_last_name: string | null;
}

const SELECT_COLUMNS = `
  s.setting_key, s.setting_value, s.updated_at, s.updated_by_user_id,
  u.first_name AS updated_by_first_name,
  u.last_name  AS updated_by_last_name
  FROM security_settings s
  LEFT JOIN users u ON u.id = s.updated_by_user_id
`;

/**
 * Decode a stored value, tolerating both a parsed value and raw JSON text.
 *
 * The subtlety is string-valued settings. mysql2 parses a JSON column for you,
 * so a stored `"enforce"` arrives as the JS string `enforce` - which is *not*
 * valid JSON. Blindly re-parsing every string therefore destroyed exactly the
 * settings that need to be strings (`ipAllowListMode`, `emergencyLockMessage`),
 * while booleans and numbers worked fine because they arrive as non-strings.
 *
 * So a string that does not parse as JSON is treated as an already-decoded
 * value rather than as corruption. Only a genuinely unusable value returns
 * `undefined`, and the caller falls back to the default and logs - a single bad
 * row must not take the whole policy down, because it is read on every
 * authenticated request.
 */
function parseStoredValue(raw: unknown): unknown {
  if (typeof raw !== 'string') return raw;

  try {
    return JSON.parse(raw);
  } catch {
    // Already decoded by the driver. A bare string is a legitimate value.
    return raw;
  }
}

export interface StoredSetting {
  key: keyof SecuritySettings;
  value: unknown;
  updatedAt: Date | null;
  updatedByName: string | null;
}

export const securitySettingsRepository = {
  /**
   * Every customised setting.
   *
   * Unknown keys - left behind by a downgrade, or a hand-edited row - are
   * dropped with a warning rather than surfaced, so a stale row cannot inject a
   * property into the settings object.
   */
  async findAll(executor?: SqlExecutor): Promise<StoredSetting[]> {
    const rows = await query<SettingRow>(`SELECT ${SELECT_COLUMNS}`, [], executor);

    const settings: StoredSetting[] = [];
    for (const row of rows) {
      if (!isSecuritySettingKey(row.setting_key)) {
        logger.warn('Ignoring unknown security setting row', { key: row.setting_key });
        continue;
      }

      const value = parseStoredValue(row.setting_value);
      if (value === undefined) {
        logger.error('Unreadable security setting value; falling back to the default', {
          key: row.setting_key,
        });
        continue;
      }

      const name = [row.updated_by_first_name, row.updated_by_last_name]
        .filter((part): part is string => Boolean(part))
        .join(' ');

      settings.push({
        key: row.setting_key,
        value,
        updatedAt: row.updated_at,
        updatedByName: name.length > 0 ? name : null,
      });
    }

    return settings;
  },

  /**
   * Write one setting.
   *
   * Upsert rather than update-then-insert so two administrators saving at the
   * same moment cannot produce a duplicate-key error on the second one.
   */
  async upsert(
    key: keyof SecuritySettings,
    value: SecuritySettings[keyof SecuritySettings],
    updatedByUserId: string | null,
    executor?: SqlExecutor,
  ): Promise<void> {
    await execute(
      `INSERT INTO security_settings (setting_key, setting_value, updated_by_user_id)
       VALUES (?, CAST(? AS JSON), ?)
       ON DUPLICATE KEY UPDATE
         setting_value      = VALUES(setting_value),
         updated_by_user_id = VALUES(updated_by_user_id),
         updated_at         = CURRENT_TIMESTAMP(3)`,
      [key, JSON.stringify(value), updatedByUserId],
      executor,
    );
  },

  /** Drop a setting, returning it to the shipped default. */
  async remove(key: keyof SecuritySettings, executor?: SqlExecutor): Promise<boolean> {
    const result = await execute(
      'DELETE FROM security_settings WHERE setting_key = ?',
      [key],
      executor,
    );
    return result.affectedRows > 0;
  },

  /** Drop every customisation. Used by the "reset to defaults" action. */
  async removeAll(executor?: SqlExecutor): Promise<number> {
    const result = await execute('DELETE FROM security_settings', [], executor);
    return result.affectedRows;
  },
};

/**
 * Fold stored rows over the defaults into a complete settings object.
 *
 * Exported because both the service and its tests need the same merge, and
 * because a value that fails validation on read - a range narrowed by a later
 * release, say - must degrade to the default rather than propagate.
 */
export function mergeSettings(stored: readonly StoredSetting[]): SecuritySettings {
  const settings: SecuritySettings = { ...SECURITY_SETTING_DEFAULTS };

  for (const entry of stored) {
    const expected = typeof SECURITY_SETTING_DEFAULTS[entry.key];
    if (typeof entry.value !== expected) {
      logger.warn('Security setting has the wrong type; using the default', {
        key: entry.key,
        expected,
        got: typeof entry.value,
      });
      continue;
    }

    // `Object.assign` rather than an index write: `SecuritySettings` has no
    // index signature, and casting to one would silently accept a key the
    // interface does not declare.
    Object.assign(settings, { [entry.key]: entry.value });
  }

  return settings;
}

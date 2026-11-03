/**
 * Runtime security policy - the settings an administrator can change without a
 * redeploy.
 *
 * ## Why this exists
 *
 * Phases 1-5 put every knob in an environment variable. That is correct for
 * things that decide how the process *boots* - which database, which secret,
 * which port - because those cannot change while it runs. It is wrong for
 * policy: "how long may a session sit idle" is a decision the security team
 * makes on a Tuesday afternoon, not one that should require an SSH session and
 * a PM2 restart.
 *
 * So policy moves here. Environment variables remain the *fallback*: a fresh
 * database with no rows still boots with sane values, and an operator who has
 * locked themselves out of the admin panel can still override from the
 * environment.
 *
 * ## Why the schema is data rather than a Zod object
 *
 * The admin settings page renders itself from {@link SECURITY_SETTING_DEFINITIONS}.
 * Adding a setting is one entry here and it appears in the UI, gets validated on
 * the server, and lands in the audit log with a human-readable label. A hand-
 * written form would drift from the validator within two phases.
 *
 * `Record<keyof SecuritySettings, ...>` makes that completeness a compile error
 * rather than a missing row in a table.
 *
 * ## Enforcement honesty
 *
 * Each setting declares where it is enforced. A `client` setting is a
 * *preference* - the browser honours it, a patched client need not. Clipboard
 * clearing and idle auto-lock are like this, and the UI says so rather than
 * implying the server can police what a browser does with its own memory. Only
 * `server` and `both` settings are guarantees.
 */

// ---------------------------------------------------------------------------
// The settings themselves
// ---------------------------------------------------------------------------

/**
 * Every administrator-configurable policy value.
 *
 * Kept flat deliberately: a flat record is trivial to diff for the audit log,
 * trivial to patch one key at a time, and trivial to store as a key/value table.
 */
export interface SecuritySettings {
  // --- Sessions ------------------------------------------------------------
  /** Sign out after this long with no request. */
  sessionIdleTimeoutMinutes: number;
  /** Sign out this long after sign-in regardless of activity. */
  sessionAbsoluteTimeoutHours: number;
  /** Concurrent sessions per user; the oldest is evicted beyond this. */
  maxActiveSessionsPerUser: number;

  // --- Vault behaviour (browser-enforced) ----------------------------------
  /** Sign the console out after this long with no input. `0` disables. */
  vaultAutoLockMinutes: number;
  /** Warn this many seconds before that sign-out. */
  vaultAutoLockWarningSeconds: number;
  /** Wipe a copied password from the clipboard after this long. `0` disables. */
  clipboardClearSeconds: number;
  /** Sign out when the browser tab is hidden. */
  lockOnTabHidden: boolean;
  /**
   * Only administrators may reveal or copy a stored password.
   *
   * Everyone else uses the credential without ever seeing it: the browser
   * extension fills it into the page, and the web console masks it with no way
   * to unmask or copy.
   *
   * See {@link PASSWORD_ACCESS_POLICY} in `permissions.ts` for what this does
   * and, importantly, does not guarantee.
   */
  restrictPasswordAccessToAdmins: boolean;

  // --- Step-up (Google re-confirmation) -----------------------------------
  /** Confirm with Google before revealing a password. */
  stepUpForReveal: boolean;
  /** Confirm with Google before exporting an audit log. */
  stepUpForExport: boolean;
  /** Confirm with Google before a destructive admin action. */
  stepUpForAdminAction: boolean;
  /** Confirm with Google before changing these settings. */
  stepUpForSettingsChange: boolean;
  /** How long one successful step-up stays good for. */
  stepUpValidityMinutes: number;

  // --- Devices -------------------------------------------------------------
  /** Allow users to mark a device trusted. */
  deviceTrustEnabled: boolean;
  /** Trust expires after this long. */
  deviceTrustDays: number;
  /** Registered devices per user; the least recently used is evicted beyond this. */
  maxDevicesPerUser: number;
  /** A device an administrator has not approved cannot sign in. */
  requireDeviceApproval: boolean;

  // --- Network -------------------------------------------------------------
  /**
   * `off` ignores the list, `audit` logs what would have been blocked, and
   * `enforce` blocks. The middle setting exists because turning this straight on
   * is how an administrator locks the whole company out at 5pm on a Friday.
   */
  ipAllowListMode: 'off' | 'audit' | 'enforce';
  /** Apply the allow list to administrators too. */
  ipAllowListAppliesToAdmins: boolean;
  /** Require a CSRF token on state-changing requests. */
  csrfEnabled: boolean;
  /** Requests per window across the whole API, per address. */
  rateLimitGlobalMax: number;
  /** Sign-in attempts per window, per address and account. */
  rateLimitLoginMax: number;
  /** Length of the rate-limit window. */
  rateLimitWindowMinutes: number;

  // --- Notifications -------------------------------------------------------
  notifyOnNewDevice: boolean;
  notifyOnVaultShared: boolean;
  notifyOnAdminAction: boolean;
  notifyOnNewLocation: boolean;
  /** Alert administrators when someone tries to unmask a password. */
  notifyOnPasswordTamper: boolean;

  // --- Access -------------------------------------------------------------
  /**
   * Only administrators may sign in to the web console.
   *
   * Everyone else uses the browser extension. With no personal vaults and no
   * reveal or copy for non-administrators, the console has nothing left for
   * them to do - so the sign-in form is a door onto an empty room.
   */
  webConsoleAdminsOnly: boolean;

  // --- Emergency -----------------------------------------------------------
  /**
   * Global kill switch. Every vault becomes unreadable and every session is
   * refused until an administrator clears it.
   */
  emergencyLockActive: boolean;
  /** Shown to users while the lock is on, so they know it is deliberate. */
  emergencyLockMessage: string;
}

// ---------------------------------------------------------------------------
// Schema metadata
// ---------------------------------------------------------------------------

export const SETTING_CATEGORY = {
  SESSION: 'session',
  VAULT: 'vault',
  STEP_UP: 'stepUp',
  DEVICE: 'device',
  NETWORK: 'network',
  NOTIFICATION: 'notification',
  EMERGENCY: 'emergency',
} as const;

export type SettingCategory = (typeof SETTING_CATEGORY)[keyof typeof SETTING_CATEGORY];

export const SETTING_CATEGORY_META: Record<
  SettingCategory,
  { label: string; description: string; order: number }
> = {
  [SETTING_CATEGORY.SESSION]: {
    label: 'Sessions',
    description: 'How long a signed-in session survives.',
    order: 3,
  },
  [SETTING_CATEGORY.VAULT]: {
    label: 'Vault behaviour',
    description:
      'Enforced by the browser, not the server. A modified client can ignore these, so treat them as safety rails rather than guarantees.',
    order: 4,
  },
  [SETTING_CATEGORY.STEP_UP]: {
    label: 'Two-step verification',
    description: 'Where the user must confirm with Google again before going ahead.',
    order: 5,
  },
  [SETTING_CATEGORY.DEVICE]: {
    label: 'Devices',
    description: 'Which machines may reach the vault, and for how long.',
    order: 6,
  },
  [SETTING_CATEGORY.NETWORK]: {
    label: 'Network',
    description: 'Address restrictions, CSRF, and request rate limits.',
    order: 7,
  },
  [SETTING_CATEGORY.NOTIFICATION]: {
    label: 'Notifications',
    description: 'Which events raise an alert for the user or an administrator.',
    order: 8,
  },
  [SETTING_CATEGORY.EMERGENCY]: {
    label: 'Emergency',
    description: 'The break-glass controls. Read the warning before using them.',
    order: 9,
  },
};

/** Where a setting is actually enforced. */
export type SettingEnforcement = 'server' | 'client' | 'both';

export interface SettingDefinition {
  type: 'boolean' | 'integer' | 'string' | 'enum';
  category: SettingCategory;
  label: string;
  description: string;
  enforcement: SettingEnforcement;
  /** Inclusive bounds for `integer`. */
  min?: number;
  max?: number;
  /** Suffix rendered after a number field. */
  unit?: string;
  /** Maximum length for `string`. */
  maxLength?: number;
  /** Choices for `enum`. */
  options?: readonly { value: string; label: string; description?: string }[];
  /** A value that means "disabled", worth spelling out in the UI. */
  zeroMeans?: string;
  /** Changing this can lock people out; the UI asks twice. */
  dangerous?: boolean;
  /** Only meaningful over TLS. Shown but flagged on a plaintext deployment. */
  requiresTls?: boolean;
}

/**
 * The schema.
 *
 * Typed as a complete record so a new field on {@link SecuritySettings} without
 * a definition here fails to compile.
 */
export const SECURITY_SETTING_DEFINITIONS: Record<keyof SecuritySettings, SettingDefinition> = {
  // --- Session -------------------------------------------------------------
  sessionIdleTimeoutMinutes: {
    type: 'integer',
    category: SETTING_CATEGORY.SESSION,
    label: 'Idle timeout',
    description:
      'Sign out after this long with no request from the client. Signing back in is one click on the Google button. 259200 is 180 days.',
    enforcement: 'both',
    min: 5,
    max: 525_600,
    unit: 'minutes',
  },
  sessionAbsoluteTimeoutHours: {
    type: 'integer',
    category: SETTING_CATEGORY.SESSION,
    label: 'Absolute timeout',
    description:
      'Sign out this long after sign-in whatever the user is doing. Caps the value of a stolen refresh token. 4320 is 180 days.',
    enforcement: 'server',
    min: 1,
    max: 8_760,
    unit: 'hours',
  },
  maxActiveSessionsPerUser: {
    type: 'integer',
    category: SETTING_CATEGORY.SESSION,
    label: 'Concurrent sessions',
    description: 'Beyond this, the oldest session is signed out.',
    enforcement: 'server',
    min: 1,
    max: 100,
    unit: 'sessions',
  },
  // --- Vault ---------------------------------------------------------------
  vaultAutoLockMinutes: {
    type: 'integer',
    category: SETTING_CATEGORY.VAULT,
    label: 'Sign the console out after',
    description:
      'Sign out after this long with no keyboard or mouse input. Protects an unattended screen, which the session idle timeout above already covers for an absent client - off by default for that reason.',
    enforcement: 'client',
    min: 0,
    max: 240,
    zeroMeans: 'never while signed in',
    unit: 'minutes',
  },
  vaultAutoLockWarningSeconds: {
    type: 'integer',
    category: SETTING_CATEGORY.VAULT,
    label: 'Warn before signing out',
    description: 'Give the user this long to say they are still there.',
    enforcement: 'client',
    min: 0,
    max: 300,
    unit: 'seconds',
    zeroMeans: 'no warning',
  },
  clipboardClearSeconds: {
    type: 'integer',
    category: SETTING_CATEGORY.VAULT,
    label: 'Clear the clipboard after',
    description:
      'Overwrite a copied password. Note that clipboard history in Windows or a sync tool may keep its own copy that no web page can reach.',
    enforcement: 'client',
    min: 0,
    max: 300,
    unit: 'seconds',
    zeroMeans: 'never clear',
  },
  lockOnTabHidden: {
    type: 'boolean',
    category: SETTING_CATEGORY.VAULT,
    label: 'Sign out when the tab is hidden',
    description:
      'Aggressive. Switching to another tab signs the console out immediately. Suitable for shared workstations, irritating everywhere else.',
    enforcement: 'client',
  },
  restrictPasswordAccessToAdmins: {
    type: 'boolean',
    category: SETTING_CATEGORY.VAULT,
    label: 'Only administrators may see or copy passwords',
    description:
      'Everyone else uses credentials through the browser extension, which fills them without showing them. Reveal and copy disappear from the console, and attempts are audited. This is a client-side control: the browser must receive a password in order to fill it, so a technical user can still recover one from browser tooling. It stops routine copying and sharing, not a determined insider.',
    enforcement: 'client',
  },

  // --- Step-up -------------------------------------------------------------
  stepUpForReveal: {
    type: 'boolean',
    category: SETTING_CATEGORY.STEP_UP,
    label: 'Before revealing a password',
    description:
      'Protects a signed-in, unattended screen. The session is already open, so this is about the person sitting at it, not the network.',
    enforcement: 'both',
  },
  stepUpForExport: {
    type: 'boolean',
    category: SETTING_CATEGORY.STEP_UP,
    label: 'Before exporting an audit log',
    description: 'An export leaves the system. Confirm the person asking is the account holder.',
    enforcement: 'server',
  },
  stepUpForAdminAction: {
    type: 'boolean',
    category: SETTING_CATEGORY.STEP_UP,
    label: 'Before a destructive admin action',
    description:
      'Deleting a user, force-signing-out everyone. The actions that are hard to undo.',
    enforcement: 'server',
  },
  stepUpForSettingsChange: {
    type: 'boolean',
    category: SETTING_CATEGORY.STEP_UP,
    label: 'Before changing these settings',
    description:
      'A hijacked admin session that can silently weaken the policy can weaken everything else afterwards.',
    enforcement: 'server',
  },
  stepUpValidityMinutes: {
    type: 'integer',
    category: SETTING_CATEGORY.STEP_UP,
    label: 'Verification lasts',
    description: 'One successful check covers further actions for this long.',
    enforcement: 'server',
    min: 1,
    max: 120,
    unit: 'minutes',
  },

  // --- Device --------------------------------------------------------------
  deviceTrustEnabled: {
    type: 'boolean',
    category: SETTING_CATEGORY.DEVICE,
    label: 'Allow trusted devices',
    description: 'Users may mark a machine as trusted to skip step-up prompts on it.',
    enforcement: 'server',
  },
  deviceTrustDays: {
    type: 'integer',
    category: SETTING_CATEGORY.DEVICE,
    label: 'Trust expires after',
    description: 'A trusted device must be re-confirmed this often.',
    enforcement: 'server',
    min: 1,
    max: 365,
    unit: 'days',
  },
  maxDevicesPerUser: {
    type: 'integer',
    category: SETTING_CATEGORY.DEVICE,
    label: 'Devices per user',
    description: 'Beyond this, the least recently used untrusted device is dropped.',
    enforcement: 'server',
    min: 1,
    max: 100,
    unit: 'devices',
  },
  requireDeviceApproval: {
    type: 'boolean',
    category: SETTING_CATEGORY.DEVICE,
    label: 'Administrator must approve new devices',
    description:
      'A new machine cannot reach the vault until someone approves it. Strong control, real support burden - every new laptop needs a human.',
    enforcement: 'server',
    dangerous: true,
  },

  // --- Network -------------------------------------------------------------
  ipAllowListMode: {
    type: 'enum',
    category: SETTING_CATEGORY.NETWORK,
    label: 'IP allow list',
    description: 'Restrict which addresses may reach the API.',
    enforcement: 'server',
    dangerous: true,
    options: [
      { value: 'off', label: 'Off', description: 'The list is ignored entirely.' },
      {
        value: 'audit',
        label: 'Audit only',
        description: 'Nothing is blocked; every request that would have been is logged.',
      },
      {
        value: 'enforce',
        label: 'Enforce',
        description: 'Requests from addresses outside the list are refused.',
      },
    ],
  },
  ipAllowListAppliesToAdmins: {
    type: 'boolean',
    category: SETTING_CATEGORY.NETWORK,
    label: 'Apply to administrators',
    description:
      'Leaving this off keeps a way back in if the list is wrong. Turning it on is stricter and is how you lock yourself out.',
    enforcement: 'server',
    dangerous: true,
  },
  csrfEnabled: {
    type: 'boolean',
    category: SETTING_CATEGORY.NETWORK,
    label: 'CSRF token required',
    description:
      'State-changing requests must carry a token matching a cookie. Leave on; the only reason to disable it is diagnosing a client that cannot read the cookie.',
    enforcement: 'server',
  },
  rateLimitGlobalMax: {
    type: 'integer',
    category: SETTING_CATEGORY.NETWORK,
    label: 'Requests per window',
    description: 'Across the whole API, per address.',
    enforcement: 'server',
    min: 10,
    max: 100_000,
    unit: 'requests',
  },
  rateLimitLoginMax: {
    type: 'integer',
    category: SETTING_CATEGORY.NETWORK,
    label: 'Sign-in attempts per window',
    description: 'Per address and account pair. Successful sign-ins do not count.',
    enforcement: 'server',
    min: 3,
    max: 1000,
    unit: 'attempts',
  },
  rateLimitWindowMinutes: {
    type: 'integer',
    category: SETTING_CATEGORY.NETWORK,
    label: 'Rate limit window',
    description: 'The period both limits above are measured over.',
    enforcement: 'server',
    min: 1,
    max: 1440,
    unit: 'minutes',
  },

  // --- Notifications -------------------------------------------------------
  notifyOnNewDevice: {
    type: 'boolean',
    category: SETTING_CATEGORY.NOTIFICATION,
    label: 'New device signed in',
    description: 'The single most useful alert: it is how a user notices a stolen session.',
    enforcement: 'server',
  },
  notifyOnVaultShared: {
    type: 'boolean',
    category: SETTING_CATEGORY.NOTIFICATION,
    label: 'A vault was shared with me',
    description: 'Tells the recipient there is something new to use.',
    enforcement: 'server',
  },
  notifyOnAdminAction: {
    type: 'boolean',
    category: SETTING_CATEGORY.NOTIFICATION,
    label: 'An administrator acted on my account',
    description:
      'Locks, forced sign-outs, role changes. Makes administrative power visible to the person it is used on.',
    enforcement: 'server',
  },
  notifyOnNewLocation: {
    type: 'boolean',
    category: SETTING_CATEGORY.NOTIFICATION,
    label: 'Sign-in from a new address',
    description:
      'Noisy on a network that hands out changing addresses; useful where addresses are stable.',
    enforcement: 'server',
  },
  webConsoleAdminsOnly: {
    type: 'boolean',
    category: SETTING_CATEGORY.SESSION,
    label: 'Only administrators may sign in to the web console',
    description:
      'Everyone else uses the browser extension, which is all a non-administrator needs: there are no personal vaults, and reveal and copy are already restricted. Turning this off lets ordinary users sign in to the console again. Note it is enforced on the sign-in itself, not merely hidden - but a client identifies its own type, so treat it as an access policy rather than a boundary.',
    enforcement: 'server',
  },
  notifyOnPasswordTamper: {
    type: 'boolean',
    category: SETTING_CATEGORY.NOTIFICATION,
    label: 'Someone tried to unmask a password',
    description:
      'Alerts administrators when a user unmasks a filled password field, or is refused a reveal. The extension puts the mask straight back, but it cannot stop someone who knows a browser - so this alert, and the audit entry beside it, are what actually cover that case. Goes to administrators, not to the person who tried.',
    enforcement: 'server',
  },

  // --- Emergency -----------------------------------------------------------
  emergencyLockActive: {
    type: 'boolean',
    category: SETTING_CATEGORY.EMERGENCY,
    label: 'Emergency lock',
    description:
      'Immediately signs everyone out and refuses all vault access until cleared. For a suspected breach. Administrators can still sign in to lift it.',
    enforcement: 'server',
    dangerous: true,
  },
  emergencyLockMessage: {
    type: 'string',
    category: SETTING_CATEGORY.EMERGENCY,
    label: 'Message shown while locked',
    description: 'Tell people this is deliberate and who to contact, or they will flood the desk.',
    enforcement: 'server',
    maxLength: 300,
  },
};

/**
 * Shipped defaults.
 *
 * Chosen to be defensible on day one without being unusable: a company that
 * never opens the settings page still gets a sensible policy.
 */
export const SECURITY_SETTING_DEFAULTS: SecuritySettings = {
  // 180 days. A LAN tool; the shorter windows appropriate to an
  // internet-facing console are not worth their cost here.
  sessionIdleTimeoutMinutes: 259_200,
  sessionAbsoluteTimeoutHours: 4_320,
  maxActiveSessionsPerUser: 10,

  vaultAutoLockMinutes: 0,
  vaultAutoLockWarningSeconds: 60,
  clipboardClearSeconds: 30,
  lockOnTabHidden: false,
  restrictPasswordAccessToAdmins: true,

  stepUpForReveal: false,
  stepUpForExport: true,
  stepUpForAdminAction: true,
  stepUpForSettingsChange: true,
  stepUpValidityMinutes: 5,

  deviceTrustEnabled: true,
  deviceTrustDays: 30,
  maxDevicesPerUser: 10,
  requireDeviceApproval: false,

  ipAllowListMode: 'off',
  ipAllowListAppliesToAdmins: false,
  csrfEnabled: true,
  rateLimitGlobalMax: 300,
  rateLimitLoginMax: 10,
  rateLimitWindowMinutes: 15,

  notifyOnNewDevice: true,
  notifyOnVaultShared: true,
  notifyOnAdminAction: true,
  notifyOnNewLocation: false,
  notifyOnPasswordTamper: true,

  webConsoleAdminsOnly: true,

  emergencyLockActive: false,
  emergencyLockMessage:
    'Access is temporarily suspended while we investigate a security issue. Contact the IT helpdesk.',
};

/** Every settings key, in schema order. */
export const SECURITY_SETTING_KEYS = Object.keys(
  SECURITY_SETTING_DEFINITIONS,
) as (keyof SecuritySettings)[];

/** Keys the browser needs in order to behave correctly, safe to hand any user. */
export const CLIENT_VISIBLE_SETTING_KEYS = [
  'sessionIdleTimeoutMinutes',
  'vaultAutoLockMinutes',
  'vaultAutoLockWarningSeconds',
  'clipboardClearSeconds',
  'lockOnTabHidden',
  'restrictPasswordAccessToAdmins',
  'stepUpForReveal',
  'stepUpValidityMinutes',
  'deviceTrustEnabled',
  'csrfEnabled',
  'emergencyLockActive',
  'emergencyLockMessage',
] as const satisfies readonly (keyof SecuritySettings)[];

/** The subset of policy a signed-in client is told about. */
export type ClientSecuritySettings = Pick<
  SecuritySettings,
  (typeof CLIENT_VISIBLE_SETTING_KEYS)[number]
>;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Is `key` a real setting? Narrows an untrusted string from a request body. */
export function isSecuritySettingKey(key: string): key is keyof SecuritySettings {
  return Object.prototype.hasOwnProperty.call(SECURITY_SETTING_DEFINITIONS, key);
}

export interface SettingValidationError {
  key: string;
  message: string;
}

/**
 * Coerce and check one value against its definition.
 *
 * Returns the normalised value, or an error. The server calls this on every
 * incoming patch; the client calls it to show the problem before submitting.
 * Integers are truncated rather than rejected, because a browser number input
 * can legitimately produce `15.0`.
 */
export function validateSettingValue(
  key: keyof SecuritySettings,
  value: unknown,
): { ok: true; value: SecuritySettings[keyof SecuritySettings] } | { ok: false; error: string } {
  const definition = SECURITY_SETTING_DEFINITIONS[key];

  switch (definition.type) {
    case 'boolean': {
      if (typeof value !== 'boolean') return { ok: false, error: 'Must be true or false.' };
      return { ok: true, value };
    }

    case 'integer': {
      const numeric = typeof value === 'number' ? value : Number(value);
      if (!Number.isFinite(numeric)) return { ok: false, error: 'Must be a number.' };

      const truncated = Math.trunc(numeric);
      const min = definition.min ?? 0;
      const max = definition.max ?? Number.MAX_SAFE_INTEGER;

      if (truncated < min || truncated > max) {
        return { ok: false, error: `Must be between ${min} and ${max}.` };
      }
      return { ok: true, value: truncated };
    }

    case 'enum': {
      if (typeof value !== 'string') return { ok: false, error: 'Must be one of the choices.' };
      const allowed = definition.options?.map((option) => option.value) ?? [];
      if (!allowed.includes(value)) {
        return { ok: false, error: `Must be one of: ${allowed.join(', ')}.` };
      }
      return { ok: true, value: value as SecuritySettings[keyof SecuritySettings] };
    }

    case 'string': {
      if (typeof value !== 'string') return { ok: false, error: 'Must be text.' };
      const limit = definition.maxLength ?? 1000;
      if (value.length > limit) return { ok: false, error: `Must be at most ${limit} characters.` };
      return { ok: true, value };
    }
  }
}

/**
 * Cross-field checks that a per-key validator cannot see.
 *
 * These are the combinations that are individually valid and jointly absurd -
 * an idle timeout that can never fire, a warning longer than the idle period it
 * warns about. Returned as a list so the UI can mark every bad field at once.
 */
export function validateSettingsCoherence(
  settings: SecuritySettings,
): readonly SettingValidationError[] {
  const errors: SettingValidationError[] = [];

  // Idle timeout longer than the absolute timeout means the idle setting can
  // never fire - it looks configured but does nothing.
  if (settings.sessionIdleTimeoutMinutes > settings.sessionAbsoluteTimeoutHours * 60) {
    errors.push({
      key: 'sessionIdleTimeoutMinutes',
      message: 'Idle timeout exceeds the absolute timeout, so it would never take effect.',
    });
  }

  // An input-idle sign-out longer than the session idle timeout never fires:
  // the session has already gone.
  if (settings.vaultAutoLockMinutes > settings.sessionIdleTimeoutMinutes) {
    errors.push({
      key: 'vaultAutoLockMinutes',
      message: 'The session would already have timed out by then.',
    });
  }

  /*
   * Only meaningful while auto-lock is actually on.
   *
   * With `vaultAutoLockMinutes: 0` - never, the default - the right-hand
   * side is zero, so any warning at all "exceeded" it and every settings write
   * in the product was rejected with a message about a warning nobody would
   * ever see. There is no warning to mis-time when nothing locks.
   */
  if (
    settings.vaultAutoLockMinutes > 0 &&
    settings.vaultAutoLockWarningSeconds > settings.vaultAutoLockMinutes * 60
  ) {
    errors.push({
      key: 'vaultAutoLockWarningSeconds',
      message: 'The warning would appear before the idle period even starts.',
    });
  }

  if (settings.emergencyLockActive && settings.emergencyLockMessage.trim().length === 0) {
    errors.push({
      key: 'emergencyLockMessage',
      message: 'Say something. A blank screen during a lockdown reads as an outage.',
    });
  }

  return errors;
}

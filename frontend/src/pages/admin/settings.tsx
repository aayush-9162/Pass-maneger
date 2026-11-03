/**
 * Security policy.
 *
 * ## Why this page renders itself
 *
 * Every control here is generated from `SECURITY_SETTING_DEFINITIONS` in
 * `@passm/shared` - the same object the server validates against. Adding a
 * setting is one entry there and it appears here, validated, labelled, and with
 * its enforcement honestly described. A hand-written form would drift from the
 * validator within a phase, and the drift would be silent: a control that saves
 * a value the server ignores.
 *
 * ## Honesty about enforcement
 *
 * Settings declare where they are enforced. A `client` setting is a preference
 * that the browser honours and a patched client need not - clipboard clearing
 * and idle auto-lock are like this. Those are badged, because an administrator
 * who believes the server polices what a browser does with its own memory has
 * been misled by the interface.
 *
 * ## Guardrails
 *
 * Dangerous settings (the emergency lock, IP enforcement, mandatory device
 * approval) ask for confirmation and state the specific consequence. Changes are
 * staged locally and saved as one patch, so an administrator can see everything
 * they are about to change before committing - and so a half-applied policy
 * cannot result from a dropped connection mid-edit.
 */

import {
  AlertTriangle,
  Check,
  Info,
  Loader2,
  Lock,
  Monitor,
  RotateCcw,
  Save,
  Server,
  ShieldAlert,
} from 'lucide-react';
import * as React from 'react';

import {
  SECURITY_SETTING_DEFINITIONS,
  SETTING_CATEGORY_META,
  validateSettingValue,
  validateSettingsCoherence,
  type SecuritySettings,
  type SettingCategory,
  type SettingDefinition,
} from '@passm/shared';

import { Feedback, PageHeader, messageOf, useAsyncData } from '@/components/admin/admin-kit';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Textarea } from '@/components/ui/textarea';
import { api } from '@/lib/api-client';
import { useStepUp } from '@/lib/step-up-context';
import { formatDateTime } from '@/lib/format';
import { cn } from '@/lib/utils';

type SettingKey = keyof SecuritySettings;
type SettingValue = SecuritySettings[SettingKey];

const CATEGORY_ORDER = (Object.keys(SETTING_CATEGORY_META) as SettingCategory[]).sort(
  (a, b) => SETTING_CATEGORY_META[a].order - SETTING_CATEGORY_META[b].order,
);

/** Keys grouped by category, in schema declaration order. */
const KEYS_BY_CATEGORY = CATEGORY_ORDER.reduce<Record<string, SettingKey[]>>((map, category) => {
  map[category] = (Object.keys(SECURITY_SETTING_DEFINITIONS) as SettingKey[]).filter(
    (key) => SECURITY_SETTING_DEFINITIONS[key].category === category,
  );
  return map;
}, {});

/** Badge explaining where a setting is actually enforced. */
function EnforcementBadge({
  definition,
}: {
  definition: SettingDefinition;
}): React.ReactElement | null {
  if (definition.enforcement === 'server') return null;

  const clientOnly = definition.enforcement === 'client';

  return (
    <span
      title={
        clientOnly
          ? 'Applied by the browser. A modified client can ignore it, so treat this as a safety rail rather than a guarantee.'
          : 'Checked by the browser for a fast error, and enforced again by the server.'
      }
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[10px] font-medium',
        clientOnly ? 'bg-warning/15 text-warning' : 'bg-secondary text-muted-foreground',
      )}
    >
      {clientOnly ? <Monitor className="size-2.5" aria-hidden /> : <Server className="size-2.5" aria-hidden />}
      {clientOnly ? 'browser only' : 'both'}
    </span>
  );
}

function SettingRow({
  settingKey,
  definition,
  value,
  original,
  locked,
  error,
  onChange,
  onReset,
}: {
  settingKey: SettingKey;
  definition: SettingDefinition;
  value: SettingValue;
  original: SettingValue;
  locked: boolean;
  error: string | undefined;
  onChange: (key: SettingKey, value: SettingValue) => void;
  onReset: (key: SettingKey) => void;
}): React.ReactElement {
  const inputId = `setting-${settingKey}`;
  const dirty = value !== original;

  return (
    <div
      className={cn(
        'grid gap-3 border-b py-4 last:border-b-0 sm:grid-cols-[1fr_16rem]',
        dirty && 'bg-primary/[0.03]',
      )}
    >
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor={inputId} className="text-sm font-medium">
            {definition.label}
          </label>
          <EnforcementBadge definition={definition} />
          {definition.dangerous && (
            <span className="inline-flex items-center gap-1 rounded-full bg-destructive/15 px-1.5 py-0.5 text-[10px] font-medium text-destructive">
              <AlertTriangle className="size-2.5" aria-hidden />
              high impact
            </span>
          )}
          {locked && (
            <span
              title="Pinned by the server environment. Change SECURITY_SETTINGS_LOCK to release it."
              className="inline-flex items-center gap-1 rounded-full bg-secondary px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"
            >
              <Lock className="size-2.5" aria-hidden />
              pinned
            </span>
          )}
          {dirty && (
            <span className="rounded-full bg-primary/15 px-1.5 py-0.5 text-[10px] font-medium text-primary">
              unsaved
            </span>
          )}
        </div>

        <p className="text-xs leading-relaxed text-muted-foreground">{definition.description}</p>

        {definition.zeroMeans && (
          <p className="text-xs text-muted-foreground">
            <span className="font-medium">0</span> means {definition.zeroMeans}.
          </p>
        )}

        {error && <p className="text-xs font-medium text-destructive">{error}</p>}
      </div>

      <div className="flex items-start gap-2 sm:justify-end">
        {definition.type === 'boolean' ? (
          <label className="flex cursor-pointer items-center gap-2 text-sm">
            <input
              id={inputId}
              type="checkbox"
              disabled={locked}
              checked={value === true}
              onChange={(event) => onChange(settingKey, event.target.checked)}
              className="size-4 rounded border-input disabled:opacity-50"
            />
            <span className="text-muted-foreground">{value === true ? 'On' : 'Off'}</span>
          </label>
        ) : definition.type === 'enum' ? (
          <Select
            id={inputId}
            disabled={locked}
            value={String(value)}
            onChange={(event) => onChange(settingKey, event.target.value)}
            className="w-full"
          >
            {definition.options?.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        ) : definition.type === 'integer' ? (
          <div className="flex w-full items-center gap-2">
            <Input
              id={inputId}
              type="number"
              inputMode="numeric"
              disabled={locked}
              min={definition.min}
              max={definition.max}
              value={String(value)}
              onChange={(event) => onChange(settingKey, Number(event.target.value))}
              className="w-full"
              aria-invalid={error !== undefined}
            />
            {definition.unit && (
              <span className="shrink-0 text-xs text-muted-foreground">{definition.unit}</span>
            )}
          </div>
        ) : (
          <Textarea
            id={inputId}
            disabled={locked}
            value={String(value)}
            maxLength={definition.maxLength}
            onChange={(event) => onChange(settingKey, event.target.value)}
            className="w-full"
            rows={3}
          />
        )}

        {dirty && (
          <Button
            variant="ghost"
            size="icon"
            title="Discard this change"
            onClick={() => onReset(settingKey)}
          >
            <RotateCcw className="size-3.5" aria-hidden />
          </Button>
        )}
      </div>
    </div>
  );
}

export default function AdminSettingsPage(): React.ReactElement {
  const [category, setCategory] = React.useState<SettingCategory>(CATEGORY_ORDER[0]!);
  const [draft, setDraft] = React.useState<Partial<SecuritySettings>>({});
  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = React.useState<Record<string, string>>({});
  const [saving, setSaving] = React.useState(false);
  const [confirming, setConfirming] = React.useState(false);
  const [reason, setReason] = React.useState('');

  const { runWithStepUp } = useStepUp();

  const { data, error: loadError, reload } = useAsyncData(() => api.getSecuritySettings(), [notice]);

  const settings = data?.settings ?? null;
  const lockedKeys = React.useMemo(
    () => new Set(data?.lockedKeys ?? []),
    [data?.lockedKeys],
  );
  const entries = React.useMemo(
    () => new Map((data?.entries ?? []).map((entry) => [entry.key, entry])),
    [data?.entries],
  );

  /** The settings as they would be after applying the draft. */
  const merged: SecuritySettings | null = React.useMemo(
    () => (settings ? { ...settings, ...draft } : null),
    [settings, draft],
  );

  const dirtyKeys = Object.keys(draft) as SettingKey[];

  const change = (key: SettingKey, value: SettingValue): void => {
    setDraft((current) => {
      const next = { ...current, [key]: value };
      // Setting a value back to what the server holds is not a change.
      if (settings && settings[key] === value) delete next[key];
      return next;
    });

    // Validate immediately so the error appears next to the field the moment it
    // becomes wrong, rather than after a round trip.
    const result = validateSettingValue(key, value);
    setFieldErrors((current) => {
      const next = { ...current };
      if (result.ok) delete next[key];
      else next[key] = result.error;
      return next;
    });
  };

  const discard = (key: SettingKey): void => {
    setDraft((current) => {
      const next = { ...current };
      delete next[key];
      return next;
    });
    setFieldErrors((current) => {
      const next = { ...current };
      delete next[key];
      return next;
    });
  };

  /** Cross-field problems, recomputed on every keystroke. */
  const coherenceErrors = React.useMemo(
    () => (merged ? validateSettingsCoherence(merged) : []),
    [merged],
  );

  const blocking = Object.keys(fieldErrors).length > 0 || coherenceErrors.length > 0;

  /** Does anything being changed warrant an explicit confirmation? */
  const dangerousChanges = dirtyKeys.filter(
    (key) => SECURITY_SETTING_DEFINITIONS[key].dangerous,
  );

  const save = async (): Promise<void> => {
    if (dirtyKeys.length === 0) return;

    setSaving(true);
    setError(null);
    setFieldErrors({});

    try {
      // Wrapped so a STEP_UP_REQUIRED refusal raises the master-password dialog
      // and replays the save, rather than surfacing as a confusing error.
      const result = await runWithStepUp('settings_change', () =>
        api.updateSecuritySettings(draft, reason.trim() || undefined),
      );

      setDraft({});
      setReason('');
      setConfirming(false);
      setNotice(result.message);
      await reload();
    } catch (caught) {
      const details = (caught as { details?: { field: string; message: string }[] }).details;
      if (details?.length) {
        setFieldErrors(
          Object.fromEntries(details.map((detail) => [detail.field, detail.message])),
        );
        setError('Some settings could not be saved. See the fields marked below.');
      } else {
        setError(messageOf(caught, 'Could not save those settings.'));
      }
    } finally {
      setSaving(false);
    }
  };

  const resetAll = async (): Promise<void> => {
    setSaving(true);
    setError(null);
    try {
      const result = await runWithStepUp('settings_change', () => api.resetSecuritySettings());
      setDraft({});
      setNotice(result.message);
      await reload();
    } catch (caught) {
      setError(messageOf(caught, 'Could not reset the settings.'));
    } finally {
      setSaving(false);
    }
  };

  if (data === null) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  const meta = SETTING_CATEGORY_META[category];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security policy"
        description="Applies to everyone, immediately. Changes are recorded in the audit trail with who made them and what they were before."
        actions={
          <>
            <Button variant="outline" onClick={() => void resetAll()} disabled={saving}>
              <RotateCcw aria-hidden />
              Reset all to defaults
            </Button>
            <Button
              onClick={() => (dangerousChanges.length > 0 ? setConfirming(true) : void save())}
              disabled={saving || dirtyKeys.length === 0 || blocking}
            >
              {saving ? <Loader2 className="animate-spin" aria-hidden /> : <Save aria-hidden />}
              Save{dirtyKeys.length > 0 ? ` ${dirtyKeys.length} change${dirtyKeys.length === 1 ? '' : 's'}` : ''}
            </Button>
          </>
        }
      />

      <Feedback notice={notice} error={error ?? loadError} onDismiss={() => setNotice(null)} />

      {!data.tlsActive && (
        <Alert>
          <Info aria-hidden />
          <AlertTitle>This deployment serves plain HTTP</AlertTitle>
          <AlertDescription>
            Passwords travel to the browser in plaintext when someone reveals, copies or fills
            one, so on plain HTTP anyone on the network path can read them, along with session
            cookies. Put TLS in front of this host. Settings that only mean something over TLS are
            marked.
          </AlertDescription>
        </Alert>
      )}

      {coherenceErrors.length > 0 && (
        <Alert variant="destructive">
          <AlertTriangle aria-hidden />
          <AlertTitle>These settings contradict each other</AlertTitle>
          <AlertDescription>
            <ul className="mt-1 list-disc space-y-1 pl-4">
              {coherenceErrors.map((problem) => (
                <li key={problem.key}>
                  <span className="font-medium">
                    {SECURITY_SETTING_DEFINITIONS[problem.key as SettingKey]?.label ?? problem.key}
                  </span>
                  : {problem.message}
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}

      {/* Category navigation. A scroller on small screens, a row of tabs above. */}
      <div className="flex gap-1 overflow-x-auto border-b pb-px" role="tablist">
        {CATEGORY_ORDER.map((option) => {
          const dirtyInCategory = dirtyKeys.filter(
            (key) => SECURITY_SETTING_DEFINITIONS[key].category === option,
          ).length;

          return (
            <button
              key={option}
              type="button"
              role="tab"
              aria-selected={category === option}
              onClick={() => setCategory(option)}
              className={cn(
                'flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition-colors',
                category === option
                  ? 'border-primary font-medium text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground',
              )}
            >
              {SETTING_CATEGORY_META[option].label}
              {dirtyInCategory > 0 && (
                <span className="rounded-full bg-primary px-1.5 text-[10px] font-medium text-primary-foreground">
                  {dirtyInCategory}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{meta.label}</CardTitle>
          <p className="text-sm text-muted-foreground">{meta.description}</p>
        </CardHeader>
        <CardContent className="pt-0">
          {(KEYS_BY_CATEGORY[category] ?? []).map((key) => (
            <SettingRow
              key={key}
              settingKey={key}
              definition={SECURITY_SETTING_DEFINITIONS[key]}
              value={merged ? merged[key] : ''}
              original={settings ? settings[key] : ''}
              locked={lockedKeys.has(key)}
              error={fieldErrors[key]}
              onChange={change}
              onReset={discard}
            />
          ))}
        </CardContent>
      </Card>

      {/* Provenance for anything customised in this category. */}
      {(KEYS_BY_CATEGORY[category] ?? []).some((key) => entries.get(key)?.isDefault === false) && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Changed from the default</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5 text-xs text-muted-foreground">
            {(KEYS_BY_CATEGORY[category] ?? [])
              .map((key) => entries.get(key))
              .filter((entry) => entry && !entry.isDefault)
              .map((entry) => (
                <p key={entry!.key}>
                  <span className="text-foreground">
                    {SECURITY_SETTING_DEFINITIONS[entry!.key].label}
                  </span>{' '}
                  — set by {entry!.updatedByName ?? 'an administrator'}
                  {entry!.updatedAt ? ` on ${formatDateTime(entry!.updatedAt)}` : ''}
                </p>
              ))}
          </CardContent>
        </Card>
      )}

      {/* Confirmation for high-impact changes. */}
      <Dialog open={confirming} onOpenChange={(open) => !open && setConfirming(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm these changes</DialogTitle>
            <DialogDescription>
              {dangerousChanges.length} of the {dirtyKeys.length} change
              {dirtyKeys.length === 1 ? '' : 's'} can lock people out. Read them before saving.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            {dangerousChanges.map((key) => (
              <Alert key={key} variant="destructive">
                <ShieldAlert aria-hidden />
                <AlertTitle>{SECURITY_SETTING_DEFINITIONS[key].label}</AlertTitle>
                <AlertDescription>
                  {String(settings?.[key])} → <strong>{String(draft[key])}</strong>.{' '}
                  {SECURITY_SETTING_DEFINITIONS[key].description}
                </AlertDescription>
              </Alert>
            ))}

            <div className="space-y-2">
              <label htmlFor="change-reason" className="text-sm font-medium">
                Reason (recorded in the audit trail)
              </label>
              <Textarea
                id="change-reason"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="Tightening the lockout policy after the incident on the 14th."
                maxLength={300}
              />
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirming(false)} disabled={saving}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void save()} disabled={saving}>
              {saving ? <Loader2 className="animate-spin" aria-hidden /> : <Check aria-hidden />}
              Save anyway
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * IP allow list.
 *
 * ## The failure mode this is designed around
 *
 * An allow list is the control most likely to cause a self-inflicted outage. An
 * administrator adds `192.168.1.0/24`, switches enforcement on, and discovers
 * that half the office is on `192.168.2.0/24` and the VPN pool is somewhere else
 * entirely. Everyone is locked out, including the administrator, and the only
 * fix is a database edit over SSH.
 *
 * Four things guard against that:
 *
 *  1. **An `audit` mode.** Nothing is blocked; every request that *would* be
 *     blocked is logged. An administrator runs this for a week, reads the log,
 *     and finds the ranges they forgot.
 *  2. **Administrators are exempt by default.** `ipAllowListAppliesToAdmins`
 *     starts off, so there is always a way back in. Turning it on is stricter
 *     and the settings page says plainly what it costs.
 *  3. **An empty list never blocks.** A list with no rules means "not
 *     configured", not "deny everyone". Enforcing an empty list would be an
 *     immediate total outage.
 *  4. **Loopback is always allowed.** Otherwise a locked-out operator cannot
 *     even fix it from the server console.
 *
 * ## Scoping
 *
 * Rules are global, per-user, or per-role. They combine as a union - any
 * matching rule admits the caller - because an allow list is an allow list. The
 * subtlety is that a user with a *personal* rule is evaluated against global
 * rules too, so an administrator does not have to re-state the office range for
 * every remote worker.
 */

import { AUDIT_ACTIONS, IP_RULE_SCOPE, parseCidr, parseIp, ipInCidr, type IpCheckResult, type IpRule, type ParsedCidr } from '@passm/shared';

import { logger } from '../config/logger';
import { ipRuleRepository } from '../repositories/ip-rule.repository';
import type { AuthContext, RequestContext } from '../types/auth.types';
import { auditService } from './audit.service';
import { securitySettingsService } from './security-settings.service';

/**
 * How long the compiled rule set is trusted.
 *
 * Longer than the settings TTL because rules change far less often than
 * settings, and compiling CIDRs costs more than reading a boolean.
 */
const CACHE_TTL_MS = 15_000;

/** A rule with its CIDR already parsed, so matching is not re-parsing text. */
interface CompiledRule {
  rule: IpRule;
  cidr: ParsedCidr;
}

interface RuleCache {
  rules: CompiledRule[];
  loadedAt: number;
}

let cache: RuleCache | null = null;
let inFlight: Promise<RuleCache> | null = null;

/**
 * Addresses that are always permitted.
 *
 * Loopback only. Without this an operator who mis-configures the list cannot
 * reach the API from the server itself to fix it, and health checks from a local
 * process supervisor start failing, which typically ends with the orchestrator
 * killing a perfectly healthy process.
 */
const ALWAYS_ALLOWED: readonly ParsedCidr[] = ['127.0.0.0/8', '::1/128']
  .map((cidr) => parseCidr(cidr))
  .filter((cidr): cidr is ParsedCidr => cidr !== null);

async function loadRules(): Promise<RuleCache> {
  const rules = await ipRuleRepository.findEnabled();
  const compiled: CompiledRule[] = [];

  for (const rule of rules) {
    const cidr = parseCidr(rule.cidr);
    if (!cidr) {
      // Should be impossible - the DTO validates on write - but a hand-edited
      // row would otherwise silently widen or narrow access.
      logger.error('IP rule has an unparseable CIDR and is being ignored', {
        ruleId: rule.id,
        cidr: rule.cidr,
      });
      continue;
    }
    compiled.push({ rule, cidr });
  }

  return { rules: compiled, loadedAt: Date.now() };
}

async function getRules(): Promise<CompiledRule[]> {
  if (cache && Date.now() - cache.loadedAt < CACHE_TTL_MS) return cache.rules;
  if (inFlight) return (await inFlight).rules;

  inFlight = loadRules()
    .then((loaded) => {
      cache = loaded;
      return loaded;
    })
    .catch((error: unknown) => {
      // Fail *open* here, unlike CSRF. An unreadable rule list must not lock
      // everyone out: the list is an additional restriction on top of
      // authentication, not the thing that establishes identity. A database
      // blip should degrade to "authenticated users get in", not "nobody does".
      logger.error('Could not load IP rules; allowing access this interval', { error });
      return cache ?? { rules: [], loadedAt: Date.now() };
    })
    .finally(() => {
      inFlight = null;
    });

  return (await inFlight).rules;
}

/** Rules that apply to a given caller. */
function applicableTo(rules: readonly CompiledRule[], auth: AuthContext | null): CompiledRule[] {
  return rules.filter(({ rule }) => {
    if (rule.scope === IP_RULE_SCOPE.GLOBAL) return true;
    if (!auth) return false;
    if (rule.scope === IP_RULE_SCOPE.USER) return rule.userId === auth.userId;
    if (rule.scope === IP_RULE_SCOPE.ROLE) return rule.roleName === auth.role;
    return false;
  });
}

export interface IpDecision {
  allowed: boolean;
  /** True when the caller would have been blocked under `enforce`. */
  wouldBlock: boolean;
  mode: 'off' | 'audit' | 'enforce';
  matchedRuleId: string | null;
  reason: string;
}

export const ipAccessService = {
  /**
   * Decide whether a caller may proceed.
   *
   * Never throws: the middleware turns a decision into a response, and this
   * separation keeps the policy testable without an Express request.
   */
  async evaluate(ip: string, auth: AuthContext | null): Promise<IpDecision> {
    const settings = await securitySettingsService.getSettings();
    const mode = settings.ipAllowListMode;

    if (mode === 'off') {
      return { allowed: true, wouldBlock: false, mode, matchedRuleId: null, reason: 'The allow list is switched off.' };
    }

    const parsed = parseIp(ip);
    if (!parsed) {
      // An address we cannot parse cannot be matched against anything. Allowing
      // it is the lesser evil: the alternative is that a proxy sending an
      // unusual format blocks the entire deployment.
      logger.warn('Could not parse the client address for the allow list', { ip });
      return {
        allowed: true,
        wouldBlock: false,
        mode,
        matchedRuleId: null,
        reason: 'The caller address could not be parsed, so the list was not applied.',
      };
    }

    for (const cidr of ALWAYS_ALLOWED) {
      if (ipInCidr(parsed, cidr)) {
        return { allowed: true, wouldBlock: false, mode, matchedRuleId: null, reason: 'Loopback is always permitted.' };
      }
    }

    // An administrator bypass, unless explicitly disabled. This is the escape
    // hatch that makes the feature safe to turn on.
    if (!settings.ipAllowListAppliesToAdmins && auth?.role === 'admin') {
      return {
        allowed: true,
        wouldBlock: false,
        mode,
        matchedRuleId: null,
        reason: 'Administrators are exempt from the allow list.',
      };
    }

    const rules = await getRules();
    const applicable = applicableTo(rules, auth);

    // No rules configured means "not set up", never "deny everyone".
    if (applicable.length === 0) {
      return {
        allowed: true,
        wouldBlock: false,
        mode,
        matchedRuleId: null,
        reason: 'No rules apply to this caller, so nothing is restricted.',
      };
    }

    for (const { rule, cidr } of applicable) {
      if (!ipInCidr(parsed, cidr)) continue;

      // Telemetry only; never awaited on the request path.
      void ipRuleRepository.recordMatch(rule.id).catch(() => undefined);

      return {
        allowed: true,
        wouldBlock: false,
        mode,
        matchedRuleId: rule.id,
        reason: `Matched "${rule.label}" (${rule.cidr}).`,
      };
    }

    return {
      allowed: mode !== 'enforce',
      wouldBlock: true,
      mode,
      matchedRuleId: null,
      reason: `${parsed.normalized} is not covered by any of the ${applicable.length} rule(s) that apply.`,
    };
  },

  /**
   * Evaluate and record. Used by the middleware.
   *
   * In `audit` mode the event is logged and the request proceeds, which is the
   * entire point of that mode: an administrator gets a week of evidence before
   * anything breaks.
   */
  async evaluateAndAudit(
    ip: string,
    auth: AuthContext | null,
    context: RequestContext,
    path: string,
  ): Promise<IpDecision> {
    const decision = await this.evaluate(ip, auth);

    if (decision.wouldBlock) {
      await auditService.recordFailure({
        action: decision.allowed ? AUDIT_ACTIONS.IP_WOULD_BLOCK : AUDIT_ACTIONS.IP_BLOCKED,
        actorUserId: auth?.userId ?? null,
        context,
        isSharedResource: true,
        metadata: { path, mode: decision.mode, reason: decision.reason },
      });
    }

    return decision;
  },

  /** Every rule, for the admin panel. */
  async listRules(): Promise<IpRule[]> {
    return ipRuleRepository.findAll();
  },

  /**
   * "Would this address get in?" - the tester in the admin panel.
   *
   * Deliberately does *not* short-circuit on `mode === 'off'`, which is what
   * {@link evaluate} does on the request path. The entire purpose of the tester
   * is to answer the question **before** enforcement is switched on: an
   * administrator who is told "the list is off, you're fine" has learnt nothing
   * about whether turning it on will lock them out.
   *
   * So this always performs the match, and reports the effect the *current* mode
   * would produce. The matching logic is shared with enforcement rather than
   * reimplemented, so the preview cannot disagree with reality.
   */
  async check(ip: string, auth: AuthContext | null): Promise<IpCheckResult> {
    const settings = await securitySettingsService.getSettings();
    const mode = settings.ipAllowListMode;

    const parsed = parseIp(ip);
    if (!parsed) {
      return {
        ip,
        allowed: true,
        matchedRuleId: null,
        matchedCidr: null,
        effect: 'allowed',
        reason: 'That address could not be parsed, so no rule can match it.',
      };
    }

    for (const cidr of ALWAYS_ALLOWED) {
      if (ipInCidr(parsed, cidr)) {
        return {
          ip: parsed.normalized,
          allowed: true,
          matchedRuleId: null,
          matchedCidr: null,
          effect: 'allowed',
          reason: 'Loopback is always permitted, whatever the rules say.',
        };
      }
    }

    const rules = await getRules();
    const applicable = applicableTo(rules, auth);

    for (const { rule, cidr } of applicable) {
      if (!ipInCidr(parsed, cidr)) continue;

      return {
        ip: parsed.normalized,
        allowed: true,
        matchedRuleId: rule.id,
        matchedCidr: rule.cidr,
        effect: 'allowed',
        reason: `Matched "${rule.label}" (${rule.cidr}).`,
      };
    }

    // Nothing matched. What that *means* depends on the mode and on who is
    // asking, and the tester has to spell that out rather than just saying no.
    if (applicable.length === 0) {
      return {
        ip: parsed.normalized,
        allowed: true,
        matchedRuleId: null,
        matchedCidr: null,
        effect: 'allowed',
        reason: 'No rules apply to this caller, so nothing is restricted.',
      };
    }

    const adminExempt = !settings.ipAllowListAppliesToAdmins && auth?.role === 'admin';

    if (adminExempt) {
      return {
        ip: parsed.normalized,
        allowed: true,
        matchedRuleId: null,
        matchedCidr: null,
        effect: 'allowed',
        reason:
          'No rule covers this address, but administrators are currently exempt from the allow list.',
      };
    }

    const reason = `${parsed.normalized} is not covered by any of the ${applicable.length} rule(s) that apply.`;

    if (mode === 'enforce') {
      return {
        ip: parsed.normalized,
        allowed: false,
        matchedRuleId: null,
        matchedCidr: null,
        effect: 'blocked',
        reason,
      };
    }

    return {
      ip: parsed.normalized,
      allowed: true,
      matchedRuleId: null,
      matchedCidr: null,
      effect: 'would-block',
      reason:
        mode === 'off'
          ? `${reason} The list is currently off, so nothing is blocked - but this address would be refused if you switch to enforce.`
          : `${reason} Audit mode is on, so it is being logged rather than blocked.`,
    };
  },

  /** Drop the compiled cache after a rule changes, so the effect is immediate. */
  invalidateCache(): void {
    cache = null;
  },
};

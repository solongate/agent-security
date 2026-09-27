import type { PolicyRule, PolicySet } from '../core/index.js';
import { UNSAFE_CONFIGURATION_WARNINGS } from '../core/index.js';

export interface SecurityWarning {
  readonly level: 'WARNING' | 'CRITICAL';
  readonly code: string;
  readonly message: string;
  readonly ruleId?: string;
  readonly recommendation: string;
}

/** Analyzes a policy set and returns security warnings. Pure function. */
export function analyzeSecurityWarnings(
  policySet: PolicySet,
): readonly SecurityWarning[] {
  const warnings: SecurityWarning[] = [];

  for (const rule of policySet.rules) {
    warnings.push(...analyzeRuleWarnings(rule));
  }

  const allowRules = policySet.rules.filter(
    (r) => r.effect === 'ALLOW' && r.enabled,
  );
  // An ALLOW rule with no command/path/file/url constraints permits everything.
  const hasNoConstraint = (r: PolicyRule): boolean => {
    const groups = ['commandConstraints', 'pathConstraints', 'filenameConstraints', 'urlConstraints'] as const;
    return !groups.some((g) => {
      const c = r[g] as { allowed?: unknown[]; denied?: unknown[] } | undefined;
      return c ? (c.allowed?.length ?? 0) + (c.denied?.length ?? 0) > 0 : false;
    });
  };
  const wildcardAllows = allowRules.filter(hasNoConstraint);

  if (wildcardAllows.length > 0) {
    warnings.push({
      level: 'CRITICAL',
      code: 'WILDCARD_ALLOW',
      message: UNSAFE_CONFIGURATION_WARNINGS.WILDCARD_ALLOW,
      recommendation:
        'Add command or path constraints so an ALLOW rule does not permit everything.',
    });
  }

  return warnings;
}

function analyzeRuleWarnings(rule: PolicyRule): SecurityWarning[] {
  const warnings: SecurityWarning[] = [];

  if (rule.effect === 'ALLOW' && rule.minimumTrustLevel === 'UNTRUSTED') {
    warnings.push({
      level: 'CRITICAL',
      code: 'ALLOW_UNTRUSTED',
      message: `Rule "${rule.id}" allows execution for UNTRUSTED requests. Unverified LLM requests can execute tools.`,
      ruleId: rule.id,
      recommendation:
        'Set minimumTrustLevel to VERIFIED or higher for ALLOW rules.',
    });
  }

  if (rule.effect === 'ALLOW' && (!rule.permission || rule.permission === 'EXECUTE')) {
    warnings.push({
      level: 'WARNING',
      code: 'ALLOW_EXECUTE',
      message: UNSAFE_CONFIGURATION_WARNINGS.EXECUTE_WITHOUT_REVIEW,
      ruleId: rule.id,
      recommendation:
        'Ensure EXECUTE permissions are intentional and scoped to specific tools.',
    });
  }

  return warnings;
}

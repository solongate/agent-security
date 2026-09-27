import { PolicyRuleSchema, PolicySetSchema } from '../core/index.js';
import {
  MAX_RULES_PER_POLICY_SET,
  UNSAFE_CONFIGURATION_WARNINGS,
} from '../core/index.js';

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
  readonly warnings: readonly string[];
}

export function validatePolicyRule(input: unknown): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const result = PolicyRuleSchema.safeParse(input);
  if (!result.success) {
    return {
      valid: false,
      errors: result.error.errors.map(
        (e) => `${e.path.join('.')}: ${e.message}`,
      ),
      warnings: [],
    };
  }

  const rule = result.data;

  if (rule.toolPattern === '*' && rule.effect === 'ALLOW') {
    warnings.push(UNSAFE_CONFIGURATION_WARNINGS.WILDCARD_ALLOW);
  }

  if (rule.minimumTrustLevel === 'TRUSTED') {
    warnings.push(UNSAFE_CONFIGURATION_WARNINGS.TRUSTED_LEVEL_EXTERNAL);
  }

  if (!rule.permission || rule.permission === 'EXECUTE') {
    warnings.push(UNSAFE_CONFIGURATION_WARNINGS.EXECUTE_WITHOUT_REVIEW);
  }

  return { valid: true, errors, warnings };
}

export function validatePolicySet(input: unknown): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const result = PolicySetSchema.safeParse(input);
  if (!result.success) {
    return {
      valid: false,
      errors: result.error.errors.map(
        (e) => `${e.path.join('.')}: ${e.message}`,
      ),
      warnings: [],
    };
  }

  const policySet = result.data;

  if (policySet.rules.length > MAX_RULES_PER_POLICY_SET) {
    errors.push(
      `Policy set exceeds maximum of ${MAX_RULES_PER_POLICY_SET} rules`,
    );
  }

  const ruleIds = new Set<string>();
  for (const rule of policySet.rules) {
    if (ruleIds.has(rule.id)) {
      errors.push(`Duplicate rule ID: "${rule.id}"`);
    }
    ruleIds.add(rule.id);
  }

  for (const rule of policySet.rules) {
    // Check warnings directly — rules are already parsed by PolicySetSchema above
    if (rule.toolPattern === '*' && rule.effect === 'ALLOW') {
      warnings.push(UNSAFE_CONFIGURATION_WARNINGS.WILDCARD_ALLOW);
    }
    if (rule.minimumTrustLevel === 'TRUSTED') {
      warnings.push(UNSAFE_CONFIGURATION_WARNINGS.TRUSTED_LEVEL_EXTERNAL);
    }
    if (!rule.permission || rule.permission === 'EXECUTE') {
      warnings.push(UNSAFE_CONFIGURATION_WARNINGS.EXECUTE_WITHOUT_REVIEW);
    }
  }

  const hasDenyRule = policySet.rules.some((r) => r.effect === 'DENY');
  if (!hasDenyRule && policySet.rules.length > 0) {
    warnings.push(
      'Policy set contains only ALLOW rules. The default-deny fallback is the only protection.',
    );
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

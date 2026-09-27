import type {
  PolicySet,
  PolicyDecision,
  ExecutionRequest,
  PolicyEffect,
} from '../core/index.js';
import { DEFAULT_POLICY_EFFECT } from '../core/index.js';
import { ruleMatchesRequest } from './matcher.js';

/**
 * Evaluates a policy set against an execution request.
 *
 * Pure function: no side effects, no I/O, fully deterministic.
 *
 * Algorithm:
 * 1. Sort rules by priority (ascending - lower number = higher priority)
 * 2. Find the first matching rule
 * 3. If a rule matches, return its effect
 * 4. If no rule matches, return DENY (default-deny)
 */
export function evaluatePolicy(
  policySet: PolicySet,
  request: ExecutionRequest,
): PolicyDecision {
  const startTime = performance.now();

  // Always sort defensively — callers may not pre-sort
  const sortedRules = [...policySet.rules].sort((a, b) => a.priority - b.priority);

  for (const rule of sortedRules) {
    if (ruleMatchesRequest(rule, request)) {
      const endTime = performance.now();
      return {
        effect: rule.effect,
        matchedRule: rule,
        reason: `Matched rule "${rule.id}": ${rule.description}`,
        timestamp: new Date().toISOString(),
        evaluationTimeMs: endTime - startTime,
      };
    }
  }

  const endTime = performance.now();
  return {
    effect: DEFAULT_POLICY_EFFECT as PolicyEffect,
    matchedRule: null,
    reason: 'No matching policy rule found. Default action: DENY.',
    timestamp: new Date().toISOString(),
    evaluationTimeMs: endTime - startTime,
    metadata: {
      evaluatedRules: sortedRules.length,
      requestContext: {
        tool: request.toolName,
        arguments: Object.keys(request.arguments ?? {}),
      },
    },
  };
}

import { TrustEscalationError } from './errors.js';

/**
 * Trust levels in the SolonGate security model.
 *
 * Core threat model principle: LLMs are UNTRUSTED by default.
 * Trust is never assumed - it must be explicitly granted and is
 * always scoped to specific capabilities.
 *
 * UNTRUSTED: Default for all LLM-originated requests. No permissions.
 * VERIFIED: Passed schema validation and policy evaluation. May execute within granted scope.
 * TRUSTED: System-internal only. NEVER assignable to LLM-originated requests.
 */
export const TrustLevel = {
  UNTRUSTED: 'UNTRUSTED',
  VERIFIED: 'VERIFIED',
  TRUSTED: 'TRUSTED',
} as const;

export type TrustLevel = (typeof TrustLevel)[keyof typeof TrustLevel];

/**
 * Validates that a trust level is a legitimate enum value.
 * Prevents type confusion attacks where a string bypasses checks.
 */
export function isValidTrustLevel(value: unknown): value is TrustLevel {
  return (
    typeof value === 'string' &&
    Object.values(TrustLevel).includes(value as TrustLevel)
  );
}

/**
 * Asserts that a trust level transition is valid.
 * UNTRUSTED -> VERIFIED (via policy evaluation) is the only escalation path.
 * TRUSTED is never reachable from external requests.
 */
export function assertValidTransition(
  from: TrustLevel,
  to: TrustLevel,
): void {
  if (to === TrustLevel.TRUSTED) {
    throw new TrustEscalationError(
      'Cannot escalate to TRUSTED level. TRUSTED is reserved for system-internal operations.',
    );
  }
  if (from === TrustLevel.VERIFIED && to === TrustLevel.UNTRUSTED) {
    return; // Downgrade is always allowed (fail-safe)
  }
  if (from === TrustLevel.UNTRUSTED && to === TrustLevel.VERIFIED) {
    return; // Normal escalation via policy evaluation
  }
  if (from === to) {
    return; // No-op
  }
  throw new TrustEscalationError(
    `Invalid trust transition from ${from} to ${to}`,
  );
}

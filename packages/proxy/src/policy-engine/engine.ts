// Engine: main PolicyEngine class that loads, validates, and evaluates policy sets.
import type { PolicySet, PolicyDecision, PolicyEffect, ExecutionRequest } from '../core/index.js';
import { POLICY_EVALUATION_TIMEOUT_MS } from '../core/index.js';
import { validatePolicySet, type ValidationResult } from './validator.js';
import { analyzeSecurityWarnings, type SecurityWarning } from './warnings.js';
import { createDefaultDenyPolicySet } from './defaults.js';
import { PolicyStore, type PolicyVersion } from './policy-store.js';
import { OpaEvaluator } from './opa/opa-evaluator.js';
// The guard's own evaluator, shared rather than reimplemented — see
// hooks/policy-eval.mjs for why a second one would be a second set of answers.
import { evaluate as evaluateLocally } from '../../hooks/policy-eval.mjs';

// PolicyEngine is the primary interface for policy evaluation.
//
// TWO BACKENDS, AND THE LOCAL ONE IS THE FLOOR. OPA WASM decides when a bundle is
// loaded (NIST SP 800-207 PDP); otherwise the decision falls through to the SAME
// evaluator the guard hook uses.
//
// It used to fail CLOSED there instead — "there is no legacy/secondary engine" —
// and that was only survivable because a service compiled the bundle and served
// it. With no service the proxy loaded none and denied every call, which is not
// fail-safe, it is not working. The guard never had that problem: OPA is an
// optional upgrade there and the local evaluator is the primary path.
//
// The two agree about modes, which is the part that matters: a denylist allows
// what no rule forbids, and a whitelist refuses what no ALLOW rule matches.
export class PolicyEngine {
  private policySet: PolicySet;
  private readonly timeoutMs: number;
  private readonly store: PolicyStore | null;
  private opaEvaluator: OpaEvaluator | null = null;

  constructor(options?: {
    policySet?: PolicySet;
    timeoutMs?: number;
    store?: PolicyStore;
    wasmBundle?: BufferSource;
  }) {
    this.policySet = options?.policySet ?? createDefaultDenyPolicySet();
    this.timeoutMs = options?.timeoutMs ?? POLICY_EVALUATION_TIMEOUT_MS;
    this.store = options?.store ?? null;

    if (options?.wasmBundle) {
      this.opaEvaluator = new OpaEvaluator();
      // WASM loading is async; call loadWasmBundle() separately
      this._pendingWasm = options.wasmBundle;
    }
  }

  private _pendingWasm: BufferSource | null = null;

  // Initializes the OPA WASM evaluator if a bundle was provided.
  // Must be called before evaluate() when using OPA mode.
  async initOpa(): Promise<void> {
    if (this._pendingWasm) {
      this.opaEvaluator = new OpaEvaluator();
      await this.opaEvaluator.loadBundle(this._pendingWasm);
      this._pendingWasm = null;
    }
  }

  // Loads a pre-compiled OPA WASM bundle for evaluation.
  async loadWasmBundle(wasmBundle: BufferSource): Promise<void> {
    this.opaEvaluator = new OpaEvaluator();
    await this.opaEvaluator.loadBundle(wasmBundle);
    this._pendingWasm = null;
  }

  // Evaluates an execution request against the current policy set.
  // Never throws for denials - denial is a normal outcome, not an error.
  // OPA WASM is the only evaluator. If no WASM bundle is loaded, evaluation
  // fails CLOSED (default DENY) — there is no legacy fallback.
  evaluate(request: ExecutionRequest): PolicyDecision {
    const startTime = performance.now();

    let decision: PolicyDecision;

    if (this.opaEvaluator?.isReady()) {
      decision = this.opaEvaluator.evaluate(request);
    } else {
      // The guard's evaluator answers the REASON a call is refused, or null when
      // nothing in the policy forbids it. Null is not "a rule allowed this" — in
      // denylist mode nothing matching is the normal outcome, and in whitelist
      // mode a call matching no ALLOW rule comes back with a reason.
      const reason = evaluateLocally(
        this.policySet as unknown as { mode?: string; rules?: readonly unknown[] },
        request.arguments,
        request.toolName,
      );
      decision = {
        effect: (reason ? 'DENY' : 'ALLOW') as PolicyEffect,
        matchedRule: null,
        reason: reason ?? 'No rule forbids this call.',
        timestamp: new Date().toISOString(),
        evaluationTimeMs: performance.now() - startTime,
      };
    }

    const elapsed = performance.now() - startTime;

    if (elapsed > this.timeoutMs) {
      console.warn(
        `[SolonGate] Policy evaluation took ${elapsed.toFixed(1)}ms ` +
        `(limit: ${this.timeoutMs}ms) for tool "${request.toolName}"`,
      );
    }

    return decision;
  }

  // Which backend decides. 'local' is the guard's evaluator, which is what runs
  // when no WASM bundle is loaded — it used to be reported as 'opa-unloaded' and
  // meant every call was denied.
  getEvaluatorMode(): 'opa' | 'local' {
    return this.opaEvaluator?.isReady() ? 'opa' : 'local';
  }

  // Loads a new policy set, replacing the current one.
  // Validates before accepting. Auto-saves version when store is present.
  loadPolicySet(
    policySet: PolicySet,
    options?: { reason?: string; createdBy?: string },
  ): ValidationResult {
    const validation = validatePolicySet(policySet);
    if (!validation.valid) {
      return validation;
    }
    this.policySet = policySet;

    if (this.store) {
      this.store.saveVersion(
        policySet,
        options?.reason ?? 'Policy updated',
        options?.createdBy ?? 'system',
      );
    }

    return validation;
  }

  // Rolls back to a previous policy version.
  // Only available when a PolicyStore is configured.
  rollback(version: number): PolicyVersion {
    if (!this.store) {
      throw new Error('PolicyStore not configured - cannot rollback');
    }

    const policyVersion = this.store.rollback(this.policySet.id, version);
    this.policySet = policyVersion.policySet;
    return policyVersion;
  }

  getPolicySet(): Readonly<PolicySet> {
    return this.policySet;
  }

  getSecurityWarnings(): readonly SecurityWarning[] {
    return analyzeSecurityWarnings(this.policySet);
  }

  getStore(): PolicyStore | null {
    return this.store;
  }

  reset(): void {
    this.policySet = createDefaultDenyPolicySet();
  }
}
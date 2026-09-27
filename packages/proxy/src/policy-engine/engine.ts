// Engine: main PolicyEngine class that loads, validates, and evaluates policy sets.
import type { PolicySet, PolicyDecision, PolicyEffect, ExecutionRequest } from '../core/index.js';
import { POLICY_EVALUATION_TIMEOUT_MS, DEFAULT_POLICY_EFFECT } from '../core/index.js';
import { validatePolicySet, type ValidationResult } from './validator.js';
import { analyzeSecurityWarnings, type SecurityWarning } from './warnings.js';
import { createDefaultDenyPolicySet } from './defaults.js';
import { PolicyStore, type PolicyVersion } from './policy-store.js';
import { OpaEvaluator } from './opa/opa-evaluator.js';

// PolicyEngine is the primary interface for policy evaluation.
// OPA WASM is the SOLE evaluation backend (NIST SP 800-207 PDP compliant).
// There is no legacy/secondary engine: if the OPA WASM bundle is not loaded,
// evaluation fails CLOSED (default DENY) rather than falling back. A WASM
// bundle must be loaded via loadWasmBundle()/initOpa() before evaluate().
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
      decision = {
        effect: DEFAULT_POLICY_EFFECT as PolicyEffect,
        matchedRule: null,
        reason: 'OPA WASM evaluator not loaded — failing closed (default DENY). '
          + 'Ensure the policy is compiled to WASM and loaded via loadWasmBundle().',
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

  // Returns the active evaluator backend. Always 'opa' — reports whether the
  // WASM bundle is loaded ('opa') or not yet loaded ('opa-unloaded', which
  // means evaluate() fails closed).
  getEvaluatorMode(): 'opa' | 'opa-unloaded' {
    return this.opaEvaluator?.isReady() ? 'opa' : 'opa-unloaded';
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
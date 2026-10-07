// SPDX-License-Identifier: Apache-2.0

export { PolicyEngine } from './engine.js';
export { evaluatePolicy } from './evaluator.js';
export { ruleMatchesRequest, toolPatternMatches, trustLevelMeetsMinimum } from './matcher.js';
export { validatePolicyRule, validatePolicySet, type ValidationResult } from './validator.js';
export { analyzeSecurityWarnings, type SecurityWarning } from './warnings.js';
export { createDefaultDenyPolicySet, createPermissivePolicySet, createReadOnlyPolicySet, createSandboxedPolicySet } from './defaults.js';
export {
  isPathAllowed,
  isWithinRoot,
  matchPathPattern,
  normalizePath,
  extractPathArguments,
} from './path-matcher.js';
export {
  isCommandAllowed,
  matchCommandPattern,
  extractCommandArguments,
} from './command-matcher.js';
export {
  isFilenameAllowed,
  matchFilenamePattern,
  extractFilenames,
} from './filename-matcher.js';
export {
  isUrlAllowed,
  matchUrlPattern,
  extractUrlArguments,
} from './url-matcher.js';
export { PolicyStore, type PolicyVersion, type PolicyDiff } from './policy-store.js';
// OPA WASM engine: compile policies to Rego→WASM and evaluate via @open-policy-agent/opa-wasm.
export { OpaEvaluator, compileRegoToWasm, isOpaAvailable, toOpaInput, type OpaInput, type OpaDecision } from './opa/index.js';

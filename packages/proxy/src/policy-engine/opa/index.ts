// SPDX-License-Identifier: Apache-2.0

// OPA: re-exports the Open Policy Agent integration modules.
export { OpaEvaluator } from './opa-evaluator.js';
export { compileRegoToWasm, isOpaAvailable } from './rego-compiler.js';
export { toOpaInput, type OpaInput, type OpaDecision } from './request-adapter.js';

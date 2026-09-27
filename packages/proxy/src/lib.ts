/**
 * @solongate/proxy — Library exports.
 *
 * Re-exports SDK classes (SolonGate, SecureMcpServer, RateLimiter, etc.)
 * so that external consumers can import from '@solongate/proxy' without
 * needing a separate @solongate/sdk package.
 */

// SDK classes (formerly @solongate/sdk)
export { SolonGate, LicenseError } from './sdk/solongate.js';
export { SecureMcpServer, type SecureMcpServerOptions } from './sdk/secure-server.js';
export { interceptToolCall, ExfiltrationChainTracker, type InterceptorOptions } from './sdk/interceptor.js';
export { resolveConfig, DEFAULT_CONFIG, type SolonGateConfig } from './sdk/config.js';
export { SecurityLogger } from './sdk/logger.js';
export { TokenIssuer } from './sdk/token-issuer.js';
export { ServerVerifier, type SignedMcpRequest, type SignatureValidationResult } from './sdk/server-verifier.js';
export { RateLimiter, type RateLimitResult } from './sdk/rate-limiter.js';

// Re-export core types for convenience
export {
  TrustLevel,
  Permission,
  PolicyEffect,
  type PolicyRule,
  type PolicySet,
  type PolicyDecision,
  type SecurityContext,
  type ExecutionRequest,
  type ExecutionResult,
  type ToolCapability,
  type McpCallToolParams,
  type McpCallToolResult,
  type CapabilityToken,
  type TokenConfig,
  type InputGuardConfig,
  type ThreatType,
  type DetectedThreat,
  type SanitizationResult,
  SolonGateError,
  PolicyDeniedError,
  SchemaValidationError,
  RateLimitError as CoreRateLimitError,
  InputGuardError,
  NetworkError,
  createSecurityContext,
  createDeniedToolResult,
  validateToolInput,
  sanitizeInput,
  detectPathTraversal,
  detectShellInjection,
  detectWildcardAbuse,
  detectSSRF,
  detectSQLInjection,
  detectExfiltration,
  detectBoundaryEscape,
  checkLengthLimits,
  checkEntropyLimits,
  scanResponse,
  RESPONSE_WARNING_MARKER,
  BOUNDARY_PREFIX,
  BOUNDARY_SUFFIX,
  tagUserInput,
  stripBoundaryTags,
  type ResponseScanConfig,
  type ResponseThreatType,
  type ResponseThreat,
  type ResponseScanResult,
  type TaggedArguments,
} from './core/index.js';

// Re-export policy engine
export {
  PolicyEngine,
  PolicyStore,
  type PolicyVersion,
  type PolicyDiff,
  createDefaultDenyPolicySet,
  createPermissivePolicySet,
  createReadOnlyPolicySet,
} from './policy-engine/index.js';

// Proxy class
export { SolonGateProxy } from './proxy.js';

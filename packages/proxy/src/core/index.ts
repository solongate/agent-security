// SPDX-License-Identifier: Apache-2.0

// Trust model
export { TrustLevel, isValidTrustLevel, assertValidTransition } from './trust.js';

// Permissions
export {
  Permission,
  PermissionSchema,
  type PermissionSet,
  createPermissionSet,
  hasPermission,
  hasAllPermissions,
  permissionForMethod,
  guessPermission,
  NO_PERMISSIONS,
  READ_ONLY,
} from './permissions.js';

// Policy
export {
  PolicyEffect,
  type PolicyRule,
  type PolicySet,
  type PolicyDecision,
  PolicyRuleSchema,
  PolicySetSchema,
} from './policy.js';

// Tool capabilities
export {
  type ToolCapability,
  createToolCapability,
} from './tool.js';

// Context
export {
  type SecurityContext,
  type ExecutionContext,
  createSecurityContext,
} from './context.js';

// Execution
export {
  type ExecutionRequest,
  type ExecutionResult,
  type ExecutionResultAllowed,
  type ExecutionResultDenied,
  type ExecutionResultError,
} from './execution.js';

// Errors
export {
  SolonGateError,
  PolicyDeniedError,
  TrustEscalationError,
  SchemaValidationError,
  RateLimitError,
  ToolNotFoundError,
  UnsafeConfigurationError,
  InputGuardError,
  NetworkError,
} from './errors.js';

// Constants
export * from './constants.js';

// MCP adapter types
export {
  type McpToolDefinition,
  type McpCallToolParams,
  type McpCallToolResult,
  type McpToolResultContent,
  createDeniedToolResult,
} from './mcp-types.js';

// Schema Validator
export {
  validateToolInput,
  createStrictSchema,
  type SchemaValidationResult,
  type SchemaValidatorOptions,
} from './schema-validator.js';

// Response Scanner
export {
  scanResponse,
  RESPONSE_WARNING_MARKER,
  DEFAULT_RESPONSE_SCAN_CONFIG,
  type ResponseThreatType,
  type ResponseThreat,
  type ResponseScanResult,
  type ResponseScanConfig,
} from './response-scanner.js';

// Capability Token types
export {
  type CapabilityToken,
  type TokenConfig,
  type TokenVerificationResult,
  DEFAULT_TOKEN_TTL_SECONDS,
  TOKEN_ALGORITHM,
  MIN_SECRET_LENGTH,
} from './capability-token.js';

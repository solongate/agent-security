// SPDX-License-Identifier: Apache-2.0

/**
 * Base error class for all SolonGate security errors.
 * Every error includes a machine-readable code for programmatic handling.
 */
export class SolonGateError extends Error {
  public readonly code: string;
  public readonly timestamp: string;
  public readonly details: Record<string, unknown>;

  constructor(
    message: string,
    code: string,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'SolonGateError';
    this.code = code;
    this.timestamp = new Date().toISOString();
    this.details = Object.freeze({ ...details });
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Serializable representation for logging and API responses.
   * Never includes stack traces (information leakage prevention).
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      timestamp: this.timestamp,
      details: this.details,
    };
  }
}

/** Thrown when a tool call is denied by policy. */
export class PolicyDeniedError extends SolonGateError {
  constructor(
    toolName: string,
    reason: string,
    details: Record<string, unknown> = {},
  ) {
    super(
      `Policy denied execution of tool "${toolName}": ${reason}`,
      'POLICY_DENIED',
      { toolName, reason, ...details },
    );
    this.name = 'PolicyDeniedError';
  }
}

/** Thrown when a trust level escalation is attempted illegally. */
export class TrustEscalationError extends SolonGateError {
  constructor(message: string) {
    super(message, 'TRUST_ESCALATION');
    this.name = 'TrustEscalationError';
  }
}

/** Thrown when tool input fails schema validation. */
export class SchemaValidationError extends SolonGateError {
  constructor(
    toolName: string,
    validationErrors: readonly string[],
  ) {
    super(
      `Schema validation failed for tool "${toolName}": ${validationErrors.join('; ')}`,
      'SCHEMA_VALIDATION_FAILED',
      { toolName, validationErrors },
    );
    this.name = 'SchemaValidationError';
  }
}

/** Thrown when a tool exceeds its rate limit. */
export class RateLimitError extends SolonGateError {
  constructor(toolName: string, limitPerMinute: number) {
    super(
      `Rate limit exceeded for tool "${toolName}": max ${limitPerMinute}/min`,
      'RATE_LIMIT_EXCEEDED',
      { toolName, limitPerMinute },
    );
    this.name = 'RateLimitError';
  }
}

/** Thrown when a tool is not found in the registry. */
export class ToolNotFoundError extends SolonGateError {
  constructor(toolName: string, serverName: string) {
    super(
      `Tool "${toolName}" not found on server "${serverName}"`,
      'TOOL_NOT_FOUND',
      { toolName, serverName },
    );
    this.name = 'ToolNotFoundError';
  }
}

/** Thrown when an unsafe configuration is detected. */
export class UnsafeConfigurationError extends SolonGateError {
  constructor(message: string, field: string) {
    super(
      `Unsafe configuration detected: ${message}`,
      'UNSAFE_CONFIGURATION',
      { field },
    );
    this.name = 'UnsafeConfigurationError';
  }
}

/** Thrown when input guard detects dangerous patterns. */
export class InputGuardError extends SolonGateError {
  constructor(
    toolName: string,
    threats: readonly { type: string; field: string; description: string }[],
  ) {
    super(
      `Input guard blocked tool "${toolName}": ${threats.map(t => t.description).join('; ')}`,
      'INPUT_GUARD_BLOCKED',
      { toolName, threatCount: threats.length, threats },
    );
    this.name = 'InputGuardError';
  }
}

/** Thrown when a network operation fails (API calls, cloud sync, etc.). */
export class NetworkError extends SolonGateError {
  constructor(
    operation: string,
    statusCode?: number,
    details: Record<string, unknown> = {},
  ) {
    super(
      `Network error during ${operation}${statusCode ? ` (HTTP ${statusCode})` : ''}`,
      'NETWORK_ERROR',
      { operation, statusCode, ...details },
    );
    this.name = 'NetworkError';
  }
}

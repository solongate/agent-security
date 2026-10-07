// SPDX-License-Identifier: Apache-2.0

import type { SecurityContext } from './context.js';
import type { Permission } from './permissions.js';
import type { PolicyDecision } from './policy.js';
import type { SolonGateError } from './errors.js';

/** An execution request represents a tool call that needs security evaluation. */
export interface ExecutionRequest {
  readonly context: SecurityContext;
  readonly toolName: string;
  readonly serverName: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly requiredPermission: Permission;
  readonly timestamp: string;
}

/** Discriminated union on `status` for exhaustive matching. */
export type ExecutionResult =
  | ExecutionResultAllowed
  | ExecutionResultDenied
  | ExecutionResultError;

export interface ExecutionResultAllowed {
  readonly status: 'ALLOWED';
  readonly request: ExecutionRequest;
  readonly decision: PolicyDecision;
  readonly toolResult: unknown;
  readonly durationMs: number;
  readonly timestamp: string;
}

export interface ExecutionResultDenied {
  readonly status: 'DENIED';
  readonly request: ExecutionRequest;
  readonly decision: PolicyDecision;
  readonly timestamp: string;
}

export interface ExecutionResultError {
  readonly status: 'ERROR';
  readonly request: ExecutionRequest;
  readonly error: SolonGateError;
  readonly timestamp: string;
}

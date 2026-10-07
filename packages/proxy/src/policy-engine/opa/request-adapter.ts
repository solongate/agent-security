// SPDX-License-Identifier: Apache-2.0

// Request Adapter: converts ExecutionRequest into OPA input documents.
import type { ExecutionRequest } from '../../core/index.js';
import { extractPathArguments } from '../path-matcher.js';
import { extractCommandArguments } from '../command-matcher.js';
import { extractUrlArguments } from '../url-matcher.js';
import { extractFilenames } from '../filename-matcher.js';

// OPA input document shape.
// This is the JSON object passed to the OPA WASM policy for evaluation.
export interface OpaInput {
  tool_name: string;
  permission: string;
  trust_level: string;
  arguments: Record<string, unknown>;
  paths: string[];
  commands: string[];
  urls: string[];
  filenames: string[];
}

// OPA decision output shape.
// Returned by the Rego policy's `decision` rule.
export interface OpaDecision {
  effect: 'ALLOW' | 'DENY';
  reason: string;
  matched_rule: string | null;
}

// Converts an ExecutionRequest into the OPA input document format.
// Re-uses existing extractor functions from the matchers — these handle
// all the heuristic argument extraction (path detection, command detection, etc.)
// independent of the evaluation engine.
export function toOpaInput(request: ExecutionRequest): OpaInput {
  const args = request.arguments ?? {};
  return {
    tool_name: request.toolName,
    permission: request.requiredPermission ?? '',
    trust_level: request.context.trustLevel,
    arguments: args as Record<string, unknown>,
    paths: extractPathArguments(args as Record<string, unknown>),
    commands: extractCommandArguments(args as Record<string, unknown>),
    urls: extractUrlArguments(args as Record<string, unknown>),
    filenames: extractFilenames(args as Record<string, unknown>),
  };
}
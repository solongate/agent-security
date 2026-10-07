// SPDX-License-Identifier: Apache-2.0

import { z, type ZodTypeAny } from 'zod';
import { MAX_ARGUMENT_DEPTH, MAX_ARGUMENTS_SIZE_BYTES } from './constants.js';

/**
 * Result of schema validation.
 * Always includes structured errors for programmatic handling.
 */
export interface SchemaValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
  readonly sanitized: Readonly<Record<string, unknown>> | null;
}

/**
 * Options for schema validation behavior.
 */
export interface SchemaValidatorOptions {
  readonly maxDepth?: number;
  readonly maxSizeBytes?: number;
  readonly stripUnknown?: boolean;
}

const DEFAULT_OPTIONS: Required<SchemaValidatorOptions> = {
  maxDepth: MAX_ARGUMENT_DEPTH,
  maxSizeBytes: MAX_ARGUMENTS_SIZE_BYTES,
  stripUnknown: false,
};

/**
 * Validates tool input against a Zod schema with strict security enforcement.
 *
 * - Unknown fields are REJECTED (no additionalProperties)
 * - Type mismatches are REJECTED
 * - Required fields are ENFORCED
 * - Recursive depth is limited
 * - Argument size is limited
 */
export function validateToolInput(
  schema: ZodTypeAny,
  input: unknown,
  options?: SchemaValidatorOptions,
): SchemaValidationResult {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const errors: string[] = [];

  // 1. Size check - prevent oversized payloads
  const sizeError = checkInputSize(input, opts.maxSizeBytes);
  if (sizeError) {
    return { valid: false, errors: [sizeError], sanitized: null };
  }

  // 2. Depth check - prevent deeply nested structures
  const depthError = checkInputDepth(input, opts.maxDepth);
  if (depthError) {
    return { valid: false, errors: [depthError], sanitized: null };
  }

  // 3. Schema validation using Zod strict mode
  const result = schema.safeParse(input);

  if (!result.success) {
    for (const issue of result.error.issues) {
      const path = issue.path.length > 0 ? issue.path.join('.') : 'root';
      errors.push(`${path}: ${issue.message}`);
    }
    return { valid: false, errors, sanitized: null };
  }

  return {
    valid: true,
    errors: [],
    sanitized: result.data as Readonly<Record<string, unknown>>,
  };
}

/**
 * Creates a strict Zod object schema that rejects unknown fields.
 * Wraps z.object().strict() for convenience.
 */
export function createStrictSchema(
  shape: Record<string, ZodTypeAny>,
): z.ZodObject<Record<string, ZodTypeAny>, 'strict'> {
  return z.object(shape).strict();
}

/**
 * Checks if input size exceeds the maximum allowed bytes.
 */
function checkInputSize(input: unknown, maxBytes: number): string | null {
  let serialized: string;
  try {
    serialized = JSON.stringify(input);
  } catch {
    return 'Input cannot be serialized to JSON';
  }

  const sizeBytes = new TextEncoder().encode(serialized).length;
  if (sizeBytes > maxBytes) {
    return `Input size ${sizeBytes} bytes exceeds maximum ${maxBytes} bytes`;
  }
  return null;
}

/**
 * Checks if input exceeds maximum nesting depth.
 * Prevents stack overflow and denial-of-service via deeply nested objects.
 */
function checkInputDepth(input: unknown, maxDepth: number): string | null {
  const depth = measureDepth(input, 0);
  if (depth > maxDepth) {
    return `Input depth ${depth} exceeds maximum ${maxDepth}`;
  }
  return null;
}

function measureDepth(value: unknown, currentDepth: number): number {
  if (currentDepth > MAX_ARGUMENT_DEPTH + 1) {
    return currentDepth; // Early exit to prevent stack overflow
  }

  if (value === null || value === undefined || typeof value !== 'object') {
    return currentDepth;
  }

  if (Array.isArray(value)) {
    let maxChildDepth = currentDepth + 1;
    for (const item of value) {
      const childDepth = measureDepth(item, currentDepth + 1);
      if (childDepth > maxChildDepth) maxChildDepth = childDepth;
    }
    return maxChildDepth;
  }

  let maxChildDepth = currentDepth + 1;
  for (const key of Object.keys(value as Record<string, unknown>)) {
    const childDepth = measureDepth(
      (value as Record<string, unknown>)[key],
      currentDepth + 1,
    );
    if (childDepth > maxChildDepth) maxChildDepth = childDepth;
  }
  return maxChildDepth;
}

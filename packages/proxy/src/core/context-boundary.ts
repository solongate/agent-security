/**
 * Context Boundary Tagging: wraps user-provided tool arguments with
 * boundary markers so the LLM can distinguish user input from system data.
 *
 * This prevents confusion attacks where adversarial input is treated
 * as trusted system instructions.
 */

import { BOUNDARY_PREFIX, BOUNDARY_SUFFIX } from './input-guard.js';

export type TaggedArguments = Record<string, unknown>;

/**
 * Wraps all string values in the arguments with context boundary markers.
 * Non-string values are passed through unchanged.
 * Objects and arrays are recursively tagged.
 */
export function tagUserInput(args: Record<string, unknown>): TaggedArguments {
  return tagObject(args);
}

function tagValue(value: unknown): unknown {
  if (typeof value === 'string') {
    return `${BOUNDARY_PREFIX}${value}${BOUNDARY_SUFFIX}`;
  }
  if (Array.isArray(value)) {
    return value.map(tagValue);
  }
  if (typeof value === 'object' && value !== null) {
    return tagObject(value as Record<string, unknown>);
  }
  return value;
}

function tagObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    result[key] = tagValue(val);
  }
  return result;
}

/**
 * Strips all boundary tags from a string (e.g. from tool responses before
 * returning to client).
 */
export function stripBoundaryTags(text: string): string {
  return text
    .replaceAll(BOUNDARY_PREFIX, '')
    .replaceAll(BOUNDARY_SUFFIX, '');
}

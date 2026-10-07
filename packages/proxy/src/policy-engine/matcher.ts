// SPDX-License-Identifier: Apache-2.0

import type { PolicyRule, ExecutionRequest } from '../core/index.js';
import { TrustLevel } from '../core/index.js';
import { isPathAllowed, extractPathArguments } from './path-matcher.js';
import { isCommandAllowed, extractCommandArguments } from './command-matcher.js';
import { isFilenameAllowed, extractFilenames } from './filename-matcher.js';
import { isUrlAllowed, extractUrlArguments } from './url-matcher.js';

/**
 * Pure function: determines if a policy rule matches an execution request.
 * No side effects. No I/O. Fully deterministic.
 */
export function ruleMatchesRequest(
  rule: PolicyRule,
  request: ExecutionRequest,
): boolean {
  if (!rule.enabled) return false;
  if (rule.permission && rule.permission !== request.requiredPermission) return false;
  if (!toolPatternMatches(rule.toolPattern, request.toolName)) return false;
  if (!trustLevelMeetsMinimum(request.context.trustLevel, rule.minimumTrustLevel)) {
    return false;
  }
  if (rule.argumentConstraints) {
    if (!argumentConstraintsMatch(rule.argumentConstraints, request.arguments)) {
      return false;
    }
  }
  if (rule.pathConstraints) {
    const satisfied = pathConstraintsMatch(rule.pathConstraints, request.arguments);
    // For DENY rules: match when constraints are VIOLATED (path is dangerous)
    // For ALLOW rules: match when constraints are SATISFIED (path is safe)
    if (rule.effect === 'DENY') {
      if (satisfied) return false; // path is safe → don't deny
    } else {
      if (!satisfied) return false; // path is dangerous → don't allow
    }
  }
  if (rule.commandConstraints) {
    const satisfied = commandConstraintsMatch(rule.commandConstraints, request.arguments);
    if (rule.effect === 'DENY') {
      if (satisfied) return false;
    } else {
      if (!satisfied) return false;
    }
  }
  if (rule.filenameConstraints) {
    const satisfied = filenameConstraintsMatch(rule.filenameConstraints, request.arguments);
    if (rule.effect === 'DENY') {
      if (satisfied) return false; // filename is safe → don't deny
    } else {
      if (!satisfied) return false; // filename is dangerous → don't allow
    }
  }
  if (rule.urlConstraints) {
    const satisfied = urlConstraintsMatch(rule.urlConstraints, request.arguments);
    if (rule.effect === 'DENY') {
      if (satisfied) return false; // URL is safe → don't deny
    } else {
      if (!satisfied) return false; // URL is dangerous → don't allow
    }
  }
  return true;
}

/**
 * Glob-style tool name pattern matching.
 * Supports:
 *   '*'        → match all
 *   'prefix*'  → starts with prefix
 *   '*suffix'  → ends with suffix
 *   '*infix*'  → contains infix
 * Does NOT support regex (ReDoS prevention).
 */
export function toolPatternMatches(pattern: string, toolName: string): boolean {
  if (pattern === '*') return true;

  const startsWithStar = pattern.startsWith('*');
  const endsWithStar = pattern.endsWith('*');

  if (startsWithStar && endsWithStar) {
    // *infix* → contains
    const infix = pattern.slice(1, -1);
    return infix.length > 0 && toolName.includes(infix);
  }
  if (endsWithStar) {
    // prefix* → starts with
    const prefix = pattern.slice(0, -1);
    return toolName.startsWith(prefix);
  }
  if (startsWithStar) {
    // *suffix → ends with
    const suffix = pattern.slice(1);
    return toolName.endsWith(suffix);
  }

  return pattern === toolName;
}

const TRUST_LEVEL_ORDER: Record<string, number> = {
  [TrustLevel.UNTRUSTED]: 0,
  [TrustLevel.VERIFIED]: 1,
  [TrustLevel.TRUSTED]: 2,
};

export function trustLevelMeetsMinimum(
  actual: TrustLevel,
  minimum: TrustLevel,
): boolean {
  return (TRUST_LEVEL_ORDER[actual] ?? -1) >= (TRUST_LEVEL_ORDER[minimum] ?? Infinity);
}

/**
 * Condition operators for argument constraints.
 * When constraint value is a plain string → exact match (or '*' for any).
 * When constraint value is an object → operator-based matching:
 *   { $contains: "str" }      — value includes substring
 *   { $notContains: "str" }   — value does NOT include substring
 *   { $startsWith: "str" }    — value starts with prefix
 *   { $endsWith: "str" }      — value ends with suffix
 *   { $in: ["a","b"] }        — value is one of the listed values
 *   { $notIn: ["a","b"] }     — value is NOT one of the listed values
 *   { $gt: 5 }                — numeric greater than
 *   { $lt: 5 }                — numeric less than
 *   { $gte: 5 }               — numeric greater than or equal
 *   { $lte: 5 }               — numeric less than or equal
 */
function argumentConstraintsMatch(
  constraints: Record<string, unknown>,
  args: Readonly<Record<string, unknown>>,
): boolean {
  for (const [key, constraint] of Object.entries(constraints)) {
    if (!(key in args)) return false;
    const argValue = args[key];

    // Plain string: exact match (backward compatible)
    if (typeof constraint === 'string') {
      if (constraint === '*') continue;
      if (typeof argValue === 'string') {
        if (argValue !== constraint) return false;
      } else {
        return false;
      }
      continue;
    }

    // Object with operators
    if (typeof constraint === 'object' && constraint !== null && !Array.isArray(constraint)) {
      const ops = constraint as Record<string, unknown>;
      const strValue = typeof argValue === 'string' ? argValue : undefined;
      const numValue = typeof argValue === 'number' ? argValue : undefined;

      if ('$contains' in ops && typeof ops.$contains === 'string') {
        if (!strValue || !strValue.includes(ops.$contains)) return false;
      }
      if ('$notContains' in ops && typeof ops.$notContains === 'string') {
        if (strValue && strValue.includes(ops.$notContains)) return false;
      }
      if ('$startsWith' in ops && typeof ops.$startsWith === 'string') {
        if (!strValue || !strValue.startsWith(ops.$startsWith)) return false;
      }
      if ('$endsWith' in ops && typeof ops.$endsWith === 'string') {
        if (!strValue || !strValue.endsWith(ops.$endsWith)) return false;
      }
      if ('$in' in ops && Array.isArray(ops.$in)) {
        if (!ops.$in.includes(argValue)) return false;
      }
      if ('$notIn' in ops && Array.isArray(ops.$notIn)) {
        if (ops.$notIn.includes(argValue)) return false;
      }
      if ('$gt' in ops && typeof ops.$gt === 'number') {
        if (numValue === undefined || numValue <= ops.$gt) return false;
      }
      if ('$lt' in ops && typeof ops.$lt === 'number') {
        if (numValue === undefined || numValue >= ops.$lt) return false;
      }
      if ('$gte' in ops && typeof ops.$gte === 'number') {
        if (numValue === undefined || numValue < ops.$gte) return false;
      }
      if ('$lte' in ops && typeof ops.$lte === 'number') {
        if (numValue === undefined || numValue > ops.$lte) return false;
      }

      continue;
    }
  }
  return true;
}

function pathConstraintsMatch(
  constraints: NonNullable<PolicyRule['pathConstraints']>,
  args: Readonly<Record<string, unknown>>,
): boolean {
  const paths = extractPathArguments(args);

  // If no path arguments found, constraints don't apply
  if (paths.length === 0) return true;

  // ALL path arguments must satisfy constraints
  return paths.every((path) => isPathAllowed(path, constraints));
}

function commandConstraintsMatch(
  constraints: NonNullable<PolicyRule['commandConstraints']>,
  args: Readonly<Record<string, unknown>>,
): boolean {
  const commands = extractCommandArguments(args);

  // If no command arguments found, constraints don't apply
  if (commands.length === 0) return true;

  // ALL command arguments must satisfy constraints
  return commands.every((cmd) => isCommandAllowed(cmd, constraints));
}

function filenameConstraintsMatch(
  constraints: NonNullable<PolicyRule['filenameConstraints']>,
  args: Readonly<Record<string, unknown>>,
): boolean {
  const filenames = extractFilenames(args);

  // If no filename arguments found, constraints don't apply
  if (filenames.length === 0) return true;

  // ALL filenames must satisfy constraints
  return filenames.every((name) => isFilenameAllowed(name, constraints));
}

function urlConstraintsMatch(
  constraints: NonNullable<PolicyRule['urlConstraints']>,
  args: Readonly<Record<string, unknown>>,
): boolean {
  const urls = extractUrlArguments(args);

  // If no URL arguments found, constraints don't apply
  if (urls.length === 0) return true;

  // ALL URLs must satisfy constraints
  return urls.every((url) => isUrlAllowed(url, constraints));
}

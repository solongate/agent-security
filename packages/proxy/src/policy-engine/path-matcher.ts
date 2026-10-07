// SPDX-License-Identifier: Apache-2.0

import type { PolicyRule } from '../core/index.js';

type PathConstraints = NonNullable<PolicyRule['pathConstraints']>;

/**
 * Normalizes a file path for consistent matching.
 * Resolves . and .. segments, normalizes separators.
 */
export function normalizePath(path: string): string {
  // Normalize separators to forward slash
  let normalized = path.replace(/\\/g, '/');

  // Remove trailing slash (except for root)
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  // Resolve . and .. segments
  const parts = normalized.split('/');
  const resolved: string[] = [];

  for (const part of parts) {
    if (part === '.' || part === '') {
      if (resolved.length === 0) resolved.push('');
      continue;
    }
    if (part === '..') {
      if (resolved.length > 1) {
        resolved.pop();
      }
      continue;
    }
    resolved.push(part);
  }

  return resolved.join('/') || '/';
}

/**
 * Checks if a path is within a root directory (sandbox boundary).
 * Prevents escaping via .., symlinks, etc.
 */
export function isWithinRoot(path: string, root: string): boolean {
  const normalizedPath = normalizePath(path);
  const normalizedRoot = normalizePath(root);

  // Path must start with root
  if (normalizedPath === normalizedRoot) return true;
  return normalizedPath.startsWith(normalizedRoot + '/');
}

/**
 * Glob-style path pattern matching.
 * Supports:
 * - * matches any single path segment (not /)
 * - ** matches any number of path segments
 * - Exact match
 *
 * Does NOT support regex (ReDoS prevention).
 */
export function matchPathPattern(path: string, pattern: string): boolean {
  const normalizedPath = normalizePath(path);
  const normalizedPattern = normalizePath(pattern);

  if (normalizedPattern === '*') return true;
  if (normalizedPattern === normalizedPath) return true;

  const patternParts = normalizedPattern.split('/');
  const pathParts = normalizedPath.split('/');

  return matchParts(pathParts, 0, patternParts, 0);
}

function matchParts(
  pathParts: string[],
  pi: number,
  patternParts: string[],
  qi: number,
): boolean {
  while (pi < pathParts.length && qi < patternParts.length) {
    const pattern = patternParts[qi]!;

    if (pattern === '**') {
      // ** can match zero or more path segments
      if (qi === patternParts.length - 1) return true;

      // Try matching ** against 0, 1, 2, ... path segments
      for (let i = pi; i <= pathParts.length; i++) {
        if (matchParts(pathParts, i, patternParts, qi + 1)) {
          return true;
        }
      }
      return false;
    }

    if (pattern === '*') {
      // * matches exactly one path segment
      pi++;
      qi++;
      continue;
    }

    // Support intra-segment globs: *.txt, file.*, test-*-data, etc.
    if (pattern.includes('*')) {
      if (!matchSegmentGlob(pathParts[pi]!, pattern)) {
        return false;
      }
      pi++;
      qi++;
      continue;
    }

    if (pattern !== pathParts[pi]) {
      return false;
    }

    pi++;
    qi++;
  }

  // Skip trailing ** patterns
  while (qi < patternParts.length && patternParts[qi] === '**') {
    qi++;
  }

  return pi === pathParts.length && qi === patternParts.length;
}

/**
 * Checks if a path is allowed by the given constraints.
 *
 * Evaluation order:
 * 1. If rootDirectory is set, path must be within it
 * 2. If denied list exists, path must NOT match any denied pattern
 * 3. If allowed list exists, path must match at least one allowed pattern
 * 4. If neither list exists, path is allowed (constraints are optional)
 */
export function isPathAllowed(
  path: string,
  constraints: PathConstraints,
): boolean {
  // 1. Root directory check (sandbox)
  if (constraints.rootDirectory) {
    if (!isWithinRoot(path, constraints.rootDirectory)) {
      return false;
    }
  }

  // 2. Denied list - any match means denied
  if (constraints.denied && constraints.denied.length > 0) {
    for (const pattern of constraints.denied) {
      if (matchPathPattern(path, pattern)) {
        return false;
      }
    }
  }

  // 3. Allowed list - must match at least one
  if (constraints.allowed && constraints.allowed.length > 0) {
    let matchesAllowed = false;
    for (const pattern of constraints.allowed) {
      if (matchPathPattern(path, pattern)) {
        matchesAllowed = true;
        break;
      }
    }
    if (!matchesAllowed) return false;
  }

  return true;
}

/**
 * Matches a single path segment against a glob pattern containing *.
 * Examples: *.txt matches safe.txt, file.* matches file.js, *secret* matches my-secret-key
 */
function matchSegmentGlob(segment: string, pattern: string): boolean {
  const startsWithStar = pattern.startsWith('*');
  const endsWithStar = pattern.endsWith('*');

  if (pattern === '*') return true;

  if (startsWithStar && endsWithStar) {
    // *infix* — contains
    const infix = pattern.slice(1, -1);
    return segment.toLowerCase().includes(infix.toLowerCase());
  }
  if (startsWithStar) {
    // *suffix — ends with
    const suffix = pattern.slice(1);
    return segment.toLowerCase().endsWith(suffix.toLowerCase());
  }
  if (endsWithStar) {
    // prefix* — starts with
    const prefix = pattern.slice(0, -1);
    return segment.toLowerCase().startsWith(prefix.toLowerCase());
  }

  // Single * in middle: split on * and check prefix+suffix
  const starIdx = pattern.indexOf('*');
  if (starIdx !== -1) {
    const prefix = pattern.slice(0, starIdx);
    const suffix = pattern.slice(starIdx + 1);
    const seg = segment.toLowerCase();
    return seg.startsWith(prefix.toLowerCase()) && seg.endsWith(suffix.toLowerCase()) && seg.length >= prefix.length + suffix.length;
  }

  return segment === pattern;
}

/**
 * Known argument field names that typically contain file paths.
 */
const PATH_FIELDS = new Set([
  'path',
  'file',
  'file_path',
  'filepath',
  'filename',
  'directory',
  'dir',
  'folder',
  'source',
  'destination',
  'dest',
  'target',
  'input',
  'output',
  'cwd',
  'root',
  'notebook_path',
]);

/**
 * Extracts path-like arguments from tool call arguments.
 * Uses multiple heuristics:
 * 1. Known path field names — always extract
 * 2. Strings containing / or \ (original heuristic)
 * 3. Strings starting with . (.env, ./foo)
 */
export function extractPathArguments(
  args: Readonly<Record<string, unknown>>,
): string[] {
  const paths: string[] = [];
  const seen = new Set<string>();

  function addPath(value: string): void {
    const trimmed = value.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      paths.push(trimmed);
    }
  }

  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== 'string') continue;

    // Known path field names
    if (PATH_FIELDS.has(key.toLowerCase())) {
      addPath(value);
      continue;
    }

    // Contains path separators
    if (value.includes('/') || value.includes('\\')) {
      addPath(value);
      continue;
    }

    // Starts with . (.env, ./config, ../secret)
    if (value.startsWith('.')) {
      addPath(value);
      continue;
    }
  }

  return paths;
}

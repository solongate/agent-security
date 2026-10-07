// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';

/**
 * Permission types are ALWAYS evaluated independently.
 * Having READ does NOT imply WRITE or EXECUTE.
 */
export const Permission = {
  READ: 'READ',
  WRITE: 'WRITE',
  EXECUTE: 'EXECUTE',
  NETWORK: 'NETWORK',
} as const;

export type Permission = (typeof Permission)[keyof typeof Permission];

export const PermissionSchema = z.enum(['READ', 'WRITE', 'EXECUTE', 'NETWORK']);

/** Guess the permission type from a tool name. */
export function guessPermission(toolName: string): Permission {
  const name = toolName.toLowerCase();
  if (name.includes('exec') || name.includes('shell') || name.includes('run') || name.includes('eval')) {
    return Permission.EXECUTE;
  }
  if (name.includes('fetch') || name.includes('http') || name.includes('request') || name.includes('curl') || name.includes('network') || name.includes('download') || name.includes('upload')) {
    return Permission.NETWORK;
  }
  if (name.includes('write') || name.includes('create') || name.includes('delete') || name.includes('update') || name.includes('set') || name.includes('edit') || name.includes('remove') || name.includes('insert')) {
    return Permission.WRITE;
  }
  return Permission.READ;
}

/** Immutable set of permissions granted to a specific scope. */
export type PermissionSet = ReadonlySet<Permission>;

/** Creates an immutable permission set from an array. */
export function createPermissionSet(
  permissions: Permission[],
): PermissionSet {
  for (const p of permissions) {
    PermissionSchema.parse(p);
  }
  return new Set(permissions) as ReadonlySet<Permission>;
}

/** Empty permission set - the default for all new tools (default-deny). */
export const NO_PERMISSIONS: PermissionSet = Object.freeze(
  new Set<Permission>(),
) as ReadonlySet<Permission>;

/** Read-only permission set - the maximum default for new tools. */
export const READ_ONLY: PermissionSet = Object.freeze(
  new Set<Permission>([Permission.READ]),
) as ReadonlySet<Permission>;

export function hasPermission(
  permissions: PermissionSet,
  required: Permission,
): boolean {
  return permissions.has(required);
}

export function hasAllPermissions(
  permissions: PermissionSet,
  required: Permission[],
): boolean {
  return required.every((p) => permissions.has(p));
}

/** Maps MCP protocol methods to SolonGate permission types. */
export function permissionForMethod(method: string): Permission {
  if (
    method.startsWith('resources/') ||
    method.startsWith('prompts/') ||
    method === 'tools/list'
  ) {
    return Permission.READ;
  }
  if (method === 'tools/call') {
    return Permission.EXECUTE;
  }
  // Default to EXECUTE for unknown methods (most restrictive)
  return Permission.EXECUTE;
}

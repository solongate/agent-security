// SPDX-License-Identifier: Apache-2.0

import type { PolicySet } from '../core/index.js';
import { PolicyEffect, Permission, TrustLevel } from '../core/index.js';

/**
 * Creates the default "deny all" policy set.
 * This is the starting policy for any new SolonGate deployment.
 */
export function createDefaultDenyPolicySet(): PolicySet {
  const now = new Date().toISOString();

  return {
    id: 'default-deny',
    name: 'Default Deny All',
    description:
      'Denies all tool executions. Add explicit ALLOW rules to grant access to specific tools.',
    version: 1,
    rules: [
      {
        id: 'deny-all-execute',
        description: 'Explicitly deny all tool executions',
        effect: PolicyEffect.DENY,
        priority: 10000,
        toolPattern: '*',
        permission: Permission.EXECUTE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'deny-all-write',
        description: 'Explicitly deny all write operations',
        effect: PolicyEffect.DENY,
        priority: 10000,
        toolPattern: '*',
        permission: Permission.WRITE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'deny-all-read',
        description: 'Explicitly deny all read operations',
        effect: PolicyEffect.DENY,
        priority: 10000,
        toolPattern: '*',
        permission: Permission.READ,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
    ],
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Creates a permissive "allow all" policy set.
 * Allows all tool executions — useful for development or when
 * using SolonGate only for monitoring and audit logging.
 */
export function createPermissivePolicySet(): PolicySet {
  const now = new Date().toISOString();

  return {
    id: 'permissive',
    name: 'Permissive (Allow All)',
    description: 'Allows all tool executions. SolonGate still provides input validation, rate limiting, and audit logging.',
    version: 1,
    rules: [
      {
        id: 'allow-all-execute',
        description: 'Allow all tool executions',
        effect: PolicyEffect.ALLOW,
        priority: 1000,
        toolPattern: '*',
        permission: Permission.EXECUTE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'allow-all-read',
        description: 'Allow all read operations',
        effect: PolicyEffect.ALLOW,
        priority: 1000,
        toolPattern: '*',
        permission: Permission.READ,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'allow-all-write',
        description: 'Allow all write operations',
        effect: PolicyEffect.ALLOW,
        priority: 1000,
        toolPattern: '*',
        permission: Permission.WRITE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
    ],
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Internal helper. Builds a read-only policy set scoped by an internal tool
 * selector — fixed to "*" in the shipped product; no UI or CLI exposes it, so
 * users can neither see nor change it. Allows reads for VERIFIED requests only.
 */
export function createReadOnlyPolicySet(toolPattern: string): PolicySet {
  const now = new Date().toISOString();

  return {
    id: `read-only-${toolPattern}`,
    name: `Read-Only: ${toolPattern}`,
    description: `Allows read access to tools matching "${toolPattern}". Denies write and execute.`,
    version: 1,
    rules: [
      {
        id: `allow-read-${toolPattern}`,
        description: `Allow read access to ${toolPattern}`,
        effect: PolicyEffect.ALLOW,
        priority: 100,
        toolPattern,
        permission: Permission.READ,
        minimumTrustLevel: TrustLevel.VERIFIED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
    ],
    createdAt: now,
    updatedAt: now,
  };
}

/**
 * Creates a sandboxed policy set for a given root directory.
 * Allows file operations within rootDir, blocks dangerous commands,
 * denies access to sensitive files.
 */
export function createSandboxedPolicySet(rootDir: string): PolicySet {
  const now = new Date().toISOString();

  return {
    id: `sandbox-${rootDir.replace(/\//g, '-')}`,
    name: `Sandbox: ${rootDir}`,
    description: `Allows operations within ${rootDir}. Blocks dangerous commands and sensitive file access.`,
    version: 1,
    rules: [
      {
        id: 'deny-dangerous-commands',
        description: 'Block dangerous shell commands',
        effect: PolicyEffect.DENY,
        priority: 50,
        toolPattern: '*',
        permission: Permission.EXECUTE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        commandConstraints: {
          denied: [
            'rm -rf *', 'rm -r /*', 'mkfs*', 'dd if=*',
            'curl*|*bash*', 'wget*|*sh*',
            'shutdown*', 'reboot*', 'chmod*777*',
          ],
        },
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'deny-sensitive-paths',
        description: 'Block access to sensitive files',
        effect: PolicyEffect.DENY,
        priority: 51,
        toolPattern: '*',
        permission: Permission.EXECUTE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        pathConstraints: {
          denied: [
            '**/.env*', '**/.ssh/**', '**/.aws/**',
            '**/credentials*', '**/*.pem', '**/*.key',
          ],
        },
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'allow-sandboxed-files',
        description: `Allow file operations within ${rootDir}`,
        effect: PolicyEffect.ALLOW,
        priority: 100,
        toolPattern: 'file_*',
        permission: Permission.EXECUTE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        pathConstraints: {
          rootDirectory: rootDir,
          allowed: [`${rootDir}/**`],
        },
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'allow-all-execute',
        description: 'Allow all other tool executions',
        effect: PolicyEffect.ALLOW,
        priority: 1000,
        toolPattern: '*',
        permission: Permission.EXECUTE,
        minimumTrustLevel: TrustLevel.UNTRUSTED,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
    ],
    createdAt: now,
    updatedAt: now,
  };
}

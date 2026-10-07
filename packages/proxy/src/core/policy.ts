// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import type { Permission } from './permissions.js';
import type { TrustLevel } from './trust.js';

/**
 * Policy effect: the only two outcomes of policy evaluation.
 * No "MAYBE" or "CONDITIONAL" - binary security decisions only.
 */
export const PolicyEffect = {
  ALLOW: 'ALLOW',
  DENY: 'DENY',
} as const;

export type PolicyEffect = (typeof PolicyEffect)[keyof typeof PolicyEffect];

/**
 * A single policy rule that matches against execution requests.
 * Rules are evaluated by priority order. First matching rule wins.
 * If NO rule matches, the result is DENY (default-deny).
 */
export interface PolicyRule {
  readonly id: string;
  readonly description: string;
  readonly effect: PolicyEffect;
  readonly priority: number;
  readonly toolPattern: string;
  readonly permission?: Permission;
  readonly minimumTrustLevel: TrustLevel;
  readonly argumentConstraints?: Record<string, unknown>;
  readonly pathConstraints?: {
    readonly allowed?: readonly string[];
    readonly denied?: readonly string[];
    readonly rootDirectory?: string;
    readonly allowSymlinks?: boolean;
  };
  readonly commandConstraints?: {
    readonly allowed?: readonly string[];
    readonly denied?: readonly string[];
  };
  readonly filenameConstraints?: {
    readonly allowed?: readonly string[];
    readonly denied?: readonly string[];
  };
  readonly urlConstraints?: {
    readonly allowed?: readonly string[];
    readonly denied?: readonly string[];
  };
  readonly enabled: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * A versioned, ordered set of policy rules.
 * Modifications create new sets (immutable by convention).
 */
export interface PolicySet {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly version: number;
  readonly rules: readonly PolicyRule[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export const PolicyRuleSchema = z.object({
  id: z.string().min(1).max(256),
  description: z.string().max(1024),
  effect: z.enum(['ALLOW', 'DENY']),
  priority: z.number().int().min(0).max(10000).default(1000),
  toolPattern: z.string().min(1).max(512),
  permission: z.enum(['READ', 'WRITE', 'EXECUTE', 'NETWORK']).optional(),
  minimumTrustLevel: z.enum(['UNTRUSTED', 'VERIFIED', 'TRUSTED']),
  argumentConstraints: z.record(z.unknown()).optional(),
  pathConstraints: z
    .object({
      allowed: z.array(z.string()).optional(),
      denied: z.array(z.string()).optional(),
      rootDirectory: z.string().optional(),
      allowSymlinks: z.boolean().optional(),
    })
    .optional(),
  commandConstraints: z
    .object({
      allowed: z.array(z.string()).optional(),
      denied: z.array(z.string()).optional(),
    })
    .optional(),
  filenameConstraints: z
    .object({
      allowed: z.array(z.string()).optional(),
      denied: z.array(z.string()).optional(),
    })
    .optional(),
  urlConstraints: z
    .object({
      allowed: z.array(z.string()).optional(),
      denied: z.array(z.string()).optional(),
    })
    .optional(),
  enabled: z.boolean().default(true),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});


export const PolicySetSchema = z.object({
  id: z.string().min(1).max(256),
  name: z.string().min(1).max(256),
  description: z.string().max(2048),
  version: z.number().int().min(0),
  rules: z.array(PolicyRuleSchema),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

/** The result of evaluating a policy against a request. */
export interface PolicyDecision {
  readonly effect: PolicyEffect;
  readonly matchedRule: PolicyRule | null;
  readonly reason: string;
  readonly timestamp: string;
  readonly evaluationTimeMs: number;
  readonly metadata?: {
    readonly evaluatedRules: number;
    readonly ruleIds?: readonly string[];
    readonly requestContext: {
      readonly tool: string;
      readonly arguments: readonly string[];
    };
  };
}

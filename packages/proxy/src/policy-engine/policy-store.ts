// SPDX-License-Identifier: Apache-2.0

import type { PolicySet, PolicyRule } from '../core/index.js';
import { createHash } from 'node:crypto';

/** Key-order-independent JSON serialization for stable comparisons. */
function stableStringify(val: unknown): string {
  return JSON.stringify(val, (_key, v) =>
    v !== null && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b)))
      : v,
  );
}

/**
 * A versioned snapshot of a policy set.
 * Immutable once created - modifications create new versions.
 */
export interface PolicyVersion {
  readonly version: number;
  readonly policySet: PolicySet;
  readonly hash: string;
  readonly reason: string;
  readonly createdBy: string;
  readonly createdAt: string;
}

/**
 * Diff between two policy versions.
 */
export interface PolicyDiff {
  readonly added: readonly PolicyRule[];
  readonly removed: readonly PolicyRule[];
  readonly modified: readonly { readonly old: PolicyRule; readonly new: PolicyRule }[];
}

/**
 * In-memory versioned policy store.
 * Stores complete history of policy changes with cryptographic hashes.
 *
 * Security properties:
 * - Immutable versions: once saved, a version cannot be modified
 * - Hash chain: each version includes SHA256 of the policy content
 * - Full history: no version is ever deleted
 */
export class PolicyStore {
  private readonly versions = new Map<string, PolicyVersion[]>();

  /**
   * Saves a new version of a policy set.
   * The version number auto-increments.
   */
  saveVersion(
    policySet: PolicySet,
    reason: string,
    createdBy: string,
  ): PolicyVersion {
    const id = policySet.id;
    const history = this.versions.get(id) ?? [];

    const latestVersion = history.length > 0 ? history[history.length - 1]!.version : 0;

    const version: PolicyVersion = {
      version: latestVersion + 1,
      policySet: Object.freeze({ ...policySet }),
      hash: this.computeHash(policySet),
      reason,
      createdBy,
      createdAt: new Date().toISOString(),
    };

    history.push(version);
    this.versions.set(id, history);

    return version;
  }

  /**
   * Gets a specific version of a policy set.
   */
  getVersion(id: string, version: number): PolicyVersion | null {
    const history = this.versions.get(id);
    if (!history) return null;
    return history.find((v) => v.version === version) ?? null;
  }

  /**
   * Gets the latest version of a policy set.
   */
  getLatest(id: string): PolicyVersion | null {
    const history = this.versions.get(id);
    if (!history || history.length === 0) return null;
    return history[history.length - 1]!;
  }

  /**
   * Gets the full version history of a policy set.
   */
  getHistory(id: string): readonly PolicyVersion[] {
    return this.versions.get(id) ?? [];
  }

  /**
   * Rolls back to a previous version by creating a new version
   * with the same content as the target version.
   */
  rollback(id: string, toVersion: number): PolicyVersion {
    const target = this.getVersion(id, toVersion);
    if (!target) {
      throw new Error(`Version ${toVersion} not found for policy "${id}"`);
    }

    return this.saveVersion(
      target.policySet,
      `Rollback to version ${toVersion}`,
      'system',
    );
  }

  /**
   * Computes a diff between two policy versions.
   */
  diff(v1: PolicyVersion, v2: PolicyVersion): PolicyDiff {
    const oldRulesMap = new Map(v1.policySet.rules.map((r) => [r.id, r]));
    const newRulesMap = new Map(v2.policySet.rules.map((r) => [r.id, r]));

    const added: PolicyRule[] = [];
    const removed: PolicyRule[] = [];
    const modified: { old: PolicyRule; new: PolicyRule }[] = [];

    // Find added and modified rules
    for (const [id, newRule] of newRulesMap) {
      const oldRule = oldRulesMap.get(id);
      if (!oldRule) {
        added.push(newRule);
      } else if (stableStringify(oldRule) !== stableStringify(newRule)) {
        modified.push({ old: oldRule, new: newRule });
      }
    }

    // Find removed rules
    for (const [id, oldRule] of oldRulesMap) {
      if (!newRulesMap.has(id)) {
        removed.push(oldRule);
      }
    }

    return { added, removed, modified };
  }

  /**
   * Computes SHA256 hash of a policy set for integrity verification.
   */
  computeHash(policySet: PolicySet): string {
    const serialized = JSON.stringify(policySet, (_key, val) =>
      val !== null && typeof val === 'object' && !Array.isArray(val)
        ? Object.fromEntries(Object.entries(val).sort(([a], [b]) => a.localeCompare(b)))
        : val,
    );
    return createHash('sha256').update(serialized).digest('hex');
  }
}

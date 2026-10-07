// SPDX-License-Identifier: Apache-2.0

/**
 * The policy, which is a file on this machine.
 *
 * Every signature here is the one the commands and the TUI were already written
 * against, and every one of them used to be an HTTP call. The types are unchanged
 * too: what changed is that the answer comes from ~/.solongate/policy.json — the
 * same file the guard reads on every tool call.
 *
 * ONE FILE MEANS ONE POLICY, and that is the only place the shape of this module
 * shows its history. A service held many and pinned one as active; a machine holds
 * the one it enforces. `list` answers with it or with nothing, and the operations
 * that only make sense among several say so plainly rather than pretending.
 *
 * Still async, because every caller awaits them and a file read is fast enough
 * that there is nothing to gain by making them all change.
 */
import { createHash } from 'node:crypto';
import { existsSync, rmSync } from 'node:fs';
import * as store from './local-store.js';
import type {
  ActivePolicy,
  PolicyDetail,
  PolicyListEntry,
  PolicyRule,
  PolicySet,
} from './types.js';

const { LocalStoreError } = store;

/** The version a policy reports. There is no history, so it is always 1. */
const VERSION = 1;

const hashOf = (p: PolicySet): string =>
  createHash('sha256').update(JSON.stringify(p.rules ?? [])).digest('hex').slice(0, 16);

function detail(p: PolicySet): PolicyDetail {
  return {
    ...p,
    mode: p.mode ?? 'denylist',
    rules: p.rules ?? [],
    _version: VERSION,
    _hash: hashOf(p),
    _created_at: new Date(0).toISOString(),
  };
}

export async function list(): Promise<{ policies: PolicyListEntry[] }> {
  const p = store.policy();
  if (!p) return { policies: [] };
  return {
    policies: [{
      id: p.id,
      name: p.name,
      rules: p.rules ?? [],
      mode: p.mode ?? 'denylist',
      version: VERSION,
      hash: hashOf(p),
      created_by: 'this machine',
      created_at: new Date(0).toISOString(),
    }],
  };
}

export async function get(id: string, _version?: number): Promise<PolicyDetail> {
  const p = store.policy();
  store.resolveId(id, p);
  return detail(p!);
}

export async function create(policy: PolicySet): Promise<PolicyDetail> {
  // Refused rather than merged. Overwriting would throw away rules that are
  // being enforced right now, and this is the command somebody runs when they
  // think the machine has nothing.
  if (store.policy()) {
    throw new LocalStoreError(
      'this machine already has a policy. `solongate policy show local` prints it, '
      + '`solongate policy delete local` removes it.',
    );
  }
  const p: PolicySet = {
    id: policy.id || 'local',
    name: policy.name || 'local',
    mode: policy.mode ?? 'denylist',
    rules: policy.rules ?? [],
    ...(policy.description ? { description: policy.description } : {}),
    ...(policy.agents ? { agents: policy.agents } : {}),
  };
  store.savePolicy(p);
  return detail(p);
}

export async function update(id: string, policy: PolicySet): Promise<PolicyDetail> {
  const current = store.policy();
  store.resolveId(id, current);
  const p: PolicySet = { ...current!, ...policy, id: current!.id };
  store.savePolicy(p);
  return detail(p);
}

export async function remove(id: string): Promise<{ deleted: boolean; policy_id: string }> {
  const p = store.policy();
  store.resolveId(id, p);
  const s = store.read();
  // The LAYERS survive. A rate limit and a DLP configuration are not part of the
  // rule list, and deleting rules must not silently switch the DLP scanner off.
  if (s.security || s.selfProtect !== null) store.write({ ...s, policy: null });
  else if (existsSync(store.policyPath())) rmSync(store.policyPath());
  return { deleted: true, policy_id: p!.id };
}

export interface RuleSpec {
  toolPattern?: string;
  kind?: 'command' | 'path' | 'filename' | 'url' | 'tool';
  value?: string;
  effect?: 'ALLOW' | 'DENY';
  /** Scopes the rule to a class of call. Absent means every class. */
  permission?: string[];
}

/** The constraint field a `kind` lands in. `tool` narrows toolPattern instead. */
const CONSTRAINT: Record<string, keyof PolicyRule> = {
  command: 'commandConstraints',
  path: 'pathConstraints',
  filename: 'filenameConstraints',
  url: 'urlConstraints',
};

export async function addRule(
  id: string,
  spec: RuleSpec,
): Promise<{ ok: true; deduped: boolean; rule?: PolicyRule; policy_id: string; policy_version?: number; message?: string }> {
  const current = store.policy();
  store.resolveId(id, current);
  const rules = (current!.rules ?? []).slice();
  const effect = spec.effect ?? 'DENY';
  const toolPattern = spec.kind === 'tool' && spec.value ? spec.value : spec.toolPattern ?? '*';

  const rule: PolicyRule = {
    id: store.nextRuleId(rules),
    description: describe(effect, spec),
    effect,
    // Highest first, and above whatever is already there: a rule somebody just
    // added is the one they expect to decide the next call.
    priority: Math.max(10, ...rules.map((r) => r.priority || 0)) + 1,
    toolPattern,
    minimumTrustLevel: 'UNTRUSTED',
    enabled: true,
    ...(spec.permission?.length ? { permission: spec.permission as PolicyRule['permission'] } : {}),
  };
  if (spec.kind && spec.kind !== 'tool' && spec.value) {
    const field = CONSTRAINT[spec.kind];
    const side = effect === 'ALLOW' ? 'allowed' : 'denied';
    (rule as unknown as Record<string, unknown>)[field as string] = { [side]: [spec.value] };
  }

  // Deduped by what the rule DOES, not by its generated id.
  const same = (a: PolicyRule): boolean =>
    a.effect === rule.effect
    && a.toolPattern === rule.toolPattern
    && JSON.stringify(constraintsOf(a)) === JSON.stringify(constraintsOf(rule));
  const existing = rules.find(same);
  if (existing) {
    return { ok: true, deduped: true, rule: existing, policy_id: current!.id, policy_version: VERSION };
  }

  rules.push(rule);
  store.savePolicy({ ...current!, rules });
  return { ok: true, deduped: false, rule, policy_id: current!.id, policy_version: VERSION };
}

const constraintsOf = (r: PolicyRule): unknown => ({
  command: r.commandConstraints ?? null,
  path: r.pathConstraints ?? null,
  filename: r.filenameConstraints ?? null,
  url: r.urlConstraints ?? null,
});

function describe(effect: string, spec: RuleSpec): string {
  const verb = effect === 'ALLOW' ? 'Allow' : 'Block';
  if (spec.kind === 'tool' && spec.value) return `${verb} the ${spec.value} tool`;
  if (spec.kind && spec.value) return `${verb} ${spec.kind} ${spec.value}`;
  return `${verb} ${spec.toolPattern ?? '*'}`;
}

export async function revokeRule(
  id: string,
  ruleId: string,
): Promise<{ ok: true; revoked: string; policy_id: string; policy_version: number }> {
  const current = store.policy();
  store.resolveId(id, current);
  const rules = current!.rules ?? [];
  if (!rules.some((r) => r.id === ruleId)) {
    throw new LocalStoreError(`no rule ${ruleId} in this policy. \`solongate policy show local\` lists them.`);
  }
  store.savePolicy({ ...current!, rules: rules.filter((r) => r.id !== ruleId) });
  return { ok: true, revoked: ruleId, policy_id: current!.id, policy_version: VERSION };
}

/**
 * What the guard would enforce on the next call.
 *
 * Read from the same file it reads, so this is not a report about what should
 * happen — it is the input to what does.
 */
export async function active(_agentId?: string): Promise<ActivePolicy> {
  const s = store.read();
  const layers = store.toLayers(s.security);
  return {
    policy: s.policy,
    version: VERSION,
    hash: s.policy ? hashOf(s.policy) : undefined,
    matched_by: 'pinned',
    self_protection_enabled: s.selfProtect !== false,
    security: {
      rateLimit: layers.rateLimit.mode === 'block'
        ? { perMinute: layers.rateLimit.perMinute, perHour: layers.rateLimit.perHour, perDay: layers.rateLimit.perDay }
        : null,
      // One key per mode, the same shape the guard reads off disk: detect writes
      // dlpObserve, redact writes dlpRedact, block writes both. `mode !== 'off'`
      // used to fill dlpRedact for every mode, which is how detect came to
      // redact.
      dlpBlock: layers.dlp.mode === 'block' ? { patterns: layers.dlp.patterns, custom: layers.dlp.custom } : null,
      dlpRedact: layers.dlp.mode === 'block' || layers.dlp.mode === 'redact'
        ? { patterns: layers.dlp.patterns, custom: layers.dlp.custom } : null,
      dlpObserve: layers.dlp.mode === 'detect' ? { patterns: layers.dlp.patterns, custom: layers.dlp.custom } : null,
      localLogs: s.security?.localLogs ?? null,
    },
    hook_versions: { guard: 0, audit: 0, shield: 0 },
  };
}

/**
 * There is nothing to pin.
 *
 * A service kept several policies and chose one; the file IS the choice. Saying
 * so is better than accepting the call and changing nothing, which is what a
 * no-op would do to `solongate policy activate`.
 */
export async function setActive(policyId: string | null): Promise<{ ok: true; active: string | null }> {
  if (policyId === null) {
    throw new LocalStoreError(
      'nothing to switch off: enforcement is this machine\'s policy file. '
      + '`solongate policy delete local` stops it, or set every rule to disabled.',
    );
  }
  const p = store.policy();
  store.resolveId(policyId, p);
  // Asking to activate the policy that is already the only one is not an error.
  return { ok: true, active: p!.id };
}

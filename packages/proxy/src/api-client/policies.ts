/** Policy endpoints (/api/v1/policies/*). */
import { request } from './client.js';
import type {
  ActivePolicy,
  PolicyDetail,
  PolicyListEntry,
  PolicyMode,
  PolicyRule,
  PolicySet,
  PolicyVersion,
} from './types.js';

export function list(): Promise<{ policies: PolicyListEntry[] }> {
  return request('GET', '/policies');
}

export function get(id: string, version?: number): Promise<PolicyDetail> {
  return request('GET', `/policies/${encodeURIComponent(id)}`, {
    query: version !== undefined ? { version } : undefined,
  });
}

export function create(policy: PolicySet): Promise<PolicyDetail> {
  return request('POST', '/policies', { body: policy });
}

export function update(id: string, policy: PolicySet): Promise<PolicyDetail> {
  return request('PUT', `/policies/${encodeURIComponent(id)}`, { body: policy });
}

export function remove(id: string): Promise<{ deleted: boolean; policy_id: string }> {
  return request('DELETE', `/policies/${encodeURIComponent(id)}`);
}

export interface RuleSpec {
  toolPattern?: string;
  kind?: 'command' | 'path' | 'filename' | 'url' | 'tool';
  value?: string;
  effect?: 'ALLOW' | 'DENY';
  /** Scopes the rule to a class of call. Absent means every class. */
  permission?: string[];
}

export function addRule(
  id: string,
  spec: RuleSpec,
): Promise<{ ok: true; deduped: boolean; rule?: PolicyRule; policy_id: string; policy_version?: number; message?: string }> {
  return request('POST', `/policies/${encodeURIComponent(id)}/rules`, { body: spec });
}

export function revokeRule(
  id: string,
  ruleId: string,
): Promise<{ ok: true; revoked: string; policy_id: string; policy_version: number }> {
  return request('DELETE', `/policies/${encodeURIComponent(id)}/rules/${encodeURIComponent(ruleId)}`);
}

export function versions(
  id: string,
  opts: { limit?: number; offset?: number } = {},
): Promise<{ versions: PolicyVersion[]; pagination: { total: number; limit: number; offset: number } }> {
  return request('GET', `/policies/${encodeURIComponent(id)}/versions`, { query: opts });
}

export function rollback(
  id: string,
  version: number,
): Promise<{ version: number; rolled_back_from: number; policy_id: string; hash: string }> {
  return request('POST', `/policies/${encodeURIComponent(id)}/rollback`, { body: { version } });
}

export function active(agentId?: string): Promise<ActivePolicy> {
  return request('GET', '/policies/active', { query: agentId ? { agent_id: agentId } : undefined });
}

export function setActive(policyId: string | null): Promise<{ ok: true; active: string | null }> {
  return request('POST', '/policies/active', { body: { policyId: policyId ?? '' } });
}

export interface DryRunResult {
  evaluated: number;
  would_allow: number;
  would_deny: number;
  newly_blocked: number;
  newly_allowed: number;
  unchanged: number;
  sample_newly_blocked: Array<{ tool: string; preview: string; predicted: string; created_at: string }>;
  sample_newly_allowed: Array<{ tool: string; preview: string; predicted: string; created_at: string }>;
  mode: PolicyMode;
  sampled: number;
  limit: number;
}

export function dryRun(body: {
  rules: PolicyRule[] | Partial<PolicyRule>[];
  mode?: PolicyMode;
  limit?: number;
  from?: number;
  to?: number;
}): Promise<DryRunResult> {
  return request('POST', '/policies/dry-run', { body });
}

// ── Backtest: the FULL dry-run the dashboard's "Policy Dry Run" page uses ────
// Richer than /policies/dry-run: per-rule / per-tool / per-agent impact, a
// timeseries and the individual changed calls, so the TUI can render the exact
// same breakdown instead of a one-line summary.
export interface BacktestSummary {
  evaluated: number;
  would_allow: number;
  would_deny: number;
  newly_blocked: number;
  newly_allowed: number;
  unchanged: number;
}
export interface BacktestPerRule { rule_id: string; matched: number; newly_blocked: number; newly_allowed: number }
export interface BacktestPerTool { tool: string; evaluated: number; changed: number; newly_blocked: number; newly_allowed: number }
export interface BacktestPerAgent { agent: string; evaluated: number; changed: number; newly_blocked: number; newly_allowed: number }
export interface BacktestBucket { bucket: number; evaluated: number; newly_blocked: number; newly_allowed: number }
export interface BacktestSample {
  id: string;
  tool: string;
  agent: string;
  preview: string;
  original: string;
  predicted: string;
  matched_rule_id: string | null;
  created_at: string | number;
}
export interface BacktestResult {
  mode: 'bulk';
  engine: string;
  sampled?: number;
  limit?: number;
  summary: BacktestSummary;
  per_rule: BacktestPerRule[];
  per_tool: BacktestPerTool[];
  per_agent: BacktestPerAgent[];
  timeseries: BacktestBucket[];
  samples: BacktestSample[];
}

export function backtest(body: {
  rules: PolicyRule[] | Partial<PolicyRule>[];
  mode?: PolicyMode;
  limit?: number;
  from?: number;
  to?: number;
}): Promise<BacktestResult> {
  return request('POST', '/policies/backtest', { body });
}

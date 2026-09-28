/**
 * The audit trail, which is the file the hooks append to.
 *
 * ~/.solongate/local-logs/solongate-audit.jsonl, one JSON object per line: the
 * guard writes a denial before it answers the agent, and the post-tool hook
 * writes everything else. Reading it is all this module does.
 *
 * An entry's ID IS ITS LINE NUMBER, which is what makes `audit whitelist <id>`
 * work against a file: the log is append-only, so line 41 is still line 41 after
 * a hundred more calls.
 */
import * as store from './local-store.js';
import * as policies from './policies.js';
import type { AuditList } from './types.js';

const { LocalStoreError } = store;

export interface AuditQuery {
  filter?: 'ALLOW' | 'DENY' | 'DENIED';
  tool?: string;
  limit?: number;
  offset?: number;
  from?: number;
  to?: number;
  agent_name?: string;
  session_id?: string;
  search?: string;
  signal?: 'dlp' | 'ratelimit';
}

export async function list(query: AuditQuery = {}): Promise<AuditList> {
  const out = store.auditList({
    limit: query.limit,
    offset: query.offset,
    // DENIED is what one of the two callers sends; both mean the same decision.
    decision: query.filter === 'DENIED' ? 'DENY' : query.filter,
    tool: query.tool,
    search: query.search,
    signal: query.signal,
    agentName: query.agent_name,
  });
  if (query.session_id) {
    const kept = out.entries.filter((e) => e.session_id === query.session_id);
    return { ...out, entries: kept, total: kept.length };
  }
  if (query.from !== undefined || query.to !== undefined) {
    const from = query.from ?? -Infinity;
    const to = query.to ?? Infinity;
    const kept = out.entries.filter((e) => {
      const at = Date.parse(e.created_at);
      return Number.isFinite(at) && at >= from && at <= to;
    });
    return { ...out, entries: kept, total: kept.length };
  }
  return out;
}

/*
 * There is no remove() and no removeAll(). Both used to call
 * `DELETE /audit-logs`; the endpoint is gone, because an audit log the audited
 * party can clear is not a record of anything. Nothing in this CLI called them.
 */

type RuleOutcome = {
  ok: true;
  deduped: boolean;
  scope: string;
  policy_id: string;
  policy_version?: number;
  message?: string;
};

/**
 * Turn one recorded call into a rule.
 *
 * `exact` narrows to what that call actually did — the command, the path, the URL
 * the entry carries. `tool` covers the tool as a whole, which is the wider and
 * more dangerous of the two, so it is never the default.
 */
async function ruleFor(id: string, scope: 'exact' | 'tool', effect: 'ALLOW' | 'DENY'): Promise<RuleOutcome> {
  const entry = store.logLines().find((l) => l.id === id);
  if (!entry) {
    throw new LocalStoreError(`no entry ${id} in this machine's audit log. \`solongate audit\` lists them.`);
  }
  const tool = entry.tool || '';
  if (!tool) throw new LocalStoreError(`entry ${id} names no tool, so there is nothing to scope a rule to.`);

  let spec: policies.RuleSpec = { toolPattern: tool, effect };
  if (scope === 'exact') {
    const args = (entry.arguments && typeof entry.arguments === 'object'
      ? entry.arguments
      : {}) as Record<string, unknown>;
    // The argument names are the ones the guard records, in the order it prefers
    // to match on: a command is more specific than the file it touched.
    const pick: Array<[policies.RuleSpec['kind'], string[]]> = [
      ['command', ['command', 'cmd', 'script']],
      ['url', ['url', 'uri']],
      ['path', ['file_path', 'path', 'filePath', 'notebook_path']],
      ['filename', ['filename', 'pattern']],
    ];
    for (const [kind, keys] of pick) {
      const key = keys.find((k) => typeof args[k] === 'string' && (args[k] as string).trim());
      if (key) {
        spec = { toolPattern: tool, effect, kind, value: String(args[key]) };
        break;
      }
    }
    if (!spec.kind) {
      // Nothing in the entry to narrow on. Widening silently to the whole tool is
      // exactly the surprise this refuses to be.
      throw new LocalStoreError(
        `entry ${id} records no command, path or URL to narrow on. `
        + `Pass --scope tool to cover the ${tool} tool as a whole.`,
      );
    }
  }

  const res = await policies.addRule('local', spec);
  return {
    ok: true,
    deduped: res.deduped,
    scope,
    policy_id: res.policy_id,
    policy_version: res.policy_version,
    ...(res.message ? { message: res.message } : {}),
  };
}

export const whitelist = (id: string, scope: 'exact' | 'tool' = 'exact'): Promise<RuleOutcome> =>
  ruleFor(id, scope, 'ALLOW');

export const block = (id: string, scope: 'exact' | 'tool' = 'exact'): Promise<RuleOutcome> =>
  ruleFor(id, scope, 'DENY');

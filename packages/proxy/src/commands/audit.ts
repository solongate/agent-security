// SPDX-License-Identifier: Apache-2.0

/** `solongate audit …` - browse audit logs, whitelist a denied call. */
import { api } from '../api-client/index.js';
import type { AuditQuery } from '../api-client/audit.js';
import { flagBool, flagNum, flagStr, parse } from './args.js';
import { bold, cyan, decisionColor, dim, err, green, printJson, red, table, truncate, usage } from './format.js';

const USAGE = usage('solongate audit', 'audit log', [
  ['audit [--filter ALLOW|DENY] [--tool <substr>] [--signal dlp|ratelimit]'],
  ['      [--search <text>] [--agent-name <name>] [--limit N]'],
  ['audit whitelist <logId> [--scope exact|tool]', 'turn a denied call into an ALLOW rule'],
  ['audit block <logId> [--scope exact|tool]', 'turn a call into a DENY rule'],
]);

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const json = flagBool(flags, 'json');

  if (positionals[0] === 'help') return err(USAGE), 0;

  if (positionals[0] === 'whitelist') {
    const id = positionals[1];
    if (!id) return err('  Usage: audit whitelist <logId> [--scope exact|tool]'), 1;
    const scope = (flagStr(flags, 'scope') as 'exact' | 'tool') ?? 'exact';
    const res = await api.audit.whitelist(id, scope);
    if (json) return printJson(res), 0;
    if (res.deduped) err(green('  ✓ ') + dim('Equivalent ALLOW already present.'));
    else err(green(`  ✓ Whitelisted (${res.scope})`) + dim(` → ${res.policy_id} v${res.policy_version}`));
    return 0;
  }

  if (positionals[0] === 'block') {
    const id = positionals[1];
    if (!id) return err('  Usage: audit block <logId> [--scope exact|tool]'), 1;
    const scope = (flagStr(flags, 'scope') as 'exact' | 'tool') ?? 'exact';
    const res = await api.audit.block(id, scope);
    if (json) return printJson(res), 0;
    if (res.deduped) err(green('  ✓ ') + dim('Equivalent DENY already present.'));
    else err(green(`  ✓ Blocked (${res.scope})`) + dim(` → ${res.policy_id} v${res.policy_version}`));
    return 0;
  }

  const query: AuditQuery = {
    filter: flagStr(flags, 'filter') as AuditQuery['filter'],
    tool: flagStr(flags, 'tool'),
    signal: flagStr(flags, 'signal') as AuditQuery['signal'],
    search: flagStr(flags, 'search'),
    agent_name: flagStr(flags, 'agent-name'),
    limit: flagNum(flags, 'limit') ?? 30,
  };
  const res = await api.audit.list(query);
  if (json) return printJson(res), 0;
  err('');
  err(`  ${bold(String(res.total))} matching entries ${dim(`(showing ${res.entries.length})`)}`);
  if (!res.entries.length) return 0;
  table(
    ['DECISION', 'TOOL', 'AGENT', 'REASON', 'DLP', 'WHEN', 'ID'],
    res.entries.map((e) => [
      decisionColor(e.decision),
      cyan(truncate(e.tool_name, 22)),
      dim(truncate(e.agent_name ?? '-', 16)),
      truncate(e.reason ?? '-', 30),
      e.dlp_matches?.length ? red(String(e.dlp_matches.length)) : dim('0'),
      dim(e.created_at),
      dim(truncate(e.id, 10)),
    ]),
  );
  return 0;
}

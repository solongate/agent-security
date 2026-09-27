/** `solongate sessions` / `solongate session <id>` - live agent-session feed & detail. */
import { api } from '../api-client/index.js';
import { flagBool, flagNum, parse } from './args.js';
import { bold, cyan, dim, err, green, printJson, red, table, truncate, yellow } from './format.js';

const statusColor = (s: string): string => (s === 'active' ? green(s) : s === 'idle' ? yellow(s) : dim(s));

/** `solongate agents` - the live feed. */
export async function runAgents(argv: string[]): Promise<number> {
  const { flags } = parse(argv);
  const json = flagBool(flags, 'json');
  const res = await api.agents.live({ limit: flagNum(flags, 'limit'), includeDeactivated: flagBool(flags, 'all') });
  if (json) return printJson(res), 0;
  err('');
  err(`  Sessions   ${green(String(res.counts.active))} active   ${yellow(String(res.counts.idle))} idle   ${dim(String(res.counts.deactivated) + ' off')}`);
  if (!res.agents.length) return err(dim('  No agent sessions.')), 0;
  table(
    ['STATUS', 'AGENT', 'CALLS', 'DENY', 'DLP', 'TRUST', 'CHARACTER'],
    res.agents.map((a) => [
      statusColor(a.status),
      cyan(truncate(a.agent_name ?? a.agent_id ?? a.session_id, 20)),
      String(a.total_calls),
      a.denied_calls ? red(String(a.denied_calls)) : dim('0'),
      a.dlp_events ? red(String(a.dlp_events)) : dim('0'),
      `${a.trust_score}`,
      dim(truncate(a.character || '-', 22)),
    ]),
  );
  return 0;
}

/** `solongate agent <id>` - deep detail for one agent. */
export async function runAgent(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const json = flagBool(flags, 'json');
  const id = positionals[0];
  if (!id) return err('  Usage: solongate session <id> [--json]'), 1;
  const a = await api.agents.get(id) as Record<string, any>;
  if (json) return printJson(a), 0;
  err('');
  err(`  ${bold(a.agent_id)}   status: ${statusColor(String(a.status))}`);
  const base = a.baseline as Record<string, any> | undefined;
  if (base) {
    err(`  ${dim(base.character ?? '')}   trust ${bold(String(base.trustScore ?? '-'))}/100   deny-rate ${(Number(base.denyRate ?? 0) * 100).toFixed(0)}%`);
  }
  const feed = (a.recent_feed as Array<Record<string, any>>) ?? [];
  if (feed.length) {
    err(dim('\n  Recent:'));
    table(
      ['DECISION', 'TOOL', 'REASON', 'WHEN'],
      feed.slice(0, 15).map((f) => [
        f.decision === 'ALLOW' ? green('ALLOW') : red(String(f.decision)),
        cyan(truncate(String(f.tool), 22)),
        truncate(String(f.reason ?? '-'), 30),
        dim(String(f.created_at)),
      ]),
    );
  }
  return 0;
}

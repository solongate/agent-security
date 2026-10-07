// SPDX-License-Identifier: Apache-2.0

/** `solongate stats …` - overview, timeseries sparklines, denial drift. */
import { api } from '../api-client/index.js';
import { flagBool, flagNum, flagStr, parse } from './args.js';
import { bold, cyan, decisionColor, dim, err, green, printJson, red, sparkline, table, truncate, unknownSub, usage } from './format.js';

const USAGE = usage('solongate stats', 'traffic & security stats', [
  ['stats', 'overview (totals, recent activity)'],
  ['stats timeseries [--period 24h|7d|30d|all]'],
  ['stats drift [--days N]', 'denials rising/falling vs previous window'],
]);

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0] ?? 'overview';
  const json = flagBool(flags, 'json');

  switch (sub) {
    case 'help':
      return err(USAGE), 0;

    case 'overview': {
      const s = await api.stats.get();
      if (json) return printJson(s), 0;
      err('');
      err(`  ${bold(String(s.total_calls))} calls   ${green(String(s.allowed))} allowed   ${red(String(s.denied))} denied`);
      err(`  ${dim(`${s.active_policies} active policies · ${s.registered_tools} tools`)}`);
      if (s.recent_activity.length) {
        err(dim('\n  Recent:'));
        table(
          ['DECISION', 'TOOL', 'TRUST', 'MS', 'WHEN'],
          s.recent_activity.map((a) => [
            decisionColor(a.decision),
            cyan(truncate(a.tool_name, 24)),
            dim(a.trust_level),
            String(a.evaluation_time_ms ?? '-'),
            dim(a.created_at),
          ]),
        );
      }
      return 0;
    }

    case 'timeseries': {
      const period = (flagStr(flags, 'period') as '24h' | '7d' | '30d' | 'all') ?? '24h';
      const ts = await api.stats.timeseries({ period });
      if (json) return printJson(ts), 0;
      const pts = ts.timeseries;
      err('');
      err(`  Timeseries ${dim(`(${ts.period}, per ${ts.granularity})`)}`);
      err(`  total    ${cyan(sparkline(pts.map((p) => p.total)))}  ${dim(`max ${Math.max(0, ...pts.map((p) => p.total))}`)}`);
      err(`  allowed  ${green(sparkline(pts.map((p) => p.allowed)))}`);
      err(`  denied   ${red(sparkline(pts.map((p) => p.denied)))}`);
      return 0;
    }

    case 'drift': {
      const d = await api.stats.drift(flagNum(flags, 'days'));
      if (json) return printJson(d), 0;
      err('');
      err(`  Denial drift ${dim(`(${d.days}d: ${d.total_current} now vs ${d.total_previous} prev)`)}`);
      if (!d.rules.length) return err(dim('  No denials in window.')), 0;
      table(
        ['NOW', 'PREV', 'Δ', 'RULE', 'REASON'],
        d.rules.slice(0, 20).map((r) => [
          bold(String(r.current)),
          dim(String(r.previous)),
          r.is_new ? green('NEW') : r.spike ? red(`+${r.delta}`) : String(r.delta),
          cyan(truncate(r.rule_id ?? '-', 22)),
          truncate(r.reason ?? r.last_tool ?? '-', 36),
        ]),
      );
      return 0;
    }

    default:
      return unknownSub('stats', sub, USAGE);
  }
}

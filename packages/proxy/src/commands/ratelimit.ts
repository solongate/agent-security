/** `solongate ratelimit …` - view/set the rate-limit layer + history sparkline. */
import { api } from '../api-client/index.js';
import type { LayerMode } from '../api-client/index.js';
import { flagBool, flagNum, flagStr, parse } from './args.js';
import { bold, cyan, dim, err, green, printJson, sparkline, table, unknownSub, usage, yellow } from './format.js';

const USAGE = usage('solongate ratelimit', 'request throttling', [
  ['ratelimit show', 'current limits + change history'],
  ['ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]'],
  ['ratelimit history', 'recent limit changes'],
]);

const modeColor = (m: string): string => (m === 'block' ? green(m) : m === 'detect' ? yellow(m) : dim(m));

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0] ?? 'show';
  const json = flagBool(flags, 'json');

  switch (sub) {
    case 'help':
      return err(USAGE), 0;

    case 'show': {
      const [{ layers }, { history }] = await Promise.all([
        api.settings.getSecurityLayers(),
        api.settings.getRateLimitHistory(),
      ]);
      if (json) return printJson({ rateLimit: layers.rateLimit, history }), 0;
      const rl = layers.rateLimit;
      err('');
      err(`  Rate limit   mode: ${modeColor(rl.mode)}`);
      err(`  ${bold(String(rl.perMinute))} ${dim('/min')}   ${bold(String(rl.perHour))} ${dim('/hour')}   ${bold(String(rl.perDay))} ${dim('/day')}`);
      if (history.length) {
        const spark = sparkline(history.map((h) => h.minute));
        err(`  history      ${cyan(spark)} ${dim(`(${history.length} changes, per-min)`)}`);
      }
      return 0;
    }

    case 'history': {
      const { history } = await api.settings.getRateLimitHistory();
      if (json) return printJson(history), 0;
      if (!history.length) return err(dim('  No rate-limit changes recorded.')), 0;
      table(
        ['WHEN', 'MINUTE', 'HOUR', 'DAY'],
        history.map((h) => [dim(new Date(h.ts).toISOString()), String(h.minute), String(h.hour), String(h.day)]),
      );
      return 0;
    }

    case 'set': {
      const minute = flagNum(flags, 'minute');
      const hour = flagNum(flags, 'hour');
      const day = flagNum(flags, 'day');
      const mode = flagStr(flags, 'mode') as LayerMode | undefined;
      if (minute === undefined && hour === undefined && day === undefined && !mode) {
        return err('  Usage: ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]'), 1;
      }
      const { layers } = await api.settings.getSecurityLayers();
      const next = {
        ...layers,
        rateLimit: {
          mode: mode ?? layers.rateLimit.mode,
          perMinute: minute ?? layers.rateLimit.perMinute,
          perHour: hour ?? layers.rateLimit.perHour,
          perDay: day ?? layers.rateLimit.perDay,
        },
      };
      const res = await api.settings.setSecurityLayers(next);
      if (json) return printJson(res.layers.rateLimit), 0;
      const r = res.layers.rateLimit;
      err(green('  ✓ Rate limit updated') + dim(`  ${r.perMinute}/min ${r.perHour}/h ${r.perDay}/day  (${r.mode})`));
      return 0;
    }

    default:
      return unknownSub('ratelimit', sub, USAGE);
  }
}

/** `solongate alerts …` - denial alert rules (Telegram / email on a spike). */
import { api } from '../api-client/index.js';
import { flagBool, flagNum, flagStr, parse } from './args.js';
import { cyan, dim, err, green, printJson, table, unknownSub, usage } from './format.js';

const USAGE = usage('solongate alerts', 'spike alerts (Telegram / email)', [
  ['alerts list'],
  ['alerts add --signal deny|dlp|ratelimit|any --threshold N --window S'],
  ['             (--email <a> | --telegram <chatId> | --slack <url>)'],
  ['alerts remove <id>'],
]);

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0] ?? 'list';
  const json = flagBool(flags, 'json');

  switch (sub) {
    case 'help':
      return err(USAGE), 0;
    case 'list': {
      const { rules } = await api.settings.getAlerts();
      if (json) return printJson(rules), 0;
      if (!rules.length) return err(dim('  No alert rules.')), 0;
      table(
        ['ID', 'ON', 'SIGNAL', 'THRESH', 'WINDOW', 'CHANNELS'],
        rules.map((r) => [
          dim(r.id),
          r.enabled ? green('●') : dim('○'),
          cyan(r.signal),
          `${r.threshold}`,
          `${r.windowSeconds}s`,
          dim([...(r.emails ?? []), ...(r.telegram ?? []).map((t) => 'tg:' + t), ...(r.slackUrls ?? []).map(() => 'slack')].join(' ') || '-'),
        ]),
      );
      return 0;
    }
    case 'add': {
      const email = flagStr(flags, 'email');
      const telegram = flagStr(flags, 'telegram');
      const slack = flagStr(flags, 'slack');
      if (!email && !telegram && !slack) return err('  Need a channel: --email / --telegram / --slack'), 1;
      const res = await api.settings.createAlert({
        signal: (flagStr(flags, 'signal') as 'any' | 'deny' | 'dlp' | 'ratelimit') ?? 'deny',
        threshold: flagNum(flags, 'threshold') ?? 5,
        windowSeconds: flagNum(flags, 'window') ?? 300,
        emails: email ? [email] : undefined,
        telegram: telegram ? [telegram] : undefined,
        slackUrl: slack,
      });
      if (json) return printJson(res.rule), 0;
      return err(green(`  ✓ Alert added (${res.rule.signal}, ${res.rule.threshold}/${res.rule.windowSeconds}s)`)), 0;
    }
    case 'remove': {
      const id = positionals[1];
      if (!id) return err('  Usage: alerts remove <id>'), 1;
      await api.settings.deleteAlert(id);
      if (json) return printJson({ ok: true, id }), 0;
      return err(green(`  ✓ Removed ${id}`)), 0;
    }
    default:
      return unknownSub('alerts', sub, USAGE);
  }
}

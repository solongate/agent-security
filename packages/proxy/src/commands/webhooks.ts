/** `solongate webhooks …` - stream every guarded event to a URL. */
import { api } from '../api-client/index.js';
import { flagBool, flagStr, parse } from './args.js';
import { cyan, dim, err, green, printJson, table, truncate, unknownSub, usage } from './format.js';

const USAGE = usage('solongate webhooks', 'event webhooks', [
  ['webhooks list'],
  ['webhooks add --url <https://…> [--events denials|allowed|all]'],
  ['webhooks remove <id>'],
]);

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0] ?? 'list';
  const json = flagBool(flags, 'json');

  switch (sub) {
    case 'help':
      return err(USAGE), 0;
    case 'list': {
      const { webhooks } = await api.settings.getWebhooks();
      if (json) return printJson(webhooks), 0;
      if (!webhooks.length) return err(dim('  No webhooks.')), 0;
      table(
        ['ID', 'ON', 'EVENTS', 'URL'],
        webhooks.map((w) => [dim(w.id), w.enabled ? green('●') : dim('○'), cyan(w.events), dim(truncate(w.url, 46))]),
      );
      return 0;
    }
    case 'add': {
      const url = flagStr(flags, 'url');
      if (!url) return err('  Usage: webhooks add --url <https://…> [--events denials|allowed|all]'), 1;
      const res = await api.settings.createWebhook({ url, events: (flagStr(flags, 'events') as 'denials' | 'allowed' | 'all') ?? 'denials' });
      if (json) return printJson(res.webhook), 0;
      return err(green(`  ✓ Webhook added (${res.webhook.events}) → ${res.webhook.url}`)), 0;
    }
    case 'remove': {
      const id = positionals[1];
      if (!id) return err('  Usage: webhooks remove <id>'), 1;
      await api.settings.deleteWebhook(id);
      if (json) return printJson({ ok: true, id }), 0;
      return err(green(`  ✓ Removed ${id}`)), 0;
    }
    default:
      return unknownSub('webhooks', sub, USAGE);
  }
}

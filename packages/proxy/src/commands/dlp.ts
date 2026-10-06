/** `solongate dlp …` - data-loss-prevention patterns (part of security layers). */
import { api } from '../api-client/index.js';
import type { LayerMode, SecurityLayers } from '../api-client/index.js';
import { flagBool, flagStr, parse } from './args.js';
import { cyan, dim, err, green, printJson, table, unknownSub, usage, yellow } from './format.js';

const USAGE = usage('solongate dlp', 'data-loss prevention', [
  ['dlp show', 'current mode + enabled patterns'],
  ['dlp mode <off|detect|redact|block>', 'detect records, redact masks, block refuses'],
  ['dlp enable <pattern>', 'enable a built-in pattern'],
  ['dlp disable <pattern>', 'disable a built-in pattern'],
  ['dlp add-custom --name X --re <regex>', 'add a custom pattern'],
  ['dlp remove-custom <name>', 'remove a custom pattern'],
]);

const modeColor = (m: string): string => (m === 'block' ? green(m) : m === 'detect' ? yellow(m) : dim(m));

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0] ?? 'show';
  const json = flagBool(flags, 'json');

  const { layers, availablePatterns } = await api.settings.getSecurityLayers();

  const save = async (next: SecurityLayers): Promise<SecurityLayers> => (await api.settings.setSecurityLayers(next)).layers;

  switch (sub) {
    case 'help':
      return err(USAGE), 0;

    case 'show': {
      if (json) return printJson({ dlp: layers.dlp, availablePatterns }), 0;
      err('');
      err(`  DLP   mode: ${modeColor(layers.dlp.mode)}`);
      const enabled = new Set(layers.dlp.patterns);
      table(
        ['', 'PATTERN'],
        availablePatterns.map((p) => [enabled.has(p) ? green('●') : dim('○'), enabled.has(p) ? p : dim(p)]),
      );
      if (layers.dlp.custom.length) {
        err(dim('\n  Custom:'));
        for (const c of layers.dlp.custom) err(`    ${cyan(c.name)}  ${dim(c.re)}`);
      }
      return 0;
    }

    case 'mode': {
      const mode = positionals[1] as LayerMode | undefined;
      if (!mode || !['off', 'detect', 'redact', 'block'].includes(mode)) return err('  Usage: dlp mode <off|detect|redact|block>'), 1;
      const saved = await save({ ...layers, dlp: { ...layers.dlp, mode } });
      if (json) return printJson(saved.dlp), 0;
      return err(green(`  ✓ DLP mode → ${saved.dlp.mode}`)), 0;
    }

    case 'enable':
    case 'disable': {
      const pattern = positionals.slice(1).join(' ');
      if (!pattern) return err(`  Usage: dlp ${sub} <pattern>`), 1;
      if (!availablePatterns.includes(pattern)) {
        err(`  Unknown pattern: "${pattern}". Available:`);
        for (const p of availablePatterns) err(`    ${dim('•')} ${p}`);
        return 1;
      }
      const set = new Set(layers.dlp.patterns);
      if (sub === 'enable') set.add(pattern);
      else set.delete(pattern);
      const saved = await save({ ...layers, dlp: { ...layers.dlp, patterns: [...set] } });
      if (json) return printJson(saved.dlp), 0;
      return err(green(`  ✓ ${sub}d "${pattern}"`) + dim(` (${saved.dlp.patterns.length} active)`)), 0;
    }

    case 'add-custom': {
      const name = flagStr(flags, 'name');
      const re = flagStr(flags, 're');
      if (!name || !re) return err('  Usage: dlp add-custom --name <name> --re <regex>'), 1;
      const custom = [...layers.dlp.custom.filter((c) => c.name !== name), { name, re }];
      const saved = await save({ ...layers, dlp: { ...layers.dlp, custom } });
      if (json) return printJson(saved.dlp), 0;
      return err(green(`  ✓ Custom pattern "${name}" added`)), 0;
    }

    case 'remove-custom': {
      const name = positionals.slice(1).join(' ');
      if (!name) return err('  Usage: dlp remove-custom <name>'), 1;
      const custom = layers.dlp.custom.filter((c) => c.name !== name);
      const saved = await save({ ...layers, dlp: { ...layers.dlp, custom } });
      if (json) return printJson(saved.dlp), 0;
      return err(green(`  ✓ Removed custom pattern "${name}"`)), 0;
    }

    default:
      return unknownSub('dlp', sub, USAGE);
  }
}

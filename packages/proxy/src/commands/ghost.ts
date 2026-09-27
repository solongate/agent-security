/**
 * `solongate ghost …` - the hidden-path layer.
 *
 * Ghost was the one security layer with no CLI at all: it lived only in the
 * dataroom's DLP panel, so it could not be scripted, put in a runbook, or
 * diffed in CI like the other four. This closes that.
 *
 * It sits beside dlp.ts rather than inside it because the two are different
 * layers that happen to share a panel. `dlp show` listing ghost routes would be
 * a lie about what DLP is.
 *
 * Mode here is 'on'/'off', not the off/detect/block of the other layers. There
 * is no detect for ghost and there cannot be: the point is that the path looks
 * absent, and a mode that recorded the attempt while still serving the file
 * would defeat it.
 */
import { api } from '../api-client/index.js';
import type { SecurityLayers } from '../api-client/index.js';
import { flagBool, parse } from './args.js';
import { cyan, dim, err, green, printJson, red, table, unknownSub, usage } from './format.js';

const USAGE = usage('solongate ghost', 'hidden paths', [
  ['ghost show', 'current mode + routes'],
  ['ghost on', 'start hiding the routes'],
  ['ghost off', 'stop hiding them (the routes are kept)'],
  ['ghost add <glob>', 'hide one more path'],
  ['ghost remove <glob>', 'stop hiding one path'],
]);

const modeColor = (m: string): string => (m === 'on' ? green(m) : dim('off'));

/**
 * A route that would hide EVERYTHING.
 *
 * `*` on its own expands to `\S*`, which matches every path the guard is handed,
 * so saving it turns the whole filesystem invisible to the agent. The next thing
 * that happens is a ticket reading "the agent says none of my files exist". The
 * policy editor refuses catch-all rules on save for the same reason.
 */
const isBlanketGlob = (glob: string): boolean => glob.replaceAll('*', '').trim() === '';

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0] ?? 'show';
  const json = flagBool(flags, 'json');

  if (sub === 'help') return err(USAGE), 0;

  const { layers } = await api.settings.getSecurityLayers();
  const save = async (next: SecurityLayers): Promise<SecurityLayers> => (await api.settings.setSecurityLayers(next)).layers;

  switch (sub) {
    case 'show': {
      if (json) return printJson(layers.ghost), 0;
      err('');
      err(`  Ghost   mode: ${modeColor(layers.ghost.mode)}`);
      if (!layers.ghost.patterns.length) {
        err(dim('\n  No routes. `solongate ghost add <glob>` to hide a path.'));
        return 0;
      }
      table(['', 'ROUTE'], layers.ghost.patterns.map((r) => [cyan('•'), r]));
      // Routes are kept when the layer is switched off, so a list on its own
      // does not tell you whether anything is being hidden.
      if (layers.ghost.mode !== 'on') {
        err(dim('\n  Ghost is off: these routes are stored but nothing is hidden.'));
      }
      return 0;
    }

    case 'on':
    case 'off': {
      const saved = await save({ ...layers, ghost: { ...layers.ghost, mode: sub } });
      if (json) return printJson(saved.ghost), 0;
      err(green(`  ✓ Ghost → ${saved.ghost.mode}`));
      if (sub === 'on' && !saved.ghost.patterns.length) {
        err(dim('  No routes yet, so nothing is hidden. `solongate ghost add <glob>`.'));
      }
      return 0;
    }

    case 'add': {
      const glob = positionals.slice(1).join(' ');
      if (!glob) return err('  Usage: ghost add <glob>'), 1;
      if (isBlanketGlob(glob)) {
        err(`${red('  ✗ ')}"${glob}" would hide every path.`);
        err(dim('    Ghost routes are globs: `*` is any run of non-whitespace.'));
        err(dim('    Anchor it on something, e.g. *payroll.csv or *internal/*.pem'));
        return 1;
      }
      // Idempotent rather than an error: a runbook that adds its routes on every
      // run should not fail its second run.
      if (layers.ghost.patterns.includes(glob)) {
        if (json) return printJson(layers.ghost), 0;
        return err(green(`  ✓ Route "${glob}" is already hidden`)), 0;
      }
      const patterns = [...layers.ghost.patterns, glob];
      const saved = await save({ ...layers, ghost: { ...layers.ghost, patterns } });
      if (json) return printJson(saved.ghost), 0;
      err(green(`  ✓ Hiding "${glob}"`) + dim(` (${saved.ghost.patterns.length} route(s))`));
      // Adding a route to a layer that is off is the one mistake this command
      // makes easy, and it fails silently: the route is saved, the file is still
      // readable, and nothing says why.
      if (saved.ghost.mode !== 'on') {
        err(dim('    Ghost is off. `solongate ghost on` to start hiding.'));
      }
      return 0;
    }

    case 'remove': {
      const glob = positionals.slice(1).join(' ');
      if (!glob) return err('  Usage: ghost remove <glob>'), 1;
      if (!layers.ghost.patterns.includes(glob)) {
        err(`  No such route: "${glob}"`);
        if (layers.ghost.patterns.length) {
          err(dim('  Current:'));
          for (const r of layers.ghost.patterns) err(`    ${dim('•')} ${r}`);
        }
        return 1;
      }
      const patterns = layers.ghost.patterns.filter((r) => r !== glob);
      const saved = await save({ ...layers, ghost: { ...layers.ghost, patterns } });
      if (json) return printJson(saved.ghost), 0;
      return err(green(`  ✓ Stopped hiding "${glob}"`) + dim(` (${saved.ghost.patterns.length} route(s) left)`)), 0;
    }

    default:
      return unknownSub('ghost', sub, USAGE);
  }
}

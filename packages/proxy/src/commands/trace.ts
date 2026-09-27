/**
 * `solongate trace …` - what the guard saw, locally, for THIS directory.
 *
 * It exists because the audit log cannot answer the question people actually
 * ask, which is "my rule names that directory, why did nothing happen".
 *
 * The cloud audit records denials reliably and ALLOWs only when the client has a
 * post-tool stage to report them from. Antigravity has none, so on that client a
 * permitted call leaves no cloud row at all, and "allowed" and "the guard never
 * ran" look identical from the outside. The guard writes a local record for
 * EVERY evaluation either way, and this reads that file.
 *
 * The interesting columns are PATHS/CMDS/URLS: what the guard managed to extract
 * from the call, and what every path, command and url rule matches against. A
 * path rule that never fires on a call showing `paths 0` is not a rule that
 * lost, it is a call the guard saw nothing addressable in.
 *
 * ARGS is the argument KEY NAMES, never the values.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { flagBool, flagNum, parse } from './args.js';
import { dim, err, printJson, red, table, unknownSub, usage } from './format.js';

const USAGE = usage('solongate trace', 'what the guard saw here', [
  ['trace', 'the last evaluations in this directory'],
  ['trace --limit N', 'how many to show (default 20)'],
  ['trace --json', 'the raw records'],
]);

interface TraceRecord {
  ts?: number;
  ms?: number;
  tool?: string;
  session?: string;
  client?: string;
  cwd?: string;
  perm?: string;
  args?: string[];
  paths?: number;
  cmds?: number;
  urls?: number;
}

/**
 * Every project's ring, not just this directory's.
 *
 * The record is filed under a hash of the directory the GUARD PROCESS was
 * spawned in, which is not always the directory the call was made in: a client
 * launches its hooks from wherever it likes, and Antigravity does. Looking only
 * under the hash of the current directory therefore finds nothing for exactly
 * the client whose allowed calls are missing from the cloud audit too, which is
 * the one case this command exists for.
 *
 * So every ring is read and the records are matched on the `cwd` they carry.
 */
function readAllRings(): TraceRecord[] {
  const root = join(homedir(), '.solongate', 'projects');
  let dirs: string[];
  try {
    dirs = readdirSync(root);
  } catch {
    return [];
  }
  const out: TraceRecord[] = [];
  for (const d of dirs) {
    let text: string;
    try {
      text = readFileSync(join(root, d, '.eval-ring.jsonl'), 'utf-8');
    } catch {
      continue;
    }
    for (const line of text.split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try { out.push(JSON.parse(t) as TraceRecord); } catch { /* a truncated write */ }
    }
  }
  return out.sort((a, b) => (b.ts ?? 0) - (a.ts ?? 0));
}

const sameDir = (a: string | undefined, b: string): boolean => {
  const clean = (s: string): string => {
    const t = String(s ?? '').replaceAll('\\', '/');
    return t.length > 1 ? t.replace(/\/+$/, '') : t;
  };
  return !!a && clean(a) === clean(b);
};

const countCell = (n: number | undefined): string => {
  if (n === undefined || n === null) return dim('-');
  // Zero is the answer that explains a rule doing nothing, so it is the one
  // value in this table worth making impossible to skim past.
  if (n === 0) return red('0');
  return String(n);
};

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0] ?? '';

  if (sub === 'help') return err(USAGE), 0;
  if (sub) return unknownSub('trace', sub, USAGE);

  const limit = flagNum(flags, 'limit') || 20;
  const here = resolve(process.cwd());

  const all = readAllRings();
  let records = all.filter((r) => sameDir(r.cwd, here));

  if (!records.length) {
    err('');
    err('  No calls recorded for this directory.');
    err(dim(`  ${here}`));
    if (all.length) {
      // Records exist, just not for here. Naming the directories they DO belong
      // to is the difference between "nothing ran" and "you are standing in the
      // wrong place", and those need different next steps.
      err('');
      err(dim('  The guard has recorded calls in:'));
      const seen = new Set<string>();
      for (const r of all) {
        if (!r.cwd || seen.has(r.cwd) || seen.size >= 8) continue;
        seen.add(r.cwd);
        err(`    ${dim('•')} ${r.cwd}`);
      }
      // A record with no cwd predates it being written down.
      if (!seen.size) err(dim('    (older records carry no directory; make one more call and retry)'));
    }
    return 1;
  }

  records = records.slice(0, limit);
  if (flagBool(flags, 'json')) return printJson(records), 0;

  err('');
  err(`  ${records.length} local evaluation(s) · ${dim(here)}`);
  table(
    ['WHEN', 'CLIENT', 'TOOL', 'PERM', 'PATHS', 'CMDS', 'URLS', 'ARGS', 'MS'],
    records.map((r) => [
      r.ts ? new Date(r.ts).toTimeString().slice(0, 8) : '',
      r.client ?? '',
      r.tool ?? '',
      dim(r.perm ?? ''),
      countCell(r.paths),
      countCell(r.cmds),
      countCell(r.urls),
      // An empty list is not the same as an absent one: it means the guard
      // parsed the payload and found no arguments in it at all.
      r.args === undefined ? dim('-') : r.args.length ? r.args.join(',') : red('(none)'),
      dim(`${Math.round(r.ms ?? 0)}ms`),
    ]),
  );
  err('');
  err(dim('  PATHS/CMDS/URLS is what the guard extracted from the call. A path rule'));
  err(dim('  cannot fire on a call whose PATHS is 0, whatever the rule says.'));
  return 0;
}

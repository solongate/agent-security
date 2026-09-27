/**
 * `solongate watch` - tail the guard's tool-call stream to the terminal, like
 * `tail -f`, without the full TUI. Merges the on-disk local log with the cloud
 * audit feed. Runs until Ctrl+C.
 *
 * Flags: --filter DENY  (only denials)   --tool <substr>   --json (one JSON
 * object per line, for piping)   --local-only / --cloud-only.
 */
import { closeSync, existsSync, openSync, readSync, statSync } from 'node:fs';
import { api } from '../api-client/index.js';
import { c } from '../cli-utils.js';
import { flagBool, flagStr, parse } from './args.js';
import { err, out } from './format.js';
import { localLogFile } from '../tui/local-log.js';

interface Row {
  at: number;
  tool: string;
  decision: string;
  permission: string;
  detail: string;
  agent: string;
  source: 'local' | 'cloud';
  dlp: boolean;
}

const trunc = (s: string, n: number): string => (s.length <= n ? s : s.slice(0, n - 1) + '…');
const time = (ms: number): string => new Date(ms).toTimeString().slice(0, 8);

function tailLocal(file: string, maxBytes = 131_072): string[] {
  try {
    const size = statSync(file).size;
    const start = Math.max(0, size - maxBytes);
    const fd = openSync(file, 'r');
    const buf = Buffer.alloc(size - start);
    readSync(fd, buf, 0, buf.length, start);
    closeSync(fd);
    const lines = buf.toString('utf-8').split('\n').filter(Boolean);
    if (start > 0) lines.shift();
    return lines;
  } catch {
    return [];
  }
}

function print(r: Row, json: boolean): void {
  if (json) return out(JSON.stringify(r));
  const dec = r.decision === 'ALLOW' ? c.green : c.red;
  const src = r.source === 'local' ? c.green + 'LOC' : c.blue4 + 'CLD';
  out(
    `${c.dim}[${time(r.at)}]${c.reset} ${src}${c.reset} ${dec}${r.decision.padEnd(6)}${c.reset} ` +
      `${c.cyan}${trunc(r.tool, 12).padEnd(13)}${c.reset}${c.dim}${r.permission.slice(0, 4).padEnd(5)}${c.reset}` +
      `${r.dlp ? c.red + 'DLP! ' + c.reset : ''}${c.dim}${trunc(r.agent || '-', 12).padEnd(13)}${r.detail}${c.reset}`,
  );
}

export async function run(argv: string[]): Promise<number> {
  const { flags } = parse(argv);
  const json = flagBool(flags, 'json');
  const decisionFilter = (flagStr(flags, 'filter') || '').toUpperCase();
  const toolFilter = (flagStr(flags, 'tool') || '').toLowerCase();
  const localOnly = flagBool(flags, 'local-only');
  const cloudOnly = flagBool(flags, 'cloud-only');

  const keep = (r: Row): boolean => {
    if (decisionFilter && r.decision.toUpperCase() !== decisionFilter && !(decisionFilter === 'DENY' && r.decision === 'DENIED')) return false;
    if (toolFilter && !r.tool.toLowerCase().includes(toolFilter)) return false;
    return true;
  };

  const seen = new Set<string>();
  let lastLocalTs = 0;
  let first = true;

  const emit = (rows: Row[]) => {
    rows.sort((a, b) => a.at - b.at);
    for (const r of rows) if (keep(r)) print(r, json);
  };

  const pollLocal = () => {
    const LOCAL_LOG = localLogFile();
    if (cloudOnly || !existsSync(LOCAL_LOG)) return;
    const rows: Row[] = [];
    for (const line of tailLocal(LOCAL_LOG)) {
      try {
        const j = JSON.parse(line) as Record<string, unknown>;
        const at = Date.parse(String(j.ts ?? ''));
        if (!Number.isFinite(at) || at <= lastLocalTs) continue;
        rows.push({
          at,
          tool: String(j.tool ?? '?'),
          decision: String(j.decision ?? 'ALLOW'),
          permission: String(j.permission ?? ''),
          detail: (j.arguments ? JSON.stringify(j.arguments) : String(j.reason ?? '')).replace(/\s+/g, ' '),
          agent: String(j.agent_name ?? ''),
          source: 'local',
          dlp: !!j.dlp,
        });
      } catch {
        /* partial */
      }
    }
    if (rows.length) lastLocalTs = rows[rows.length - 1]!.at;
    if (!first) emit(rows); // skip backlog on first pass
  };

  const pollCloud = async () => {
    if (localOnly) return;
    try {
      const res = await api.audit.list({ limit: 50 });
      const rows: Row[] = [];
      for (const e of res.entries) {
        if (seen.has(e.id)) continue;
        seen.add(e.id);
        rows.push({
          at: Date.parse(e.created_at),
          tool: e.tool_name,
          decision: e.decision,
          permission: e.permission ?? '',
          detail: (e.arguments_summary ? JSON.stringify(e.arguments_summary) : e.reason ?? '').replace(/\s+/g, ' '),
          agent: e.agent_name ?? '',
          source: 'cloud',
          dlp: !!e.dlp_matches?.length,
        });
      }
      if (!first) emit(rows);
    } catch {
      /* transient */
    }
  };

  if (!json) err(`  ${c.dim}watching guard stream - Ctrl+C to stop${c.reset}`);
  // Prime buffers (mark existing as seen) then start emitting.
  pollLocal();
  await pollCloud();
  first = false;

  return new Promise<number>(() => {
    setInterval(pollLocal, 2000);
    setInterval(() => void pollCloud(), 4000);
    // never resolves - runs until the process is killed.
  });
}

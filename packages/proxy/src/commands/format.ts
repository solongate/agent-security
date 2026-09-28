/**
 * Shared output helpers for the scriptable CLI commands.
 *
 * Two audiences:
 *  - humans: colored, aligned tables (via cli-utils `c`).
 *  - machines (Claude / CI): `--json` prints raw JSON to stdout, nothing else.
 *
 * All human/status text goes to stderr so that `--json` stdout stays a clean,
 * parseable JSON document even when mixed with progress noise.
 */
import { c } from '../cli-utils.js';

export const out = (s = ''): void => void process.stdout.write(s + '\n');
export const err = (s = ''): void => void process.stderr.write(s + '\n');

/** Print a value as pretty JSON to stdout (the machine contract). */
export function printJson(value: unknown): void {
  out(JSON.stringify(value, null, 2));
}

export const dim = (s: string): string => `${c.dim}${s}${c.reset}`;
export const bold = (s: string): string => `${c.bold}${s}${c.reset}`;
export const green = (s: string): string => `${c.green}${s}${c.reset}`;
export const red = (s: string): string => `${c.red}${s}${c.reset}`;
export const yellow = (s: string): string => `${c.yellow}${s}${c.reset}`;
export const cyan = (s: string): string => `${c.cyan}${s}${c.reset}`;

/**
 * Render a colored command usage block, matching the top-level `solongate --help`
 * style: bold title, cyan command syntax, dim descriptions. `rows` are
 * [syntax, description?] pairs; a syntax with no description prints on its own
 * (used for long or continuation lines). Returns the whole block as one string.
 */
export function usage(
  title: string,
  tagline: string,
  rows: Array<[string, string?]>,
  footer = 'Add --json for machine-readable output.',
): string {
  const W = 40; // syntax column width
  const lines: string[] = ['', `  ${c.bold}${c.blue4}${title}${c.reset}  ${c.dim}${tagline}${c.reset}`, ''];
  for (const [syntax, desc] of rows) {
    if (!syntax) { lines.push(''); continue; }
    if (desc === undefined) { lines.push(`    ${c.cyan}${syntax}${c.reset}`); continue; }
    if (syntax.length <= W) {
      lines.push(`    ${c.cyan}${syntax}${c.reset}${' '.repeat(W - syntax.length)}${c.dim}${desc}${c.reset}`);
    } else {
      lines.push(`    ${c.cyan}${syntax}${c.reset}`);
      lines.push(`    ${' '.repeat(W)}${c.dim}${desc}${c.reset}`);
    }
  }
  if (footer) lines.push('', `  ${c.dim}${footer}${c.reset}`);
  return lines.join('\n');
}

/**
 * What a command's switch falls through to when the first positional is not one
 * of its subcommands.
 *
 * Printing the usage block on its own was the old behaviour everywhere, and it
 * reads as though the command simply has no default: a correct-looking help
 * screen appears, and finding the mistake means diffing it against what you
 * typed. Naming the token first costs one line and removes that step.
 *
 * `solongate dlp -g` is the case that made it obvious. The parser treats only
 * `--x` as a flag, so a single-dash token arrives as a SUBCOMMAND, and the
 * result was a help screen that looked like a successful command.
 *
 * The empty case still happens: a command invoked with a flag and no subcommand
 * has nothing to name, and `Unknown subcommand: ""` would be worse than none.
 */
export function unknownSub(command: string, sub: string, usageText: string): number {
  if (sub) err(`${red('  ✗ ')}Unknown ${command} subcommand: ${cyan(sub)}`);
  err(usageText);
  return 1;
}

/** Color a decision string (ALLOW green, DENY/DENIED red). */
export function decisionColor(decision: string): string {
  const d = decision.toUpperCase();
  if (d === 'ALLOW') return green(d);
  if (d === 'DENY' || d === 'DENIED') return red(d);
  return dim(d);
}

// Strip ANSI when measuring width so colored cells still align.
const ANSI = /\x1b\[[0-9;]*m/g;
const width = (s: string): number => s.replace(ANSI, '').length;

/**
 * Render an aligned table to stderr. `headers` are dimmed; each row is an array
 * of already-colored (or plain) strings. Columns size to their widest cell.
 */
export function table(headers: string[], rows: string[][]): void {
  const cols = headers.length;
  const w: number[] = new Array(cols).fill(0);
  for (let i = 0; i < cols; i++) w[i] = width(headers[i] ?? '');
  for (const row of rows) {
    for (let i = 0; i < cols; i++) w[i] = Math.max(w[i]!, width(row[i] ?? ''));
  }
  const pad = (s: string, i: number): string => s + ' '.repeat(Math.max(0, w[i]! - width(s)));
  err('  ' + headers.map((h, i) => dim(pad(h, i))).join('  '));
  for (const row of rows) {
    err('  ' + row.map((cell, i) => pad(cell ?? '', i)).join('  '));
  }
}

/** Truncate to n chars with an ellipsis. */
export function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, Math.max(0, n - 1)) + '…';
}

/** Best-effort relative time from an ISO/date string. */
export function ago(ts: string | number): string {
  const t = typeof ts === 'number' ? ts : Date.parse(ts);
  if (Number.isNaN(t)) return String(ts);
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return `${Math.floor(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

/** Unicode sparkline for a numeric series (empty string when no data). */
const BLOCKS = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
export function sparkline(values: number[]): string {
  if (values.length === 0) return '';
  const max = Math.max(...values, 0);
  if (max === 0) return BLOCKS[0]!.repeat(values.length);
  return values
    .map((v) => BLOCKS[Math.min(BLOCKS.length - 1, Math.round((v / max) * (BLOCKS.length - 1)))]!)
    .join('');
}

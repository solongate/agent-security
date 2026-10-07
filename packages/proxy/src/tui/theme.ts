// SPDX-License-Identifier: Apache-2.0

/** Shared colors + small helpers for the Ink TUI. */
import { loadConfig } from './config.js';

const accent = loadConfig().accent;

export const theme = {
  accent: accent || 'white',
  accentBright: accent || 'white',
  ok: 'green',
  warn: 'yellow',
  bad: 'red',
  dim: 'gray',
} as const;

/** Ink `color` for a decision string. */
export function decisionColor(decision: string): string {
  const d = (decision || '').toUpperCase();
  if (d === 'ALLOW') return theme.ok;
  if (d === 'DENY' || d === 'DENIED') return theme.bad;
  return theme.dim;
}

/** Ink `color` for a layer/agent mode/status. */
export function modeColor(m: string): string {
  if (m === 'block' || m === 'active' || m === 'on') return theme.ok;
  // redact acts, detect only watches, so they are not the same amber.
  if (m === 'redact') return theme.accent;
  if (m === 'detect' || m === 'idle') return theme.warn;
  return theme.dim;
}

const BLOCKS = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
export function sparkline(values: number[], width?: number): string {
  let v = values;
  if (width && v.length > width) v = v.slice(v.length - width);
  if (v.length === 0) return '';
  const max = Math.max(...v, 0);
  if (max === 0) return BLOCKS[0]!.repeat(v.length);
  return v
    .map((n) => BLOCKS[Math.min(BLOCKS.length - 1, Math.round((n / max) * (BLOCKS.length - 1)))]!)
    .join('');
}

/** Pretty-print a JSON string; non-JSON comes back unchanged. */
export function prettyJson(s: string): string {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

/** Hard-wrap text to `width` columns (existing newlines preserved). */
export function wrapLines(s: string, width: number): string[] {
  const w = Math.max(8, width);
  const out: string[] = [];
  for (const raw of (s ?? '').split('\n')) {
    if (raw.length <= w) {
      out.push(raw);
      continue;
    }
    for (let i = 0; i < raw.length; i += w) out.push(raw.slice(i, i + w));
  }
  return out;
}

export function truncate(s: string, n: number): string {
  if (!s) return '';
  return s.length <= n ? s : s.slice(0, Math.max(0, n - 1)) + '…';
}

export function ago(ts: string | number): string {
  const t = typeof ts === 'number' ? ts : Date.parse(ts);
  if (Number.isNaN(t)) return String(ts ?? '');
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return `${Math.floor(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

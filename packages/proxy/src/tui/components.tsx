/** Reusable Ink building blocks: Panel, Table, Bar, DataView, KeyHints, StreamLine. */
import { Box, Text } from 'ink';
import type { JSX, ReactNode } from 'react';
import { decisionColor, theme, truncate } from './theme.js';

/** HH:MM:SS for a timestamp (ms or ISO); `--:--:--` when unparseable. */
export const hhmmss = (ts: string | number): string => {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? '--:--:--' : d.toTimeString().slice(0, 8);
};

/** YYYY-MM-DD for a timestamp; `----------` when unparseable. */
export const ymd = (ts: string | number): string => {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '----------';
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
};

/** Section divider title used across the Live/Audit consoles. */
export function PaneTitle({ label, extra, width }: { label: string; extra?: string; width: number }): JSX.Element {
  const tail = extra ? ` ${extra} ` : ' ';
  const used = 2 + 1 + label.length + tail.length;
  return (
    <Text wrap="truncate">
      <Text color={theme.dim}>{'─ '}</Text>
      <Text color={theme.accentBright} bold>
        ▎{label}
      </Text>
      <Text color={theme.dim}>{tail + '─'.repeat(Math.max(0, width - used))}</Text>
    </Text>
  );
}

/**
 * One tool-stream row, shared verbatim by Live (rolling buffer) and Audit (full
 * history). `loc` tags where the record IS: LOC (a line in this machine's
 * local log) vs CLD (the cloud audit log). With local storage off nothing is
 * LOC, which is the whole point of the setting. `selected` highlights + shows
 * the ▸ cursor.
 * Columns are fixed-width and NEVER conditional so scrolling can't reshuffle the
 * line and glitch the frame.
 */
export interface StreamRow {
  at: number;
  tool: string;
  decision: string;
  permission: string;
  detail: string;
  dlp: boolean;
  burst: boolean;
  agent?: string | null;
  evalMs?: number | null;
  rule?: string | null;
}

// A LOC/CLD column stood in this row, from a `loc` prop. Every entry on every surface is
// read from this machine's own audit file, so it distinguished nothing — and labelled some
// of them "cloud". internal/tui/components.go lost the same column.
export function StreamLine({ e, selected, date }: { e: StreamRow; selected?: boolean; date?: boolean }): JSX.Element {
  return (
    <Text wrap="truncate" backgroundColor={selected ? '#1c2f63' : undefined}>
      <Text color={selected ? theme.accentBright : theme.dim}>{selected ? '▸' : ' '}</Text>
      <Text color={theme.dim}>[{date ? ymd(e.at) + ' ' : ''}{hhmmss(e.at)} </Text>
      <Text color={theme.dim}>] </Text>
      <Text color={decisionColor(e.decision)} bold={e.decision !== 'ALLOW'}>
        {e.decision.padEnd(6)}
      </Text>
      <Text color={theme.accent}>{truncate(e.tool, 12).padEnd(13)}</Text>
      <Text color={theme.dim}>{(e.permission ?? '').padEnd(5)}</Text>
      <Text color={e.evalMs != null && e.evalMs > 500 ? theme.warn : theme.dim}>{(e.evalMs != null ? `${e.evalMs}ms` : '—').padEnd(7)}</Text>
      <Text color={theme.dim}>{truncate(e.agent ?? '-', 11).padEnd(12)}</Text>
      <Text color={e.dlp ? theme.bad : theme.dim} bold={e.dlp}>
        {('dlp:' + (e.dlp ? 'yes' : 'no')).padEnd(8)}
      </Text>
      <Text color={e.burst ? theme.warn : theme.dim} bold={e.burst}>
        {('rl:' + (e.burst ? 'yes' : 'no')).padEnd(7)}
      </Text>
      {e.rule && e.decision !== 'ALLOW' ? <Text color={theme.bad}>{truncate(e.rule, 14) + ' '}</Text> : null}
      <Text color={theme.dim}>{e.detail}</Text>
    </Text>
  );
}

export function Panel({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }): JSX.Element {
  return (
    <Box flexDirection="column" flexGrow={1} paddingX={1}>
      <Box>
        <Text bold color={theme.accentBright}>
          {title}
        </Text>
        {subtitle ? <Text color={theme.dim}>{'  ' + subtitle}</Text> : null}
      </Box>
      <Box marginTop={1} flexDirection="column">
        {children}
      </Box>
    </Box>
  );
}

/** Wraps panel content with loading / error / empty handling. */
export function DataView({
  loading,
  error,
  empty,
  emptyText,
  children,
}: {
  loading: boolean;
  error: string | null;
  empty?: boolean;
  emptyText?: string;
  children: ReactNode;
}): JSX.Element {
  if (error) return <Text color={theme.bad}>✗ {error}</Text>;
  if (loading) return <Text color={theme.warn}>⟳ loading…</Text>;
  if (empty) return <Text color={theme.dim}>{emptyText ?? 'No data.'}</Text>;
  return <>{children}</>;
}

export interface Column {
  header: string;
  width: number;
}
export interface Cell {
  value: string;
  color?: string;
  dim?: boolean;
  bold?: boolean;
}

/** Fixed-width aligned table. Cells are padded/truncated to their column width. */
export function Table({ columns, rows }: { columns: Column[]; rows: Cell[][] }): JSX.Element {
  const fit = (s: string, w: number): string => {
    const v = s ?? '';
    if (v.length > w) return v.slice(0, Math.max(0, w - 1)) + '…';
    return v.padEnd(w);
  };
  return (
    <Box flexDirection="column">
      <Box>
        {columns.map((c, i) => (
          <Text key={i} color={theme.dim}>
            {fit(c.header, c.width) + '  '}
          </Text>
        ))}
      </Box>
      {rows.map((row, ri) => (
        <Box key={ri}>
          {row.map((cell, ci) => (
            <Text key={ci} color={cell.color} dimColor={cell.dim} bold={cell.bold}>
              {fit(cell.value, columns[ci]?.width ?? 10) + '  '}
            </Text>
          ))}
        </Box>
      ))}
    </Box>
  );
}

/** A labeled horizontal bar (unicode blocks) scaled to `max`. */
export function Bar({ label, value, max, width = 24, color = theme.accent }: { label: string; value: number; max: number; width?: number; color?: string }): JSX.Element {
  const filled = max > 0 ? Math.round((value / max) * width) : 0;
  return (
    <Box>
      <Text>{label.padEnd(16)}</Text>
      <Text color={color}>{'█'.repeat(Math.min(width, filled))}</Text>
      <Text color={theme.dim}>{'░'.repeat(Math.max(0, width - filled))}</Text>
      <Text color={theme.dim}>{'  ' + value}</Text>
    </Box>
  );
}

export function KeyHints({ hints }: { hints: [string, string][] }): JSX.Element {
  return (
    <Box>
      {hints.map(([key, label], i) => (
        <Text key={i} color={theme.dim}>
          <Text color={theme.accent}>{key}</Text> {label}
          {i < hints.length - 1 ? '   ' : ''}
        </Text>
      ))}
    </Box>
  );
}

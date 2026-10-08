/**
 * DLP panel — draft-only edits, saved with `s` (never auto-saves).
 *
 * ONE scrollable cursor over three sections, so nothing is ever clipped:
 *   built-in secret patterns  · space toggles each on/off · A all · U none
 *   custom patterns           · a add (name → glob) · d remove
 *
 * The built-ins tile FOUR to a row. There are seventy of them: one per line put
 * the custom section four screens below the fold, and the names are short enough
 * (23 chars at the longest) that four fit side by side on any terminal this TUI
 * already requires. ↑↓ steps a whole row, ←→ steps one cell.
 *
 * Custom patterns use the SAME glob syntax as the built-in secret patterns
 * (`*` = any characters) — NOT regular expressions.
 *
 * The add editor is pinned at the TOP (always visible) so you can see what you
 * type. Self-protection lives in Settings, not here.
 */
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { useEffect, useState } from 'react';
import type { JSX } from 'react';
import { api } from '../../api-client/index.js';
import type { DlpMode, SecurityLayers } from '../../api-client/index.js';
import { DataView } from '../components.js';
import { useLoader, usePanelSize, usePoll } from '../hooks.js';
import { modeColor, theme, truncate } from '../theme.js';

const MODES: DlpMode[] = ['off', 'detect', 'redact', 'block'];
// Built-ins per row. Fixed, not derived from width: the row stride is also the
// ↑↓ step, and a stride that changed with the terminal would move the cursor
// somewhere different on every resize.
const BCOLS = 4;
type Dlp = SecurityLayers['dlp'];

// Selectable rows, flattened across the two sections in display order.
type Entry = { kind: 'builtin'; name: string } | { kind: 'custom'; i: number };

export function DlpPanel({ focused }: { active: boolean; focused: boolean }): JSX.Element {
  const { cols, rows } = usePanelSize();
  const q = useLoader(() => api.settings.getSecurityLayers());
  const [dlp, setDlp] = useState<Dlp | null>(null);
  const [available, setAvailable] = useState<string[]>([]);
  const [sel, setSel] = useState(0);
  const [dirty, setDirty] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  // `name` → `re` builds a custom DLP pattern.
  const [adding, setAdding] = useState<null | 'name' | 're'>(null);
  const [newName, setNewName] = useState('');
  const [input, setInput] = useState('');
  // When editing an existing entry (not adding a new one): its index, else null.
  const [editIdx, setEditIdx] = useState<number | null>(null);

  // Sync from the server on fresh data whenever there are no unsaved edits, so a
  // change made elsewhere shows up on the next auto-refresh (initial load + any
  // external change), without clobbering an in-progress edit.
  // Re-sync ONLY when NEW data arrives (not when `dirty` flips) — depending on
  // `dirty` made a save revert (setDirty(false) re-ran this with stale data and
  // overwrote the just-saved draft). Guard on !dirty so edits are never clobbered.
  useEffect(() => {
    if (q.data && !dirty) {
      setDlp({ ...q.data.layers.dlp, patterns: [...q.data.layers.dlp.patterns], custom: [...q.data.layers.dlp.custom] });
      setAvailable(q.data.availablePatterns);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data]);

  // Auto-refresh while the panel is open; paused mid-edit so it can't overwrite
  // the draft (and never while typing a new pattern/route).
  usePoll(() => {
    if (!dirty && !adding) q.reloadQuiet();
  }, 3000);

  const mutate = (next: Dlp) => {
    setDlp(next);
    setDirty(true);
    setStatus(null);
  };

  const save = async () => {
    if (!dlp || !q.data) return;
    setStatus('Saving…');
    try {
      const res = await api.settings.setSecurityLayers({ ...q.data.layers, dlp });
      setDlp({ ...res.layers.dlp, patterns: [...res.layers.dlp.patterns], custom: [...res.layers.dlp.custom] });
      setDirty(false);
      setStatus('✓ Saved');
      q.reload();
    } catch (e) {
      setStatus('✗ ' + (e instanceof Error ? e.message : String(e)));
    }
  };

  const discard = () => {
    if (!q.data) return;
    setDlp({ ...q.data.layers.dlp, patterns: [...q.data.layers.dlp.patterns], custom: [...q.data.layers.dlp.custom] });
    setDirty(false);
    setStatus('discarded');
  };

  const entries: Entry[] = [
    ...available.map((name) => ({ kind: 'builtin' as const, name })),
    ...(dlp?.custom ?? []).map((_, i) => ({ kind: 'custom' as const, i })),
  ];
  const selC = Math.min(sel, Math.max(0, entries.length - 1));
  const cur = entries[selC];

  const nB = available.length;

  useInput(
    (input2, key) => {
      if (!dlp) return;
      if (key.ctrl && input2 === 'r') { q.reload(); setStatus(`⟳ refreshed ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}`); return; }
      // Built-ins are a grid, customs are a list: ↑↓ steps a row inside the grid
      // and a single entry inside the list, and crossing the boundary lands on
      // the nearest edge of the other section rather than skipping it.
      if (key.upArrow) setSel(() => (selC >= nB ? (selC - 1 >= nB ? selC - 1 : Math.max(0, nB - 1)) : Math.max(0, selC - BCOLS)));
      else if (key.downArrow)
        setSel(() => {
          if (selC >= nB) return Math.min(entries.length - 1, selC + 1);
          const next = selC + BCOLS;
          if (next < nB) return next;
          return Math.min(entries.length - 1, nB);
        });
      else if (key.leftArrow) setSel(() => (selC < nB ? Math.max(0, selC - 1) : selC));
      else if (key.rightArrow) setSel(() => (selC < nB ? Math.min(nB - 1, selC + 1) : selC));
      else if (input2 === 'A') mutate({ ...dlp, patterns: [...available] });
      else if (input2 === 'U') mutate({ ...dlp, patterns: [] });
      else if (input2 === 'm') mutate({ ...dlp, mode: MODES[(MODES.indexOf(dlp.mode) + 1) % MODES.length]! });
      else if (input2 === ' ' && cur?.kind === 'builtin') {
        const set = new Set(dlp.patterns);
        if (set.has(cur.name)) set.delete(cur.name);
        else set.add(cur.name);
        mutate({ ...dlp, patterns: [...set] });
      } else if (input2 === 'a') {
        setNewName('');
        setInput('');
        setAdding('name');
      } else if (input2 === 'd') {
        if (cur?.kind === 'custom') {
          mutate({ ...dlp, custom: dlp.custom.filter((_, i) => i !== cur.i) });
          setSel(() => Math.max(0, selC - 1));
        }
      } else if (input2 === 'e' || key.return) {
        // Edit the selected custom pattern in place.
        if (cur?.kind === 'custom' && dlp.custom[cur.i]) {
          setEditIdx(cur.i);
          setNewName(dlp.custom[cur.i]!.name);
          setInput(dlp.custom[cur.i]!.re);
          setAdding('re');
        }
      } else if (input2 === 's') void save();
      else if (input2 === 'x') discard();
    },
    { isActive: focused && !adding },
  );

  const enabled = new Set(dlp?.patterns ?? []);

  // Split a glob into its leading/trailing wildcard state + core, so each entry
  // can show whether the `*` on either side is ON (green ✱) or OFF (dim ·) — the
  // same clarity the policies editor's Match field gives.
  const wcParts = (pat: string): { left: boolean; core: string; right: boolean } => {
    const s = String(pat ?? '');
    const left = s.startsWith('*');
    const right = s.length > 1 && s.endsWith('*');
    let core = s;
    if (left) core = core.replace(/^\*+/, '');
    if (right) core = core.replace(/\*+$/, '');
    return { left, core: core || s, right };
  };
  const starL = (on: boolean) => <Text color={on ? theme.ok : theme.dim}>{on ? '✱ ' : '· '}</Text>;
  const starR = (on: boolean) => <Text color={on ? theme.ok : theme.dim}>{on ? ' ✱' : ' ·'}</Text>;

  // ── build display lines (section headers + selectable entry rows) ─────────
  // A line can hold FOUR selectable entries now, so each one carries the set of
  // entry indexes it draws — the scroll window finds the line containing the
  // cursor by membership, not by equality.
  const lines: Array<{ node: JSX.Element; entries: number[] }> = [];
  const header = (key: string, label: string, extra?: string) =>
    lines.push({
      node: (
        <Text key={key} wrap="truncate">
          <Text color={theme.accentBright} bold>{label}</Text>
          {extra ? <Text color={theme.dim}>{'  ' + extra}</Text> : null}
        </Text>
      ),
      entries: [],
    });
  const note = (key: string, text: string) => lines.push({ node: <Text key={key} color={theme.dim} wrap="truncate">{text}</Text>, entries: [] });

  let ei = 0;
  const onCount = available.reduce((n, p) => n + (enabled.has(p) ? 1 : 0), 0);
  header('h:builtin', 'built-in secret patterns', `${onCount}/${nB} on · space toggles · A all · U none`);
  // Four to a row. The cell is sized from the panel, floored so a narrow
  // terminal truncates names instead of wrapping the row (wrap="truncate" would
  // then drop whole cells off the right and they would be unreachable).
  const cellW = Math.max(12, Math.floor((cols - 1) / BCOLS));
  for (let r = 0; r < nB; r += BCOLS) {
    const row = available.slice(r, r + BCOLS);
    lines.push({
      node: (
        <Text key={'brow:' + r} wrap="truncate">
          {row.map((p, c) => {
            const i = r + c;
            const on = enabled.has(p);
            const isCur = focused && i === selC;
            return (
              <Text key={p} backgroundColor={isCur ? '#1c2f63' : undefined} bold={isCur}>
                <Text color={isCur ? theme.accentBright : theme.dim}>{isCur ? '▸' : ' '}</Text>
                <Text color={on ? theme.ok : theme.dim}>{on ? '●' : '○'}</Text>
                <Text color={on ? undefined : theme.dim}>{' ' + truncate(p, cellW - 4).padEnd(cellW - 3)}</Text>
              </Text>
            );
          })}
        </Text>
      ),
      entries: row.map((_, c) => r + c),
    });
  }
  ei = nB;

  header('h:custom', 'custom patterns', 'a add · d remove');
  note('n:custom-help', '  * = any chars · green ✱ on a side = wildcard active there · e.g.  sk-*   *PRIVATE KEY*');
  if ((dlp?.custom.length ?? 0) === 0) note('n:custom', '  (none — press a to add a name + pattern)');
  (dlp?.custom ?? []).forEach((c, i) => {
    const isCur = focused && ei === selC;
    const idx = ei++;
    const w = wcParts(c.re);
    lines.push({
      node: (
        <Text key={'c:' + c.name + i} wrap="truncate" backgroundColor={isCur ? '#1c2f63' : undefined} bold={isCur}>
          <Text color={isCur ? theme.accentBright : theme.dim}>{isCur ? '▸ ' : '  '}</Text>
          <Text color={theme.accent}>{c.name}</Text>
          <Text color={theme.dim}>{'  '}</Text>
          {starL(w.left)}
          <Text color={theme.dim}>{truncate(w.core, Math.max(6, cols - c.name.length - 14))}</Text>
          {starR(w.right)}
        </Text>
      ),
      entries: [idx],
    });
  });

  // ── header block (fixed, always visible) + windowed list ──────────────────
  const editRows = adding ? 1 : 0;
  const headerRows = 2 + editRows + (status ? 1 : 0);
  const budget = Math.max(3, rows - headerRows - 1);
  const selLine = Math.max(0, lines.findIndex((l) => l.entries.includes(selC)));
  const maxStart = Math.max(0, lines.length - budget);
  const start = Math.min(Math.max(0, selLine - Math.floor(budget / 2)), maxStart);
  const win = lines.slice(start, start + budget);
  const moreAbove = start;
  const moreBelow = Math.max(0, lines.length - (start + budget));

  return (
    <DataView loading={q.loading && !dlp} error={q.error}>
      {dlp ? (
        <Box flexDirection="column">
          <Text wrap="truncate">
            <Text>mode: </Text>
            <Text color={modeColor(dlp.mode)} bold>{dlp.mode}</Text>
            <Text color={theme.dim}>{dlp.mode === 'off' ? '  (nothing is scanned)' : dlp.mode === 'detect' ? '  (record the hit, change nothing)' : dlp.mode === 'redact' ? '  (mask the secret, let the call through)' : '  (refuse the call)'}</Text>
            {dirty ? <Text color={theme.warn}>{'   ● unsaved (s save · x discard)'}</Text> : null}
          </Text>
          <Text color={theme.dim} wrap="truncate">
            {focused
              ? `↑↓←→ move · space on/off · A all · U none · m mode · a add · e edit · d remove · s save · x discard${moreAbove ? ` · ▲${moreAbove}` : ''}${moreBelow ? ` · ▼${moreBelow}` : ''}`
              : 'press → to edit'}
          </Text>

          {adding ? (
            <Box flexDirection="column">
              <Box>
                <Text color={theme.warn}>
                  {adding === 'name' ? 'new pattern name: ' : `${editIdx != null ? 'edit' : 'new'} pattern for "${newName}" (glob, * = any chars): `}
                </Text>
                {adding !== 'name' ? starL(input.startsWith('*')) : null}
                <TextInput
                  value={input}
                  onChange={setInput}
                  onSubmit={(v) => {
                    const t = v.trim();
                    if (adding === 'name') {
                      if (!t) { setAdding(null); setEditIdx(null); return; }
                      setNewName(t);
                      setInput('');
                      setAdding('re');
                    } else {
                      if (t && dlp) {
                        if (editIdx != null) mutate({ ...dlp, custom: dlp.custom.map((c, i) => (i === editIdx ? { name: newName, re: t } : c)) });
                        else mutate({ ...dlp, custom: [...dlp.custom, { name: newName, re: t }] });
                      }
                      setAdding(null); setEditIdx(null);
                    }
                  }}
                />
                {adding !== 'name' ? starR(input.length > 1 && input.endsWith('*')) : null}
              </Box>
            </Box>
          ) : null}

          <Box marginTop={1} flexDirection="column" height={budget} overflow="hidden">
            {win.map((l) => l.node)}
          </Box>

          {status ? <Text color={status.startsWith('✗') ? theme.bad : theme.ok} wrap="truncate">{status}</Text> : null}
        </Box>
      ) : null}
    </DataView>
  );
}

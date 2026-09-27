/** Rate-limit panel — edit the layer + the dashboard's busiest/bursts view. */
import { Box, Text, useInput } from 'ink';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { api } from '../../api-client/index.js';
import type { LayerMode, SecurityLayers } from '../../api-client/index.js';
import { DataView, Table } from '../components.js';
import { useLoader, usePanelSize, usePoll } from '../hooks.js';
import { modeColor, theme, truncate } from '../theme.js';

const MODES: LayerMode[] = ['off', 'detect', 'block'];
const FIELDS = ['mode', 'perMinute', 'perHour', 'perDay'] as const;

interface Anomaly { agent: string; minute: string; count: number; limit: number; blocked: boolean }
interface Peaks { minute: number; hour: number; day: number }

const when = (ms: number): string => {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
};

export function RateLimitPanel({ focused }: { active: boolean; focused: boolean }): JSX.Element {
  const { cols, rows } = usePanelSize();
  const layersQ = useLoader(() => api.settings.getSecurityLayers());
  const historyQ = useLoader(() => api.settings.getRateLimitHistory());
  const insightsQ = useLoader(() => api.stats.securityInsights(7));
  const [draft, setDraft] = useState<SecurityLayers['rateLimit'] | null>(null);
  const [dirty, setDirty] = useState(false);
  const [sel, setSel] = useState(0); // unified ↑↓ cursor: 0-3 = fields, 4+ = bursts
  const [status, setStatus] = useState<string | null>(null);

  // Sync the draft from the server whenever fresh data arrives AND there are no
  // unsaved edits — so a change made elsewhere (dashboard, another session)
  // shows up on the next auto-refresh without clobbering an in-progress edit.
  // Re-sync from the server ONLY when NEW data arrives (not when `dirty` flips) —
  // depending on `dirty` made a save revert: setDirty(false) re-ran this with the
  // still-stale loader data and overwrote the just-saved draft. Guard on !dirty so
  // an in-progress edit is never clobbered.
  useEffect(() => {
    if (layersQ.data && !dirty) setDraft({ ...layersQ.data.layers.rateLimit });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layersQ.data]);

  // Auto-refresh while the panel is open (paused mid-edit for the layer config so
  // it can't overwrite the draft; the read-only bursts/activity always refresh).
  // Config is light — poll it fast (3s) so a change made on the dashboard shows up
  // quickly. The heavier history/insights scan polls slower (10s).
  usePoll(() => { if (!dirty) layersQ.reloadQuiet(); }, 3000);
  usePoll(() => { historyQ.reloadQuiet(); insightsQ.reloadQuiet(); }, 10000);

  const adjust = (dir: 1 | -1, step: number) => {
    if (!draft || fi < 0) return; // cursor is on a burst row, not a field
    const field = FIELDS[fi]!;
    if (field === 'mode') setDraft({ ...draft, mode: MODES[(MODES.indexOf(draft.mode) + dir + MODES.length) % MODES.length]! });
    else setDraft({ ...draft, [field]: Math.max(0, (draft[field] as number) + dir * step) });
    setDirty(true);
    setStatus(null);
  };

  const save = async () => {
    if (!draft || !layersQ.data) return;
    setStatus('Saving…');
    try {
      const res = await api.settings.setSecurityLayers({ ...layersQ.data.layers, rateLimit: draft });
      setDraft({ ...res.layers.rateLimit });
      setDirty(false);
      setStatus('✓ Saved');
      layersQ.reload();
      historyQ.reload();
      insightsQ.reload();
    } catch (e) {
      setStatus('✗ ' + (e instanceof Error ? e.message : String(e)));
    }
  };

  const history = (historyQ.data?.history ?? []).slice().sort((a, b) => b.ts - a.ts);
  const lastChange = history[0];
  const peaks = (insightsQ.data?.['peaks'] as Peaks | undefined) ?? { minute: 0, hour: 0, day: 0 };
  // Biggest bursts first (then newest), matching the dashboard's ordering.
  const anomalies = ((insightsQ.data?.['anomalies'] as Anomaly[] | undefined) ?? [])
    .slice()
    .sort((a, b) => b.count - a.count || new Date(b.minute).getTime() - new Date(a.minute).getTime());

  // Bursts layout budget — computed here (not just in the render) so PgUp/PgDn can
  // scroll the list. `off` is the clamped scroll offset into the sorted bursts.
  const hasLoad = (draft?.perMinute ?? 0) > 0;
  const showExtras = rows >= 20;
  // The blank line above the footer is the first thing to give up when the panel
  // is short — on a small terminal it was costing a whole burst row.
  const spacerRows = showExtras ? 1 : 0;
  // Budgeting the list to fill the panel EXACTLY is what broke scrolling: the
  // footer had nowhere to go, so it pushed rows past the clip and the selection
  // moved into space that is never drawn, which reads as the list being stuck.
  // Every list panel that scrolls correctly (DLP, Policies) keeps a line back.
  const fixed =
    1 /*hint*/ +
    4 /*fields*/ +
    (showExtras ? (hasLoad ? 1 : 0) + 5 /*busiest hdr+3+activity*/ : 0) +
    1 /*bursts hdr*/ +
    1 /*col hdr*/ +
    spacerRows +
    1 /*limit now*/ +
    1 /*slack*/;
  const burstBudget = Math.max(1, rows - fixed);
  const maxOff = Math.max(0, anomalies.length - burstBudget);
  // Unified cursor: indexes 0-3 are the editable fields, 4+ are burst rows — so ↑↓
  // scrolls freely from the fields down through every burst (windowed), exactly
  // like the DLP / Policies lists. `off` keeps the selected burst in view.
  const total = 4 + anomalies.length;
  const selC = Math.min(sel, Math.max(0, total - 1));
  const onField = selC < 4;
  const fi = onField ? selC : -1;
  const bcur = onField ? -1 : selC - 4;
  const off = bcur < 0 ? 0 : Math.min(Math.max(0, bcur - Math.floor(burstBudget / 2)), maxOff);

  useInput(
    (input, key) => {
      const step = key.shift ? 10 : 1;
      if (key.upArrow) setSel((n) => Math.max(0, n - 1));
      else if (key.downArrow) setSel((n) => Math.min(total - 1, n + 1));
      else if (key.pageDown) setSel((n) => Math.min(total - 1, n + burstBudget));
      else if (key.pageUp) setSel((n) => Math.max(0, n - burstBudget));
      else if (key.leftArrow) adjust(-1, step);
      else if (key.rightArrow) adjust(1, step);
      else if (input === 's') void save();
      else if (key.ctrl && input === 'r') { layersQ.reload(); historyQ.reload(); insightsQ.reload(); setStatus(`⟳ refreshed ${when(Date.now())}`); }
    },
    { isActive: focused },
  );

  return (
    <DataView loading={layersQ.loading && !draft} error={layersQ.error}>
      {draft ? (() => {
        const lim = draft.perMinute;
        const now = insightsQ.data ? ((insightsQ.data['activity'] as { minute?: { count: number }[] })?.minute?.slice(-1)[0]?.count ?? 0) : 0;
        const loadPct = lim > 0 ? Math.min(100, Math.round((now / lim) * 100)) : 0;
        const last24h = (((insightsQ.data?.['activity'] as { hour?: { count: number }[] })?.hour) ?? []).reduce((s, b) => s + b.count, 0);

        // Bursts are the point of this panel, so they get priority: the secondary
        // "Busiest 7d" + load + activity block only renders when the panel is tall
        // (see showExtras above), else it ate the height and left room for one burst.
        const shown = anomalies.slice(off, off + burstBudget);
        const bw = Math.max(10, cols - 30);

        return (
          <Box flexDirection="column" height={rows} overflow="hidden">
            <Text color={theme.dim} wrap="truncate">{focused ? '↑↓ move (fields + bursts) · ←→ ±1 · shift+←→ ±10 · s save · ^R refresh' : 'press → to edit'}</Text>
            <FieldRow label="Mode" active={focused && fi === 0}><Text color={modeColor(draft.mode)} bold>{draft.mode}</Text><Text color={theme.dim}>{draft.mode === 'off' ? '  no limit' : draft.mode === 'detect' ? '  flag bursts, never block' : '  DENY calls over the limit'}</Text></FieldRow>
            <FieldRow label="Per minute" active={focused && fi === 1}><Text bold>{draft.perMinute || 'off'}</Text></FieldRow>
            <FieldRow label="Per hour" active={focused && fi === 2}><Text bold>{draft.perHour || 'off'}</Text></FieldRow>
            <FieldRow label="Per day" active={focused && fi === 3}><Text bold>{draft.perDay || 'off'}</Text></FieldRow>

            {showExtras && (<>
            {hasLoad ? (
              <Text wrap="truncate">
                <Text color={theme.dim}>{'load now'.padEnd(13)}</Text>
                <Text color={loadPct >= 100 ? theme.bad : loadPct >= 80 ? theme.warn : theme.ok}>{'█'.repeat(Math.min(18, Math.round((now / lim) * 18)))}</Text>
                <Text color="#233457">{'░'.repeat(Math.max(0, 18 - Math.round((now / lim) * 18)))}</Text>
                <Text color={theme.dim}>{`  ${now}/${lim} this minute (${loadPct}%)`}</Text>
              </Text>
            ) : null}

            <Text color={theme.accentBright} bold wrap="truncate">{'Busiest 7d'}<Text color={theme.dim}>{'   most calls in one window vs your limit'}</Text></Text>
            <BusiestRow label="minute" peak={peaks.minute} limit={draft.perMinute} />
            <BusiestRow label="hour" peak={peaks.hour} limit={draft.perHour} />
            <BusiestRow label="day" peak={peaks.day} limit={draft.perDay} />
            <Text color={theme.dim} wrap="truncate">{`activity`.padEnd(11) + `   last 24h · ${last24h} calls · busiest hour ${peaks.hour}/hr`}</Text>
            </>)}

            <Box flexDirection="column">
            <Text color={theme.accentBright} bold wrap="truncate">
              {`Recent bursts 7d${anomalies.length ? ` (${anomalies.length})` : ''}`}
              {maxOff > 0 ? <Text color={theme.warn}>{`  ${off + 1}-${Math.min(off + burstBudget, anomalies.length)}/${anomalies.length}`}</Text> : null}
              <Text color={theme.dim}>{'   over the per-minute limit · Bypassed = detect (not blocked)'}</Text>
            </Text>
            {anomalies.length === 0 ? (
              <Text color={theme.dim}>  {insightsQ.loading ? 'loading…' : insightsQ.error ? `couldn't load bursts: ${String(insightsQ.error).slice(0, 60)}` : 'no bursts in the last 7 days'}</Text>
            ) : (
              // Bounded here as well as on the outer frame, so a list longer than
              // the budget is clipped inside its own box instead of shoving the
              // footer out of the panel and taking the scroll window with it.
              <Box flexDirection="column" height={burstBudget + 1 /*col hdr*/} overflow="hidden">
                <Table
                  columns={[{ header: 'WHEN', width: 15 }, { header: 'RESULT', width: 9 }, { header: 'CALLS', width: 7 }, { header: 'AGENT', width: Math.max(8, bw - 31) }]}
                  rows={shown.map((a, i) => {
                    const isSel = off + i === bcur;
                    return [
                      { value: (isSel ? '▸ ' : '  ') + when(new Date(a.minute).getTime()), color: isSel ? theme.accentBright : undefined, dim: !isSel },
                      { value: a.blocked ? 'Blocked' : 'Bypassed', color: a.blocked ? theme.bad : theme.warn },
                      { value: `${a.count}/${a.limit}`, color: theme.warn },
                      { value: truncate(a.agent, Math.max(8, bw - 31)), dim: !isSel },
                    ];
                  })}
                />
              </Box>
            )}
            </Box>

            {spacerRows ? <Text> </Text> : null}
            <Text wrap="truncate">
              <Text color={theme.dim}>{'limit now  '}</Text>
              <Text>{lim > 0 ? `${lim}/min` : 'no per-minute limit'}</Text>
              {lastChange ? <Text color={theme.dim}>{`  · changed ${when(lastChange.ts)}`}</Text> : null}
              {dirty ? <Text color={theme.warn}>{'   ● unsaved (s)'}</Text> : null}
              {status ? <Text color={status.startsWith('✗') ? theme.bad : theme.ok}>{'   ' + status}</Text> : null}
            </Text>
          </Box>
        );
      })() : null}
    </DataView>
  );
}

// One "Busiest" stat line (dashboard card, TUI edition): peak calls in one window
// over 7 days, coloured red when it went OVER your configured limit.
function BusiestRow({ label, peak, limit }: { label: string; peak: number; limit: number }): JSX.Element {
  const ctx = limit > 0 ? (peak > limit ? `over ${limit}` : peak === limit ? `at limit ${limit}` : `limit ${limit}`) : 'no limit set';
  const hot = limit > 0 && peak > limit;
  return (
    <Text wrap="truncate">
      <Text color={theme.dim}>{('  ' + label).padEnd(11)}</Text>
      <Text color={hot ? theme.bad : undefined} bold={hot}>{String(peak).padStart(4) + ' calls'}</Text>
      <Text color={hot ? theme.bad : theme.dim}>{'  · ' + ctx}</Text>
    </Text>
  );
}

function FieldRow({ label, active, children }: { label: string; active: boolean; children: ReactNode }): JSX.Element {
  return (
    <Text wrap="truncate">
      <Text color={active ? theme.accentBright : undefined}>{(active ? '▸ ' : '  ') + label.padEnd(11)}</Text>
      {children}
    </Text>
  );
}

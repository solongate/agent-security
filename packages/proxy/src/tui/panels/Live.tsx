/**
 * Live — fullscreen realtime ops console.
 *
 * Copying: SPACE toggles COPY MODE — the screen freezes completely (polls
 * skip, in-flight responses dropped, tick halted) so terminal mouse selection
 * works; the user copies whatever they want. No auto-copy key.
 *
 * Keys (stream mode): ↑↓ select a row · w whitelist a DENY · b block an ALLOW ·
 *   d/x/r deny/dlp/ratelimit filter · f source LOC/CLD · / search ·
 *   space copy-mode · esc menu · q quit. Security events (deny/dlp/burst)
 *   raise a banner + bell + notify-send.
 *
 * TRAFFIC uses 10-second buckets over the last 10 minutes, anchored to
 * wall-clock slots — fast flow with activity, zero movement without.
 */
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { localLogsSetting, tailLines, type LocalLogSetting } from '../local-log.js';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { JSX } from 'react';
import { api } from '../../api-client/index.js';
import { ruleSpecFor } from '../../api-client/audit.js';
import type { Stats } from '../../api-client/index.js';
import { loadConfig } from '../config.js';
import { desktopNotify } from '../notify.js';
import { useLoader, usePoll, useTermSize } from '../hooks.js';
import { PaneTitle, StreamLine, hhmmss } from '../components.js';
import { decisionColor, prettyJson, theme, truncate, wrapLines } from '../theme.js';

const CONFIG = loadConfig();

const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const BG = '#12234f';
const DIM_FLOOR = '#233457';
// Same hash the hooks use to name a project's scratch directory. The flags used
// to live in `./.solongate/` next to the user's code; they now sit under
// ~/.solongate/projects/<key> so nothing is written where someone works. All
// three copies of this must agree or the dataroom reads an empty ring.
const projectKey = (dir: string): string => {
  let h = 0x811c9dc5;
  for (let i = 0; i < dir.length; i++) {
    h ^= dir.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16);
};
const RING = join(homedir(), '.solongate', 'projects', projectKey(resolve(process.cwd())), '.eval-ring.jsonl');

const fmtUp = (ms: number): string => {
  const s = Math.floor(ms / 1000);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(s % 60)}`;
};

interface StreamItem {
  id: string;
  at: number;
  tool: string;
  decision: string;
  permission: string;
  detail: string;
  /** What the guard RECORDED, for w/b to build a rule from. */
  args?: unknown;
  dlp: boolean;
  burst: boolean;
  session?: string;
  agent?: string;
  evalMs?: number;
  rule?: string;
}

// extractTarget lived here: a second reader of a call's target, over the DISPLAY string
// rather than the recorded arguments. It checked a url LAST (so a call carrying both
// scoped to the path), reduced a path to its BASENAME (so allowing a read of /etc/hosts
// allowed every file called hosts anywhere), and — with nothing to narrow on — left the
// rule at TOOL scope, silently allowing every call to that tool forever.
//
// api-client/audit.ts ruleSpecFor is the one answer, shared with `solongate audit
// whitelist`, and internal/api RuleSpecFor is its Go twin.

// cloudItem lived here, turning an audit-API entry into a stream row for the SECOND
// plane — a second read of the same file this panel already tails. See the note on
// mergedAll below.

function ColumnChart({ series, hot, height, width, color, hotColor = theme.bad }: { series: number[]; hot?: boolean[]; height: number; width: number; color: string; hotColor?: string }): JSX.Element {
  const pad = Math.max(0, width - series.length);
  const data = [...new Array(pad).fill(0), ...series.slice(-width)] as number[];
  const hotPad = hot ? ([...new Array(pad).fill(false), ...hot.slice(-width)] as boolean[]) : undefined;
  const max = Math.max(1, ...data);
  const lines: JSX.Element[] = [];
  for (let r = height; r >= 1; r--) {
    const segs: Array<{ text: string; color: string }> = [];
    for (let i = 0; i < data.length; i++) {
      const v = data[i]!;
      const frac = v / max;
      let ch: string;
      if (frac >= r / height) ch = '█';
      else if (frac >= (r - 0.5) / height) ch = '▄';
      else if (r === 1) ch = '▁';
      else ch = ' ';
      const c = r === 1 && v === 0 ? DIM_FLOOR : hotPad?.[i] ? hotColor : color;
      const last = segs[segs.length - 1];
      if (last && last.color === c) last.text += ch;
      else segs.push({ text: ch, color: c });
    }
    lines.push(
      <Text key={r}>
        {segs.map((s, i) => (
          <Text key={i} color={s.color}>
            {s.text}
          </Text>
        ))}
      </Text>,
    );
  }
  return <Box flexDirection="column">{lines}</Box>;
}

function HBar({ label, value, max, width, color }: { label: string; value: number; max: number; width: number; color: string }): JSX.Element {
  const filled = max > 0 ? Math.round((value / max) * width) : 0;
  return (
    <Text wrap="truncate">
      <Text color={theme.dim}>{label.padEnd(10)}</Text>
      <Text color={color}>{'█'.repeat(Math.min(width, filled))}</Text>
      <Text color={DIM_FLOOR}>{'░'.repeat(Math.max(0, width - filled))}</Text>
      <Text color={theme.dim}>{' ' + value}</Text>
    </Text>
  );
}

interface LogLine {
  ts: number;
  msg: string;
  level: 'ok' | 'warn' | 'bad';
}

interface InsightsBits {
  activity?: { minute?: Array<{ t: number; count: number }> };
  layers?: {
    rateLimit?: { perMinute?: number; perHour?: number; perDay?: number; mode?: string };
    dlp?: { mode?: string; patterns?: string[]; custom?: Array<{ name?: string; re?: string }> };
  };
  dlpByPattern?: Array<{ pattern: string; count: number }>;
}

type Mode = 'stream' | 'inspect' | 'layers';

/** Full key reference shown by `?` inside Live (any mode). */
const LIVE_HELP: Array<[string, Array<[string, string]>]> = [
  [
    'Stream',
    [
      ['↑↓ / PgUp PgDn', 'select a row (window follows)'],
      ['enter', 'open the FULL entry content'],
      ['w', 'whitelist the selected DENY (adds ALLOW rule)'],
      ['b', 'block the selected ALLOW (adds DENY rule)'],
      ['d / x / r', 'filter: denies / dlp hits / rate-limit bursts'],
      ['/', 'live search (tool, agent, command…) · enter done'],
      ['l', 'layers detail (rate limit · dlp · guard)'],
      ['e', 'export visible rows → ~/.solongate/live-export.jsonl'],
      ['space', 'copy mode: freeze screen for mouse selection'],
      ['esc', 'back to menu'],
      ['q', 'quit dataroom'],
    ],
  ],
  [
    'Entry (full content)',
    [
      ['↑↓ / PgUp PgDn', 'scroll the content'],
      ['space', 'copy mode (freeze, then select with mouse)'],
      ['←', 'back to where you came from'],
    ],
  ],
  ['Anywhere', [['?', 'this help'], ['any key', 'close this help']]],
];

export function LivePanel({ active }: { active: boolean; focused: boolean }): JSX.Element {
  const [s, setS] = useState<Stats | null>(null);
  // WHAT ENFORCEMENT COSTS, in milliseconds per decision, sampled from the
  // evaluation_time_ms the guard writes into every entry.
  //
  // It was `lat`: the round trip of the audit fetch — a read of a file on this machine,
  // charted under the title "API LATENCY". On any machine the number was 0 or 1.
  const [evalMs, setEvalMs] = useState<number[]>([]);
  const [localBuf, setLocalBuf] = useState<StreamItem[]>([]);
  const [localOn, setLocalOn] = useState<boolean | null>(null);
  const [localPath, setLocalPath] = useState<LocalLogSetting | null>(null);
  const [ring, setRing] = useState<{ avgMs: number; session: string; count: number } | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  // Signal preset: d/x/r narrow the stream to denies / dlp hits / rate bursts.
  const [signal, setSignal] = useState<'none' | 'deny' | 'dlp' | 'ratelimit'>('none');
  // `/` search — live substring filter over the stream and session timelines.
  const [search, setSearch] = useState('');
  const [editingSearch, setEditingSearch] = useState(false);
  const [sel, setSel] = useState(0); // selected stream row (index into visibleDesc)
  const [actionMsg, setActionMsg] = useState<{ text: string; level: 'ok' | 'bad'; until: number } | null>(null);
  const notifiedRef = useRef<Set<string>>(new Set()); // security events already alerted
  const openedAtRef = useRef(Date.now()); // panel-open time; only alert on calls AFTER it
  const [mode, setMode] = useState<Mode>('stream');
  // Entry inspector (enter on a stream/timeline row): the FULL log content.
  const [inspect, setInspect] = useState<StreamItem | null>(null);
  const [inspectScroll, setInspectScroll] = useState(0);
  // Layers detail (l): full rate-limit / dlp / guard configuration.
  const [layersScroll, setLayersScroll] = useState(0);
  const inspectFromRef = useRef<Exclude<Mode, 'inspect'>>('stream');
  // `seenRef` (audit-entry ids already ingested) stood here, for the second read.
  const lastLocalTs = useRef(0);
  // Monotonic suffix for local StreamItem ids. A rate-limit burst writes many
  // log lines in the SAME millisecond with the SAME tool, so ts+tool alone
  // collides — duplicate React keys make React print a console warning, which
  // (rendered above the frame) freezes the top of the screen. Never reuse ids.
  const localSeq = useRef(0);
  const pausedUntil = useRef(0);
  const mergedRef = useRef<StreamItem[]>([]); // latest merged stream, read by the security-notify effect
  const [alerts, setAlerts] = useState<Array<{ id: string; msg: string; level: 'warn' | 'bad'; until: number }>>([]);
  // COPY MODE (space): a REAL freeze — polls skip, in-flight responses are
  // dropped at resolve time, and the tick stops, so the screen is pixel-static
  // and terminal mouse selection survives. The user copies however they like.
  const [frozen, setFrozen] = useState(false);
  const frozenRef = useRef(false);
  frozenRef.current = frozen;
  const [showHelp, setShowHelp] = useState(false);

  const pushLog = useCallback((msg: string, level: LogLine['level'] = 'ok') => {
    setLog((prev) => [...prev.slice(-59), { ts: Date.now(), msg, level }]);
  }, []);

  // Every read is a file read now. The backoff this used to carry — 429s and
  // "network unreachable, retrying" — described a service that is not there, and
  // a blip that self-heals on the next poll is not a thing a local file does. An
  // error here is real: an unreadable policy file, a permission problem. Said
  // once, plainly.
  const onApiError = useCallback(
    (e: unknown) => {
      pushLog(truncate(e instanceof Error ? e.message : String(e), 60), 'bad');
    },
    [pushLog],
  );
  const paused = () => frozenRef.current || Date.now() < pausedUntil.current;

  // ── LOCAL plane ───────────────────────────────────────────────────────────
  const pollLocal = useCallback(() => {
    if (frozenRef.current) return;
    // on/off is the SETTING, never the presence of output. An enabled log with
    // nothing in it yet (fresh install, folder just changed, account just
    // switched) used to read as off, and the panel then told the user to enable
    // what was already enabled.
    const setting = localLogsSetting();
    setLocalOn(setting.enabled);
    setLocalPath(setting);
    // With the setting off, the file is not read at all. It still holds
    // whatever was written while it was on, and surfacing that would put LOC
    // rows in the stream of a project that has local storage turned off.
    if (!setting.enabled) return;
    const lines = tailLines(setting.file);
    if (!lines.length) return;
    const fresh: StreamItem[] = [];
    for (const line of lines) {
      try {
        const j = JSON.parse(line) as {
          ts?: string;
          tool?: string;
          decision?: string;
          reason?: string;
          arguments?: unknown;
          dlp?: unknown;
          permission?: string;
          session_id?: string;
          agent_name?: string;
          evaluation_time_ms?: number;
          matched_rule_id?: string;
          rate_limit_burst?: boolean;
        };
        const at = Date.parse(j.ts ?? '');
        if (!Number.isFinite(at) || at <= lastLocalTs.current) continue;
        fresh.push({
          id: 'l:' + at + ':' + (j.tool ?? '') + ':' + localSeq.current++,
          at,
          tool: j.tool ?? '?',
          decision: j.decision ?? 'ALLOW',
          permission: (j.permission ?? '').slice(0, 4),
          detail: (j.arguments ? JSON.stringify(j.arguments) : j.reason ?? '').replace(/\s+/g, ' '),
          // What the guard RECORDED, for w/b to build a rule from. detail is the same
          // JSON collapsed for display, and it was what the action re-parsed.
          args: j.arguments,
          dlp: !!j.dlp,
          burst: !!j.rate_limit_burst,
          session: j.session_id,
          agent: j.agent_name,
          evalMs: j.evaluation_time_ms,
          rule: j.matched_rule_id,
        });
      } catch {
        /* partial line */
      }
    }
    if (fresh.length) {
      lastLocalTs.current = fresh[fresh.length - 1]!.at;
      setLocalBuf((prev) => [...prev, ...fresh].slice(-400));
      // What each decision COST, for the GUARD COST chart. One sample per entry that
      // carries a measurement; an entry without one is skipped rather than counted as
      // zero, because a zero would drag the median toward a speed nothing achieved.
      const costs = fresh.map((f) => f.evalMs).filter((v): v is number => typeof v === 'number');
      if (costs.length) setEvalMs((prev) => [...prev, ...costs.map((v) => Math.round(v))].slice(-240));
      const denies = fresh.filter((f) => f.decision !== 'ALLOW').length;
      if (fresh.length < 10) pushLog(`local +${fresh.length} calls${denies ? ` · ${denies} DENIED` : ''}`, denies ? 'bad' : 'warn');
    }
    const ringLines = tailLines(RING, 8_192).slice(-30);
    if (ringLines.length) {
      let sum = 0;
      let n = 0;
      let session = '';
      for (const rl of ringLines) {
        try {
          const j = JSON.parse(rl) as { ms?: number; session?: string };
          if (typeof j.ms === 'number') {
            sum += j.ms;
            n++;
          }
          if (j.session) session = j.session;
        } catch {
          /* ignore */
        }
      }
      if (n) setRing({ avgMs: Math.round(sum / n), session, count: n });
    }
  }, [pushLog]);

  useEffect(() => {
    if (!active) return;
    pollLocal();
    const t = setInterval(pollLocal, 2000);
    return () => clearInterval(t);
  }, [active, pollLocal]);

  // A SECOND PLANE stood here: pollFeed fetched the audit API every 3s, which reads the
  // same file this panel already tails, and its rows were buffered separately, deduped
  // against the tailed ones on tool|decision|minute, then labelled LOC or CLD. So a
  // person saw rows tagged "cloud" for work that never left their machine, and a source
  // filter that filtered one file from itself. It also timed that read and charted the
  // result as "API LATENCY".
  //
  // One file, one plane. internal/tui/live.go lost the same thing.

  const pollMedium = useCallback(async () => {
    if (paused()) return;
    try {
      const sd = await api.stats.get();
      if (!frozenRef.current) setS(sd);
    } catch (e) {
      onApiError(e);
    }
  }, [onApiError]);

  // The stream comes from pollLocal above, on its own 2s timer. This one is the
  // summaries — stats and insights — which a stream row does not carry.
  //
  // It used to run pollFeed at 3s too, and the comment above it read "poll budget (~40
  // req/min) … without risking the API's rate limit". Both of those read a file.
  useEffect(() => {
    if (!active) return;
    void pollMedium();
    const t = setInterval(() => void pollMedium(), 8000);
    return () => clearInterval(t);
  }, [active, pollMedium]);

  const insights = useLoader(() => api.stats.securityInsights(7));
  const guard = useLoader(() => api.settings.getGuardStatus());
  usePoll(() => {
    if (!paused()) insights.reloadQuiet();
  }, 20_000, active);
  usePoll(() => {
    if (!paused()) guard.reloadQuiet();
  }, 60_000, active);

  // ── animation tick (2fps; fully halted in copy mode) ─────────────────────
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!active || frozen) return;
    const t = setInterval(() => setTick((n) => n + 1), 500);
    return () => clearInterval(t);
  }, [active, frozen]);
  const startRef = useRef(Date.now());

  // ── shared notification primitive ─────────────────────────────────────────
  // In-app ALERT banner + terminal bell + desktop toast (notify-send, best
  // effort). `level` colours the banner. Deduped by id.
  // Desktop toasts are BATCHED, not dropped: a burst delivers many notable
  // calls in one poll, and a plain per-event throttle would toast only the
  // FIRST one (often a rate-limit burst) while silently swallowing the DLP
  // hits behind it. Queue by title, flush 400ms later (min 3s between
  // flushes): one event → its own detailed toast; several → one summary toast
  // ordered by severity ("3× DLP hit · 2× Call denied · 4× Rate-limit burst").
  const lastNotifyAt = useRef(0);
  const toastQueue = useRef<Map<string, { count: number; msg: string }>>(new Map());
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const TOAST_RANK: Record<string, number> = { 'DLP hit': 0, 'Call denied': 1, 'Rate-limit burst': 2 };
  const flushToasts = useCallback(function flush(): void {
    toastTimer.current = null;
    const q = toastQueue.current;
    if (!q.size) return;
    const wait = 3000 - (Date.now() - lastNotifyAt.current);
    if (wait > 0) {
      toastTimer.current = setTimeout(flush, wait);
      return;
    }
    lastNotifyAt.current = Date.now();
    const items = [...q.entries()].sort((a, b) => (TOAST_RANK[a[0]] ?? 9) - (TOAST_RANK[b[0]] ?? 9));
    q.clear();
    try {
      process.stdout.write('\x07');
    } catch {
      /* ignore */
    }
    const total = items.reduce((n, [, v]) => n + v.count, 0);
    if (items.length === 1 && total === 1) desktopNotify(items[0]![0], items[0]![1].msg);
    else desktopNotify('Security alerts', items.map(([t, v]) => `${v.count}× ${t}`).join(' · '));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(
    () => () => {
      if (toastTimer.current) clearTimeout(toastTimer.current);
    },
    [],
  );
  const fireAlert = useCallback(
    (id: string, title: string, msg: string, level: 'warn' | 'bad' = 'warn', desktop = true) => {
      pushLog(`${level === 'bad' ? '⛔' : '⏸'} ${msg}`, level);
      setAlerts((a) => [...a.filter((x) => x.id !== id), { id, msg, level, until: Date.now() + 15_000 }].slice(-4));
      if (!desktop || !CONFIG.notifications) return; // in-app banner still shows; skip bell + desktop toast
      const cur = toastQueue.current.get(title);
      toastQueue.current.set(title, { count: (cur?.count ?? 0) + 1, msg: cur?.msg ?? msg });
      if (!toastTimer.current) toastTimer.current = setTimeout(flushToasts, 400);
    },
    [pushLog, flushToasts],
  );

  // ── security-event notifications (DENY / DLP / rate-limit burst) ───────────
  // Fire once per notable call that happens AFTER the panel opened. Gating on the
  // call timestamp (`e.at`) instead of a "first scan seeds the seen-set" flag is
  // what fixes the backlog spam: that flag armed on the empty first tick (before
  // any data had loaded), so the whole historical backlog — arriving a tick later —
  // counted as "new" and dumped a wall of toasts on every open. Old denials have
  // `at <= openedAt` and are silently skipped; only genuinely new calls alert.
  useEffect(() => {
    if (!active) return;
    const notable = mergedRef.current.filter((e) => e.decision !== 'ALLOW' || e.dlp || e.burst);
    for (const e of notable) {
      if (notifiedRef.current.has(e.id)) continue;
      notifiedRef.current.add(e.id);
      if (!(e.at > openedAtRef.current)) continue; // backlog / pre-open call → no toast
      const who = e.agent ? ` · ${truncate(e.agent, 20)}` : '';
      if (e.dlp) fireAlert('sec:' + e.id, 'DLP hit', `SECRET in ${e.tool}${who}: ${truncate(e.detail, 60)}`, 'bad');
      else if (e.decision !== 'ALLOW') fireAlert('sec:' + e.id, 'Call denied', `DENY ${e.tool}${who}: ${truncate(e.rule ?? e.detail, 60)}`, 'bad');
      else if (e.burst) fireAlert('sec:' + e.id, 'Rate-limit burst', `BURST ${e.tool}${who}`, 'warn');
    }
  }, [tick, active, fireAlert]);

  // ── derived ───────────────────────────────────────────────────────────────
  const { cols, rows } = useTermSize(); // re-renders on resize — layout budgets below stay correct
  const ins = (insights.data ?? {}) as InsightsBits;
  const spin = SPIN[tick % SPIN.length];
  const nowMs = Date.now();

  // ONE PLANE, oldest first. Entries are appended as they are read, and a file written
  // by several processes is not strictly ordered by timestamp, so the sort stays.
  //
  // A dedupe stood here, against the second plane: the same call arrived twice — once
  // tailed off the log, once fetched through the audit API, which reads that same file —
  // and cloud rows matching a local row on tool|decision|±1min were dropped. The
  // heuristic collapses exactly the shape a retrying agent and a rate-limit burst
  // produce, so losing it is a gain as well as a simplification.
  const mergedAll = localBuf.slice().sort((a, b) => a.at - b.at);
  mergedRef.current = mergedAll; // feed the security-notify effect

  // TRAFFIC: always the LIVE window — 10-second buckets over the last 10
  // minutes, anchored to wall-clock slots. Bars slide left as real time
  // passes and age out naturally (an hours-old deny can never paint a giant
  // red column). No historical fallback: an idle window is an honest flat
  // floor, not a rescaled 24h chart.
  const nowSlot = Math.floor(nowMs / 10_000);
  const traffic = new Array(60).fill(0) as number[];
  const trafficHot = new Array(60).fill(false) as boolean[];
  for (const e of mergedAll) {
    const idx = 59 - (nowSlot - Math.floor(e.at / 10_000));
    if (idx >= 0 && idx < 60) {
      traffic[idx]!++;
      if (e.decision !== 'ALLOW') trafficHot[idx] = true;
    }
  }
  const trafficLabel = 'calls/10s · last 10m · live';

  const rl = ins.layers?.rateLimit;
  const dl = ins.layers?.dlp;
  const minuteNow = mergedAll.filter((e) => nowMs - e.at < 60_000).length;
  const dlpBars = (ins.dlpByPattern ?? []).slice(0, 2);
  const maxDlpBar = dlpBars[0]?.count ?? 1;

  const denialsAll = mergedAll.filter((e) => e.decision !== 'ALLOW');
  const lastDeny = denialsAll[denialsAll.length - 1];
  const toolCounts = new Map<string, number>();
  for (const e of mergedAll) toolCounts.set(e.tool, (toolCounts.get(e.tool) ?? 0) + 1);
  const topTools = [...toolCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);

  const evalNow = evalMs[evalMs.length - 1] ?? 0;
  const sortedEval = [...evalMs].sort((a, b) => a - b);
  const evalMed = sortedEval.length ? sortedEval[Math.floor(sortedEval.length / 2)]! : 0;
  // Amber above 2.5x the median, with a floor so a quiet machine whose median is 2ms does
  // not paint every ordinary call hot. The floor was 2000ms for a network round trip; for
  // a local policy decision 50ms is already slow.
  const evalHotAt = Math.max(50, evalMed * 2.5);
  const backingOff = Date.now() < pausedUntil.current;

  // isLoc and a SOURCE filter stood here — all → LOC → CLD, cycled by `f`. Everything
  // is read from one file, so it filtered that file from itself. The signal and search
  // filters below are the ones that mean something.
  const q = search.trim().toLowerCase();
  const matches = (e: StreamItem): boolean =>
    !q || `${e.tool} ${e.agent ?? ''} ${e.decision} ${e.permission} ${e.rule ?? ''} ${e.detail}`.toLowerCase().includes(q);
  const signalOk = (e: StreamItem): boolean =>
    signal === 'none' ? true : signal === 'deny' ? e.decision !== 'ALLOW' : signal === 'dlp' ? e.dlp : e.burst;
  const filtered = mergedAll.filter(matches).filter(signalOk);
  // Show EVERY buffered entry (newest first), scrollable — the count then matches the
  // entry total in the status bar.
  const visibleDesc = filtered.slice().reverse();

  // ── fixed layout budget ───────────────────────────────────────────────────
  // The WHOLE frame must stay at rows - 1 or less: at outputHeight >= rows ink
  // abandons in-place diffing and does clearTerminal + full rewrite on every
  // render — a constant flicker that shows up as "glitching" as soon as bright
  // content (RL/DLP hits, alert banners) is on screen. Fixed rows here: title,
  // counters, stream pane title, footer (4) + the rows - 1 headroom = 5, plus
  // any transient banner rows (security ALERT + action feedback).
  const activeAlert = alerts.filter((a) => nowMs < a.until).slice(-1)[0];
  const activeAction = actionMsg && nowMs < actionMsg.until ? actionMsg : null;
  const bannerRows = (activeAlert ? 1 : 0) + (activeAction ? 1 : 0);
  const chartH = rows >= 36 ? 6 : 4;
  const colH = rows >= 32 ? 7 : 5;
  const streamRows = Math.max(4, rows - 6 - (1 + chartH) - colH - bannerRows);
  const innerW = cols - 2;
  const leftW = Math.floor(innerW * 0.55);
  const rightW = innerW - leftW - 2;
  const colW = Math.max(20, Math.floor((innerW - 2) / 2));

  // Reserve the first line for the persistent search bar so it's never clipped.
  const streamBodyRows = Math.max(3, streamRows - 1);
  // ↑↓ move a SELECTION cursor; the window scrolls to keep it centred so the
  // selected row (target of w/b) is always visible.
  const selClamped = Math.min(Math.max(0, sel), Math.max(0, visibleDesc.length - 1));
  const maxScroll = Math.max(0, visibleDesc.length - streamBodyRows);
  const clampedScroll = Math.min(Math.max(0, selClamped - Math.floor((streamBodyRows - 1) / 2)), maxScroll);
  const windowed = visibleDesc.slice(clampedScroll, clampedScroll + streamBodyRows);
  const selEntry = visibleDesc[selClamped];

  // ── whitelist / block the selected stream row ─────────────────────────────
  // Cloud entries use the audit endpoints (agent→policy resolution); local
  // entries add a rule to this machine's active policy directly.
  const doAction = async (act: 'whitelist' | 'block') => {
    const e = selEntry;
    if (!e) return;
    const ok = act === 'whitelist' ? e.decision !== 'ALLOW' : e.decision === 'ALLOW';
    if (!ok) {
      setActionMsg({ text: act === 'whitelist' ? 'select a DENY to whitelist (w)' : 'select an ALLOW to block (b)', level: 'bad', until: Date.now() + 4000 });
      return;
    }
    setActionMsg({ text: act === 'whitelist' ? 'whitelisting…' : 'blocking…', level: 'ok', until: Date.now() + 4000 });
    try {
      // Active-policy gate: with no policy active nothing is granted — not allow, not
      // deny. Resolved fresh on every action, so editing the policy file in another
      // terminal applies immediately.
      const a = await api.policies.active();
      const pid = a.policy?.id ?? null;
      if (!pid) throw new Error('no active policy — rule NOT added. Activate a policy first (Policies section).');
      const verb = act === 'whitelist' ? 'ALLOW' : 'DENY';
      // THE SAME RULE `solongate audit whitelist` WOULD MAKE. This had two branches, one
      // per source: an entry from the audit API went through api.audit.whitelist, which
      // builds the rule from the recorded arguments and REFUSES when there is nothing to
      // narrow on; a tailed entry got a local extractor that checked a url last, took
      // only the basename of a path, and — finding nothing — left the rule at TOOL scope,
      // silently allowing every call to that tool forever.
      //
      // ruleSpecFor is the one implementation, shared with the CLI.
      const res = await api.policies.addRule(pid, ruleSpecFor(e.tool, e.args, 'exact', verb));
      setActionMsg({
        text: res.deduped ? `${verb} rule already present` : `${verb} rule added → ${res.policy_id ?? '?'}${res.policy_version ? ' v' + res.policy_version : ''} · reaches agents in ~30s`,
        level: 'ok',
        until: Date.now() + 7000,
      });
      pushLog(`${act === 'whitelist' ? '✓ whitelisted' : '⛔ blocked'} ${e.tool}`, act === 'whitelist' ? 'ok' : 'warn');
    } catch (err) {
      setActionMsg({ text: '✗ ' + (err instanceof Error ? err.message : String(err)), level: 'bad', until: Date.now() + 7000 });
    }
  };

  // ── keys ──────────────────────────────────────────────────────────────────
  useInput(
    (input, key) => {
      // Copy mode toggle first; while frozen only space resumes.
      if (input === ' ') {
        setFrozen((f) => !f);
        return;
      }
      if (frozen) return;
      // `?` opens the full key reference from ANY mode; any key closes it.
      if (showHelp) {
        setShowHelp(false);
        return;
      }
      if (input === '?') {
        setShowHelp(true);
        return;
      }
      // `/` opens live search in the stream.
      if (input === '/') {
        setEditingSearch(true);
        return;
      }
      if (mode === 'inspect') {
        if (key.leftArrow) {
          setMode(inspectFromRef.current);
          setInspect(null);
        } else if (key.upArrow) setInspectScroll((n) => Math.max(0, n - 1));
        else if (key.downArrow) setInspectScroll((n) => n + 1); // clamped at render
        else if (key.pageUp) setInspectScroll((n) => Math.max(0, n - 10));
        else if (key.pageDown) setInspectScroll((n) => n + 10);
        return;
      }
      if (mode === 'layers') {
        if (key.leftArrow || input === 'l') setMode('stream');
        else if (key.upArrow) setLayersScroll((n) => Math.max(0, n - 1));
        else if (key.downArrow) setLayersScroll((n) => n + 1); // clamped at render
        else if (key.pageUp) setLayersScroll((n) => Math.max(0, n - 10));
        else if (key.pageDown) setLayersScroll((n) => n + 10);
        return;
      }
      // stream mode
      const toggleSignal = (s: 'deny' | 'dlp' | 'ratelimit') => {
        setSignal((cur) => (cur === s ? 'none' : s));
        setSel(0);
      };
      if (key.return) {
        if (selEntry) {
          inspectFromRef.current = 'stream';
          setInspect(selEntry);
          setInspectScroll(0);
          setMode('inspect');
        }
      } else if (false) {
      } else if (input === 'l') {
        setLayersScroll(0);
        setMode('layers');
      } else if (input === 'w') void doAction('whitelist');
      else if (input === 'b') void doAction('block');
      else if (input === 'd') toggleSignal('deny');
      else if (input === 'x') toggleSignal('dlp');
      else if (input === 'r') toggleSignal('ratelimit');
      else if (input === 'e') {
        const file = join(homedir(), '.solongate', 'live-export.jsonl');
        try {
          mkdirSync(join(homedir(), '.solongate'), { recursive: true });
          writeFileSync(file, visibleDesc.map((x) => JSON.stringify(x)).join('\n') + '\n');
          setActionMsg({ text: `✓ exported ${visibleDesc.length} lines → ${file}`, level: 'ok', until: Date.now() + 6000 });
        } catch (err) {
          setActionMsg({ text: '✗ export failed: ' + (err instanceof Error ? err.message : String(err)), level: 'bad', until: Date.now() + 6000 });
        }
      }
      else if (key.downArrow) setSel((n) => Math.min(visibleDesc.length - 1, n + 1));
      else if (key.upArrow) setSel((n) => Math.max(0, n - 1));
      else if (key.pageDown) setSel((n) => Math.min(visibleDesc.length - 1, n + streamBodyRows));
      else if (key.pageUp) setSel((n) => Math.max(0, n - streamBodyRows));
    },
    { isActive: active && !editingSearch },
  );

  // Persistent search bar — ALWAYS rendered as the first row under the stream /
  // timeline title (never hidden), so it's obvious where to type. `/` focuses
  // it; while focused a live TextInput takes over, otherwise it shows the query
  // or a hint.
  const searchRow = (
    <Text wrap="truncate">
      <Text color={editingSearch ? theme.warn : theme.dim} bold={editingSearch}>
        {editingSearch ? '⌕ search: ' : '⌕ search: '}
      </Text>
      {editingSearch ? (
        <>
          <TextInput
            value={search}
            onChange={(v) => {
              if (v.endsWith('/')) {
                setEditingSearch(false);
                return;
              }
              setSearch(v);
              setSel(0);
            }}
            onSubmit={() => setEditingSearch(false)}
          />
          <Text color={theme.dim}>{`  ${filtered.length} match · enter/​/ done · empty clears`}</Text>
        </>
      ) : search ? (
        <>
          <Text color={theme.accentBright} bold>
            {search}
          </Text>
          <Text color={theme.dim}>{`  ${filtered.length} match · press / to edit · type to clear`}</Text>
        </>
      ) : (
        <Text color={theme.dim}>{'press / to filter the stream by tool, agent, command…'}</Text>
      )}
    </Text>
  );

  if (s === null && localOn === null) {
    return <Text color={theme.dim}>{spin} connecting…</Text>;
  }

  // ── title + counters (shared by all modes) ────────────────────────────────
  const titleBar = (
    <Text wrap="truncate">
      <Text backgroundColor="#1432A0" color="white" bold>
        {' SOLONGATE LIVE '}
      </Text>
      <Text backgroundColor={BG} color="white">
        {/* `· api <n>ms` stood here, the round trip of the audit fetch. What is worth a
            place in the title is what ENFORCEMENT costs — see the GUARD COST pane. */}
        {` ${spin} up ${fmtUp(nowMs - startRef.current)} · ${hhmmss(nowMs)} · guard ${evalNow}ms `}
      </Text>
      {frozen ? (
        <Text backgroundColor="#123d1f" color="#7bd88f" bold>
          {' ⏵ COPY MODE — screen frozen, select & copy freely · space resume '}
        </Text>
      ) : backingOff ? (
        <Text backgroundColor="#3d2a12" color="#ffb454" bold>
          {' RATE LIMITED · backing off '}
        </Text>
      ) : lastDeny ? (
        <Text backgroundColor="#3d1220" color="#ff6b6b" bold>
          {` ⚠ ${hhmmss(lastDeny.at)} ${lastDeny.tool} DENIED `}
        </Text>
      ) : (
        <Text backgroundColor={BG} color="white">
          {' ✓ clean '}
        </Text>
      )}
    </Text>
  );

  // ── HELP OVERLAY (`?` from any mode) ──────────────────────────────────────
  if (showHelp) {
    return (
      <Box flexDirection="column" paddingX={1}>
        {titleBar}
        <Text bold color={theme.accentBright}>
          LIVE — all keys
        </Text>
        <Box flexDirection="column" marginTop={1}>
          {LIVE_HELP.map(([group, keys]) => (
            <Box key={group} flexDirection="column" marginBottom={1}>
              <Text bold color={theme.accent}>
                {group}
              </Text>
              {keys.map(([k, desc]) => (
                <Text key={k} wrap="truncate">
                  <Text color={theme.accentBright}>{('  ' + k).padEnd(20)}</Text>
                  <Text color={theme.dim}>{desc}</Text>
                </Text>
              ))}
            </Box>
          ))}
        </Box>
        <Text color={theme.dim}>press any key to close</Text>
      </Box>
    );
  }

  // ── ENTRY INSPECTOR — the FULL content of one log line ───────────────────
  if (mode === 'inspect' && inspect) {
    const e = inspect;
    const bodyW = Math.max(20, cols - 4);
    const lines = wrapLines(prettyJson(e.detail || '(no arguments / reason recorded)'), bodyW);
    const bodyRows = Math.max(4, rows - 7); // title + 3 header rows + pane title + footer
    const maxScroll = Math.max(0, lines.length - bodyRows);
    const off = Math.min(inspectScroll, maxScroll);
    const win = lines.slice(off, off + bodyRows);
    return (
      <Box flexDirection="column" paddingX={1}>
        {titleBar}
        <Text wrap="truncate">
          <Text backgroundColor={BG} color="white" bold>
            {' ENTRY '}
          </Text>
          <Text color={decisionColor(e.decision)} bold>
            {'  ' + e.decision}
          </Text>
          <Text color={theme.accent} bold>
            {'  ' + e.tool}
          </Text>
          {e.dlp ? <Text color={theme.bad}>{'  DLP!'}</Text> : null}
          {e.burst ? <Text color={theme.warn}>{'  BURST'}</Text> : null}
          <Text color={theme.dim}>{'  ← back'}</Text>
        </Text>
        <Text wrap="truncate">
          <Text color={theme.dim}>│ when </Text>
          <Text>{new Date(e.at).toLocaleString()}</Text>
          <Text color={theme.dim}> │ perm </Text>
          <Text>{e.permission || '—'}</Text>
          <Text color={theme.dim}> │ eval </Text>
          <Text color={e.evalMs != null && e.evalMs > 500 ? theme.warn : undefined}>{e.evalMs != null ? `${e.evalMs}ms` : '—'}</Text>
          <Text color={theme.dim}> │ agent </Text>
          <Text>{e.agent ?? '—'}</Text>
          <Text color={theme.dim}> │</Text>
        </Text>
        <Text wrap="truncate">
          <Text color={theme.dim}>│ session </Text>
          <Text color={theme.dim}>{e.session ?? '—'}</Text>
          <Text color={theme.dim}> │ rule </Text>
          <Text color={e.rule && e.decision !== 'ALLOW' ? theme.bad : theme.dim}>{e.rule ?? '—'}</Text>
          <Text color={theme.dim}> │</Text>
        </Text>
        <PaneTitle label="FULL CONTENT" extra={`${lines.length} lines${maxScroll ? ` · ▼${maxScroll - off} more · ↑↓ scroll` : ''} · space copy · ← back`} width={innerW} />
        <Box flexDirection="column" height={bodyRows} overflow="hidden">
          {win.map((l, i) => (
            <Text key={off + i} wrap="truncate">
              {l || ' '}
            </Text>
          ))}
        </Box>
        <Text wrap="truncate">
          <Text backgroundColor={BG} color="white" bold>
            {' ENTRY '}
          </Text>
          <Text backgroundColor="#0b1530" color="white">
            {` ${e.id} `}
          </Text>
          <Text backgroundColor={BG} color="white">
            {' ↑↓ scroll · space copy · ? all keys · ← back · esc menu '}
          </Text>
        </Text>
      </Box>
    );
  }

  // ── LAYERS DETAIL VIEW (l) — full security-layer configuration ───────────
  if (mode === 'layers') {
    const modeColor = (m?: string): string => (m === 'block' || m === 'on' ? theme.ok : m === 'detect' ? theme.warn : theme.dim);
    const barW = Math.max(10, Math.min(40, innerW - 30));
    const burstsInBuf = mergedAll.filter((e) => e.burst).length;
    const dlpInBuf = mergedAll.filter((e) => e.dlp).length;
    const allHits = ins.dlpByPattern ?? [];
    const maxHit = allHits[0]?.count ?? 1;
    const L: JSX.Element[] = [];
    const push = (el: JSX.Element) => L.push(<Box key={L.length}>{el}</Box>);
    const blank = () => push(<Text> </Text>);
    const section = (label: string, m?: string, note?: string) =>
      push(
        <Text wrap="truncate">
          <Text bold color={theme.accentBright}>
            ▎{label.padEnd(10)}
          </Text>
          <Text bold color={modeColor(m)}>
            {(m ?? '?').padEnd(8)}
          </Text>
          {note ? <Text color={theme.dim}>{note}</Text> : null}
        </Text>,
      );
    const kv = (k: string, v: JSX.Element) =>
      push(
        <Text wrap="truncate">
          <Text color={theme.dim}>{('  ' + k).padEnd(16)}</Text>
          {v}
        </Text>,
      );

    section('RATELIMIT', rl?.mode, rl?.mode === 'block' ? 'over-limit calls are DENIED' : rl?.mode === 'detect' ? 'over-limit calls are observed & flagged rl:yes' : 'no limit enforcement');
    kv('limits', <Text>{rl?.perMinute || rl?.perHour || rl?.perDay ? `${rl?.perMinute || '—'}/min · ${rl?.perHour || '—'}/hour · ${rl?.perDay || '—'}/day` : 'none configured'}</Text>);
    kv('load now', <Text>{`${minuteNow} calls in the last 60s`}</Text>);
    if (rl?.perMinute) push(<HBar label="  load/min" value={minuteNow} max={rl.perMinute} width={barW} color={minuteNow > rl.perMinute ? theme.bad : theme.accent} />);
    kv('bursts', <Text color={burstsInBuf ? theme.warn : theme.dim}>{`${burstsInBuf} flagged in the live buffer`}</Text>);
    blank();

    section('DLP', dl?.mode, dl?.mode === 'block' ? 'secrets in arguments are DENIED + redacted' : dl?.mode === 'detect' ? 'secrets observed & flagged dlp:yes, output redacted' : 'no secret scanning');
    kv('hits', <Text color={dlpInBuf ? theme.bad : theme.dim}>{`${dlpInBuf} flagged in the live buffer`}</Text>);
    const builtin = dl?.patterns ?? [];
    kv('builtin', <Text>{builtin.length ? `${builtin.length} patterns enabled` : 'none enabled'}</Text>);
    for (const line of wrapLines(builtin.join(' · '), Math.max(20, innerW - 18))) push(<Text wrap="truncate" color={theme.dim}>{'                ' + line}</Text>);
    const custom = dl?.custom ?? [];
    kv('custom', <Text>{custom.length ? `${custom.length} patterns` : 'none'}</Text>);
    for (const c of custom)
      push(
        <Text wrap="truncate">
          <Text color={theme.dim}>{'                '}</Text>
          <Text color={theme.accent}>{truncate(c.name ?? 'custom', 24).padEnd(25)}</Text>
          <Text color={theme.dim}>{truncate(c.re ?? '', Math.max(10, innerW - 44))}</Text>
        </Text>,
      );
    kv('pattern hits', <Text color={theme.dim}>{allHits.length ? 'last 7 days' : 'none in the last 7 days'}</Text>);
    for (const h of allHits) push(<HBar label={'  ' + truncate(h.pattern, 10)} value={h.count} max={maxHit} width={barW} color={theme.bad} />);
    blank();

    section('GUARD', guard.data ? (guard.data.up_to_date ? 'ok' : 'stale') : '?', 'the PreToolUse hook enforcing all of the above');
    kv(
      'hooks',
      guard.data ? (
        <Text color={guard.data.up_to_date ? theme.ok : theme.warn}>
          {`v${guard.data.installed ?? '?'}${guard.data.up_to_date ? ' (latest)' : ` → v${guard.data.latest} available`} · ${guard.data.device_count} device${guard.data.device_count === 1 ? '' : 's'}`}
        </Text>
      ) : (
        <Text color={theme.dim}>loading…</Text>
      ),
    );
    kv('local eval', ring ? <Text color={theme.ok}>{`avg ${ring.avgMs}ms over ${ring.count} recent calls`}</Text> : <Text color={theme.dim}>no local ring in cwd</Text>);

    const bodyRows = Math.max(4, rows - 5);
    const maxLScroll = Math.max(0, L.length - bodyRows);
    const lOff = Math.min(layersScroll, maxLScroll);
    const win = L.slice(lOff, lOff + bodyRows);
    return (
      <Box flexDirection="column" paddingX={1}>
        {titleBar}
        <Text wrap="truncate">
          <Text backgroundColor={BG} color="white" bold>
            {' LAYERS '}
          </Text>
          <Text color={theme.dim}>{'  security layers, limits and patterns · insights window: last 7 days'}</Text>
          <Text color={theme.dim}>{'  ← back'}</Text>
        </Text>
        <PaneTitle label="LAYERS" extra={`${insights.data ? '' : spin + ' loading · '}${maxLScroll ? `▼${maxLScroll - lOff} more · ↑↓ scroll · ` : ''}l or ← back`} width={innerW} />
        <Box flexDirection="column" height={bodyRows} overflow="hidden">
          {win}
        </Box>
        <Text wrap="truncate">
          <Text backgroundColor={BG} color="white" bold>
            {' LAYERS '}
          </Text>
          <Text backgroundColor="#0b1530" color="white">
            {' rate limit · dlp · guard '}
          </Text>
          <Text backgroundColor={BG} color="white">
            {' ↑↓ scroll · ? all keys · ← back · esc menu '}
          </Text>
        </Text>
      </Box>
    );
  }

  // ── MAIN GRID ─────────────────────────────────────────────────────────────
  return (
    <Box flexDirection="column" paddingX={1}>
      {titleBar}

      <Text wrap="truncate">
        <Text color={theme.dim}>│ calls </Text>
        <Text bold>{s ? s.total_calls : '····'}</Text>
        <Text color={theme.dim}> │ allow </Text>
        <Text color={theme.ok}>{s ? s.allowed : '···'}</Text>
        <Text color={theme.dim}> │ deny </Text>
        <Text color={theme.bad} bold>
          {s ? s.denied : '··'}
        </Text>
        <Text color={theme.dim}> │ local </Text>
        {localOn ? <Text color={theme.ok}>✓</Text> : <Text color={theme.dim}>off</Text>}
        <Text color={theme.dim}> │ rl </Text>
        <Text color={rl?.mode === 'block' ? theme.ok : rl?.mode === 'detect' ? theme.warn : theme.dim}>{rl?.mode ?? '?'}</Text>
        <Text color={theme.dim}> │ dlp </Text>
        <Text color={dl?.mode === 'block' ? theme.ok : dl?.mode === 'detect' ? theme.warn : theme.dim}>{dl?.mode ?? '?'}</Text>
        <Text color={theme.dim}> │ hooks </Text>
        <Text color={guard.data?.up_to_date ? theme.ok : theme.warn}>
          {guard.data ? `v${guard.data.installed ?? '?'}${guard.data.up_to_date ? '' : '→v' + guard.data.latest} ${guard.data.device_count}dev` : '·'}
        </Text>
        <Text color={theme.dim}> │</Text>
      </Text>

      {activeAlert ? (
        <Text
          wrap="truncate"
          backgroundColor={activeAlert.level === 'bad' ? '#3d1220' : '#3d2a12'}
          color={activeAlert.level === 'bad' ? '#ff6b6b' : '#ffb454'}
          bold
        >
          {` ${activeAlert.level === 'bad' ? '⛔ ALERT' : '⏸ IDLE'} · ${truncate(activeAlert.msg, innerW - 14)} `}
        </Text>
      ) : null}
      {activeAction ? (
        <Text wrap="truncate" backgroundColor={activeAction.level === 'bad' ? '#3d1220' : '#123d1f'} color={activeAction.level === 'bad' ? '#ff6b6b' : '#7bd88f'} bold>
          {` ${truncate(activeAction.text, innerW - 4)} `}
        </Text>
      ) : null}

      <Box height={1 + chartH} overflow="hidden">
        <Box flexDirection="column" width={leftW} height={1 + chartH} marginRight={2} overflow="hidden">
          <PaneTitle label="TRAFFIC" extra={`${trafficLabel} · peak ${Math.max(0, ...traffic)} · red = denials`} width={leftW} />
          <ColumnChart series={traffic} hot={trafficHot} height={chartH} width={leftW} color={theme.accent} />
        </Box>
        <Box flexDirection="column" width={rightW} height={1 + chartH} overflow="hidden">
          <PaneTitle label="GUARD COST" extra={`ms per decision · now ${evalNow} · med ${evalMed} · amber >${Math.round(evalHotAt)}`} width={rightW} />
          <ColumnChart series={evalMs} hot={evalMs.map((v) => v > evalHotAt)} height={chartH} width={rightW} color="white" hotColor="#ffb454" />
        </Box>
      </Box>

      {/* height AND overflow must sit on the SAME box. They used to be split —
          the fixed height here, `overflow: hidden` on the three columns below —
          which clips nothing: a column with no height of its own sizes to its
          content, so `hidden` had no boundary to clip against, and a column
          taller than colH simply overflowed this box and grew the whole frame
          past rows-1. That is the clearTerminal repaint the budget above exists
          to avoid, and it is why LAYERS (up to 7 rows once rate limits and DLP
          bars are present, against colH=5 on a terminal under 32 rows) made the
          lower half flicker exactly when there was something to look at. */}
      <Box height={colH} overflow="hidden">
        <Box flexDirection="column" width={colW} height={colH} marginRight={2} overflow="hidden">
          <PaneTitle label="LAYERS" extra="l = inspect" width={colW} />
          <Text wrap="truncate">
            <Text color={theme.dim}>{'RATELIMIT '.padEnd(10)}</Text>
            <Text color={rl?.mode === 'block' ? theme.ok : rl?.mode === 'detect' ? theme.warn : theme.dim}>{(rl?.mode ?? '?').padEnd(7)}</Text>
            <Text color={theme.dim}>{rl?.perMinute ? `${minuteNow}/${rl.perMinute}m ${rl.perHour || '—'}h ${rl.perDay || '—'}d` : 'no limits set'}</Text>
          </Text>
          {rl?.perMinute ? <HBar label="load/min" value={minuteNow} max={rl.perMinute} width={Math.max(6, colW - 16)} color={minuteNow > rl.perMinute ? theme.bad : theme.accent} /> : null}
          <Text wrap="truncate">
            <Text color={theme.dim}>{'DLP'.padEnd(10)}</Text>
            <Text color={dl?.mode === 'block' ? theme.ok : dl?.mode === 'detect' ? theme.warn : theme.dim}>{(dl?.mode ?? '?').padEnd(7)}</Text>
            <Text color={theme.dim}>{`${(dl?.patterns ?? []).length} builtin · ${(dl?.custom ?? []).length} custom`}</Text>
          </Text>
          {dlpBars.length ? (
            dlpBars.map((d2) => <HBar key={d2.pattern} label={truncate(d2.pattern, 10)} value={d2.count} max={maxDlpBar} width={Math.max(6, colW - 16)} color={theme.bad} />)
          ) : (
            // 36 chars against a colW that is ~31 at cols=100: without truncate
            // this wrapped onto a second line and pushed the column over colH.
            <Text wrap="truncate" color={theme.dim}>{'          no dlp hits in last 7 days'}</Text>
          )}
          <Text wrap="truncate">
            <Text color={theme.dim}>{'GUARD'.padEnd(10)}</Text>
            {ring ? (
              <Text color={theme.ok}>
                local ✓ <Text color={theme.dim}>{`eval avg ${ring.avgMs}ms`}</Text>
              </Text>
            ) : (
              <Text color={theme.dim}>no local ring in cwd</Text>
            )}
          </Text>
        </Box>
        <Box flexDirection="column" width={colW} height={colH} overflow="hidden">
          <PaneTitle label="EVENT LOG" extra="system heartbeat" width={colW} />
          {log.slice(-(colH - 1)).map((l, i) => (
            <Text key={l.ts + ':' + i} wrap="truncate">
              <Text color={theme.dim}>{hhmmss(l.ts)} </Text>
              <Text color={l.level === 'bad' ? theme.bad : l.level === 'warn' ? theme.warn : '#4f8f6b'}>▸ </Text>
              <Text color={l.level === 'bad' ? theme.bad : theme.dim}>{l.msg}</Text>
            </Text>
          ))}
        </Box>
      </Box>

      <PaneTitle
        label="TOOL STREAM"
        extra={`${selClamped + 1}/${visibleDesc.length}${signal !== 'none' ? ` · ${signal}` : ''}${q ? ' · search' : ''} · enter full entry · ? all keys`}
        width={innerW}
      />
      <Box flexDirection="column" height={streamRows} overflow="hidden">
        {searchRow}
        {/* A "local logs off — enable: dataroom → Settings or dashboard → Settings" row
            stood first here. Recording is unconditional: the setting chooses the folder
            and nothing else, so `off` is a state the writers cannot be in. */}
        {localOn && localPath && !localPath.usableHere ? (
          // The folder is a PROJECT setting, so it can name a path that exists
          // on another machine. Saying so beats showing a path nothing writes to.
          <Text wrap="truncate">
            <Text color={theme.warn}>local logs on</Text>
            <Text color={theme.dim}>{` — ${localPath.configuredPath} is not a folder on this device · writing to ${localPath.file}`}</Text>
          </Text>
        ) : localOn && localBuf.length === 0 ? (
          <Text wrap="truncate">
            <Text color={theme.ok}>local logs on</Text>
            <Text color={theme.dim}>{` — no entries yet · hooks write ${localPath?.file ?? ''}`}</Text>
          </Text>
        ) : null}
        {windowed.length === 0 ? <Text color={theme.dim}>{spin} awaiting traffic…</Text> : null}
        {windowed.map((e, i) => (
          <StreamLine key={e.id} e={e} selected={clampedScroll + i === selClamped} />
        ))}
      </Box>

      <Text wrap="truncate">
        <Text backgroundColor={BG} color="white" bold>
          {' LIVE '}
        </Text>
        {/* A source indicator and the `f` key that cycled it stood here. It merged one
            file with itself. */}
        <Text backgroundColor="#0b1530" color="white">
          {` local-log ${localOn ? 'on' : 'off'} · ${localBuf.length} entries · top ${topTools.map(([t, c]) => `${t}×${c}`).join(' ') || '—'} `}
        </Text>
        <Text backgroundColor={BG} color="white">
          {` ↑↓ select · enter full entry · / search · space copy · ? all keys · esc menu · q quit `}
        </Text>
      </Text>
    </Box>
  );
}

/**
 * Dry Run panel — the dashboard's "Policy Dry Run" page, in the terminal.
 *
 * Replays a policy's rules against your real historical traffic (POST
 * /policies/backtest, the same endpoint the web page uses) and renders the same
 * breakdown: summary + deny-rate shift, per-rule / per-agent / per-tool impact
 * and the individual changed calls. Nothing is enforced or saved.
 *
 * The whole report is built as a flat list of lines and windowed to the panel
 * height, so it scrolls with ↑↓ and never overflows (which would glitch the
 * banner).
 */
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { useEffect, useState } from 'react';
import { api } from '../../api-client/index.js';
import type { BacktestResult } from '../../api-client/policies.js';
import { DataView } from '../components.js';
import { useLoader, usePanelSize } from '../hooks.js';
import { theme, truncate } from '../theme.js';

const DEFAULT_LIMIT = 1000;
/** Hard ceiling on how many logs a single dry run replays. */
const MAX_LIMIT = 5000;

/** Policy to preselect when the user pressed D in the Policies panel. */
let pendingPolicyId: string | null = null;
export function requestDryRun(policyId: string): void {
  pendingPolicyId = policyId;
}

const pct = (n: number, d: number): string => (d ? ((n / d) * 100).toFixed(1) + '%' : '0%');

export function DryRunPanel({ focused }: { active: boolean; focused: boolean }): JSX.Element {
  const list = useLoader(() => api.policies.list());
  const policies = list.data?.policies ?? [];
  const [pi, setPi] = useState(0);
  // How many of your most recent audit logs to replay. Typed in (n), clamped to
  // however many you actually have.
  const [limit, setLimit] = useState(DEFAULT_LIMIT);
  const [editLogs, setEditLogs] = useState<string | null>(null);
  const statsQ = useLoader(() => api.stats.get());
  const totalLogs = statsQ.data?.total_calls ?? null;
  const [res, setRes] = useState<BacktestResult | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [off, setOff] = useState(0);
  const { cols, rows } = usePanelSize();

  const selected = policies[Math.min(pi, Math.max(0, policies.length - 1))];

  function run(policyIdx = pi, lim = limit): void {
    const p = policies[policyIdx];
    if (!p) return;
    setRunning(true);
    setErr(null);
    setRes(null);
    setOff(0);
    api.policies
      .backtest({ rules: p.rules ?? [], mode: p.mode, limit: lim })
      .then((r) => setRes(r))
      .catch((e: unknown) => setErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setRunning(false));
  }

  // Auto-run once the policy list lands. Honours a D handoff from Policies.
  useEffect(() => {
    if (policies.length === 0 || res || running || err) return;
    let idx = 0;
    if (pendingPolicyId) {
      const found = policies.findIndex((p) => p.id === pendingPolicyId);
      if (found >= 0) idx = found;
      pendingPolicyId = null;
    }
    setPi(idx);
    run(idx, limit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policies.length]);

  useInput((input, key) => {
    if (!focused || editLogs !== null) return; // TextInput owns the keys while editing
    if (key.upArrow) setOff((n) => Math.max(0, n - 1));
    else if (key.downArrow) setOff((n) => n + 1);
    else if (input === 'p' || input === 'P') {
      const n = policies.length ? (pi + 1) % policies.length : 0;
      setPi(n);
      run(n, limit);
    } else if (input === 'n' || input === 'N') {
      setEditLogs(String(limit));
    } else if (input === 'r' || input === 'R') run(pi, limit);
  });

  function commitLogs(raw: string): void {
    const cap = Math.min(MAX_LIMIT, totalLogs && totalLogs > 0 ? totalLogs : MAX_LIMIT);
    const parsed = parseInt(raw.replace(/[^0-9]/g, ''), 10);
    const next = Number.isFinite(parsed) && parsed > 0 ? Math.min(parsed, cap) : limit;
    setEditLogs(null);
    setLimit(next);
    run(pi, next);
  }

  // ── build the report as flat lines ────────────────────────────────────────
  const w = Math.max(40, cols);
  const lines: JSX.Element[] = [];
  const head = (t: string) => lines.push(<Text key={`h${lines.length}`} bold color={theme.accentBright}>{t}</Text>);
  const dim = (t: string) => lines.push(<Text key={`d${lines.length}`} color={theme.dim} wrap="truncate">{t}</Text>);
  const row = (t: string) => lines.push(<Text key={`r${lines.length}`} wrap="truncate">{t}</Text>);
  const blank = () => lines.push(<Text key={`b${lines.length}`}> </Text>);

  if (res) {
    const s = res.summary;
    const denyAfter = s.would_deny;
    const denyBefore = s.would_deny - s.newly_blocked + s.newly_allowed;
    const before = pct(denyBefore, s.evaluated);
    const after = pct(denyAfter, s.evaluated);
    const ppShift = s.evaluated ? (((denyAfter - denyBefore) / s.evaluated) * 100).toFixed(1) : '0.0';

    head('Summary');
    row(`  evaluated ${s.evaluated}    would allow ${s.would_allow}    would deny ${s.would_deny}`);
    lines.push(
      <Text key={`sum${lines.length}`} wrap="truncate">
        {'  newly blocked '}<Text color={theme.bad} bold>{String(s.newly_blocked)}</Text>
        {'    newly allowed '}<Text color={theme.ok} bold>{String(s.newly_allowed)}</Text>
        {'    unchanged '}<Text color={theme.dim}>{String(s.unchanged)}</Text>
      </Text>,
    );
    row(`  deny rate ${before} -> ${after}  (${Number(ppShift) > 0 ? '+' : ''}${ppShift}pp)`);
    blank();

    if (res.per_rule.length) {
      head('Per-rule impact');
      dim(`  ${'RULE'.padEnd(38)}${'MATCHED'.padEnd(9)}${'%'.padEnd(8)}${'NEW-BLK'.padEnd(9)}NEW-ALW`);
      for (const r of res.per_rule.slice(0, 30)) {
        row(`  ${truncate(r.rule_id, 36).padEnd(38)}${String(r.matched).padEnd(9)}${pct(r.matched, s.evaluated).padEnd(8)}${String(r.newly_blocked).padEnd(9)}${r.newly_allowed}`);
      }
      blank();
    }

    if (res.per_agent.length) {
      head('Per-agent impact');
      dim(`  ${'AGENT'.padEnd(24)}${'EVALUATED'.padEnd(11)}${'CHANGED'.padEnd(9)}${'NEW-BLK'.padEnd(9)}NEW-ALW`);
      for (const a of res.per_agent) {
        row(`  ${truncate(a.agent || '-', 22).padEnd(24)}${String(a.evaluated).padEnd(11)}${String(a.changed).padEnd(9)}${String(a.newly_blocked).padEnd(9)}${a.newly_allowed}`);
      }
      blank();
    }

    if (res.per_tool.length) {
      head('Per-tool breakdown');
      dim(`  ${'TOOL'.padEnd(24)}${'EVALUATED'.padEnd(11)}${'CHANGED'.padEnd(9)}${'NEW-BLK'.padEnd(9)}NEW-ALW`);
      for (const t of res.per_tool) {
        row(`  ${truncate(t.tool || '-', 22).padEnd(24)}${String(t.evaluated).padEnd(11)}${String(t.changed).padEnd(9)}${String(t.newly_blocked).padEnd(9)}${t.newly_allowed}`);
      }
      blank();
    }

    if (res.samples.length) {
      head(`Changed calls (${res.samples.length})`);
      for (const c of res.samples) {
        const flip = `${c.original}->${c.predicted}`;
        const newlyAllowed = c.predicted === 'ALLOW';
        lines.push(
          <Text key={`c${lines.length}`} wrap="truncate">
            {'  '}
            <Text color={theme.accent}>{truncate(c.tool, 16).padEnd(17)}</Text>
            <Text color={theme.dim}>{truncate(c.agent || '-', 14).padEnd(15)}</Text>
            <Text color={newlyAllowed ? theme.ok : theme.bad}>{flip.padEnd(14)}</Text>
            <Text color={theme.dim}>{truncate(c.preview.replace(/\s+/g, ' '), Math.max(10, w - 50))}</Text>
          </Text>,
        );
      }
    }
  }

  // ── window the report so it never overflows the panel ─────────────────────
  const headerRows = 5;
  const budget = Math.max(3, rows - headerRows);
  const maxOff = Math.max(0, lines.length - budget);
  const start = Math.min(off, maxOff);
  const win = lines.slice(start, start + budget);
  const above = start;
  const below = Math.max(0, lines.length - (start + budget));

  return (
    <DataView loading={list.loading && !list.data} error={list.error}>
      <Box flexDirection="column">
        <Text bold color={theme.accentBright}>Policy Dry Run</Text>
        <Text wrap="truncate">
          <Text color={theme.dim}>{'  policy  '}</Text>
          <Text color={theme.accent}>{'‹ ' + truncate(selected?.name ?? 'none', 30) + ' ›'}</Text>
          <Text color={theme.dim}>{`  ${policies.length ? pi + 1 : 0}/${policies.length}  press p   ·   mode ${selected?.mode ?? '-'}`}</Text>
        </Text>
        {editLogs !== null ? (
          <Box>
            <Text color={theme.dim}>{'  logs    '}</Text>
            <Text color={theme.warn}>{'how many recent logs to replay: '}</Text>
            <TextInput value={editLogs} onChange={setEditLogs} onSubmit={commitLogs} />
            <Text color={theme.dim}>{`   (max ${Math.min(MAX_LIMIT, totalLogs && totalLogs > 0 ? totalLogs : MAX_LIMIT)})`}</Text>
          </Box>
        ) : (
          <Text wrap="truncate">
            <Text color={theme.dim}>{'  logs    '}</Text>
            <Text color={theme.accent}>{'‹ ' + String(limit) + ' ›'}</Text>
            <Text color={theme.dim}>
              {`  press n to type a number   max ${Math.min(MAX_LIMIT, totalLogs && totalLogs > 0 ? totalLogs : MAX_LIMIT)}${res?.sampled != null ? `   replayed ${res.sampled}` : ''}`}
            </Text>
          </Text>
        )}
        <Text color={theme.dim} wrap="truncate">
          {focused
            ? `↑↓ scroll · p policy · n logs · r re-run${above ? ` · ▲${above}` : ''}${below ? ` · ▼${below}` : ''}`
            : 'press → to open'}
        </Text>
        {running ? <Text color={theme.warn}>replaying recent traffic…</Text> : null}
        {err ? <Text color={theme.bad} wrap="truncate">{'✗ ' + err}</Text> : null}
        {!running && !err && !res ? <Text color={theme.dim}>no result yet, press r to run</Text> : null}
        <Box marginTop={1} flexDirection="column">{win}</Box>
      </Box>
    </DataView>
  );
}
